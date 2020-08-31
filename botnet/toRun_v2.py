import ida_ida
import ida_auto
import ida_pro
import idaapi
import idautils
import idc
import ida_funcs
from collections import Counter
import re
import ida_idaapi

MIPS_CHECK_INST = ["li      $v0, 0x107C", "syscall"]
IA32_CHECK_INST = ["mov     eax, 37h", "int     80h"]

class Analyzer():
    def __init__(self):
        self.main = None
        self.call_graph = {}
        self.pl = None
        self.UP_BOUND = None
        self.DOWN_BOUND = None
        self.size_of_all_const = None
        self.label_with_size = {}
        self.start, self.end = None, None
        self.all_func_access_rodata = {}
        self.all_func_access_rodata_counter = {}
        self.global_seg_start = None
    
    def set_platform(self,pl):
        self.pl = pl
        self.get_up_bound()
        self.get_down_bound()

    def find_main_x86(self):
        start = ida_ida.inf_get_start_ea()
        fn = idaapi.get_func(start)
        f_start, f_end = fn.start_ea, fn.end_ea
        eas = list(idautils.Heads(f_start, f_end))
        mnem = idc.print_insn_mnem(eas[-1])
        if mnem == 'jmp':
            return idc.get_operand_value(eas[-1],0)
        elif mnem == 'call':
            for i in range(len(list(eas))-2,-1,-1):
                mnem = idc.print_insn_mnem(eas[i])
                if mnem == 'push':
                    return idc.get_operand_value(eas[i],0)
        else:
            print(idc.GetDisasm(eas[-1]))
            return 0

    def find_main_mips(self):
        start = ida_ida.inf_get_start_ea()
        fn = idaapi.get_func(start)
        f_start, f_end = fn.start_ea, fn.end_ea
        eas = list(idautils.Heads(f_start, f_end))
        loads = {}
        for ea in eas:
            if idc.print_insn_mnem(ea) == 'la':
                reg = idc.print_operand(ea,0)
                opd = idc.get_operand_value(ea,1)
                loads[reg] = opd
        if '$a0' in loads:
            return loads['$a0']
        else:
            return loads['$t9']

    def isLibcFunc(self,func_addr):
        if not(self.DOWN_BOUND): return 0 #TODO:Don't care them
        return (func_addr > self.UP_BOUND) and (func_addr < self.DOWN_BOUND)

    def get_up_bound(self):
        self.UP_BOUND = ida_ida.inf_get_start_ea()

    def get_down_bound(self):
        func_addr = None
        if self.pl == "ia32":
            func_addr = idc.get_name_ea_simple("fcntl")
            if func_addr == ida_idaapi.BADADDR:
                return None
        else:
            for func_addr in idautils.Functions():
                function = ida_funcs.get_func(func_addr)
                start_ea, end_ea = function.start_ea, function.end_ea

                for addr in idautils.Heads(start_ea, end_ea):
                    inst = idc.generate_disasm_line(addr, 0)
                    if MIPS_CHECK_INST[0] not in inst: continue

                    addrr = idc.next_head(addr)
                    instt = idc.generate_disasm_line(addrr, 1)
                    if MIPS_CHECK_INST[1] not in instt: continue

        self.DOWN_BOUND = func_addr

    @staticmethod
    def get_func_start(f):
        fn = idaapi.get_func(f)
        if not(fn):
            if not(ida_funcs.add_func(f)): return 0 
            fn = idaapi.get_func(f)
        return fn.start_ea

    def parse_one_func(self,f):
        fn = idaapi.get_func(f)
        if not(fn):
            if not(ida_funcs.add_func(f)): return 0 
            fn = idaapi.get_func(f)
        f_start, f_end = fn.start_ea, fn.end_ea
        if self.isLibcFunc(f_start): return 0
        if f_start in self.call_graph: return 1
        else: self.call_graph[f_start] = []
        eas = list(idautils.Heads(f_start, f_end))
        if self.pl == 'ia32':
            for ea in eas:
                mnem = idc.print_insn_mnem(ea)
                if mnem == 'call':
                    nextEA = self.get_func_start(idc.get_operand_value(ea,0))
                    if not(nextEA): continue
                    if self.parse_one_func(nextEA):
                        self.call_graph[f_start].append(nextEA)
        elif self.pl == 'mips':
            for ea in eas:
                mnem = idc.print_insn_mnem(ea)
                '''
                Two cases:
                1. jalr + $t9 <jalr always followed by t9>
                2. jr + $t9 <only jrs followed by t9 are func call>
                '''
                if mnem in ['jalr','jr']:
                    reg = idc.print_operand(ea,1)
                    if not(reg == '$t9'): continue
                    line = idc.GetDisasm(ea)
                    parts = line.split(';')
                    if len(parts) == 2:
                        nextEA = self.get_func_start(int(parts[-1].split('_')[-1],16))
                        if not(nextEA): continue
                        if self.parse_one_func(nextEA):
                            self.call_graph[f_start].append(nextEA)

        return 1

    def gen_call_graph(self):
        if self.pl == 'ia32':
            self.main = self.find_main_x86()
        elif self.pl == 'mips':
            self.main = self.find_main_mips()
        self.parse_one_func(self.main)
    
    def traverse_all_data_with_label_in_seg(self, name, start, end):
    
        lastlabel = ''
        laststart = 0
        size_of_all_const = {}
        for ea in range(start, end):
            if idc.get_name(ea):
                label =  idc.get_name(ea)
                if lastlabel:
                    size_of_all_const[lastlabel] = ea - laststart
                laststart = ea
                lastlabel = label
                for func in fromDataToFunc(ea, 0):
                    if self.isLibcFunc(func):
                        continue
                    if func in self.all_func_access_rodata:
                        func_instance = self.all_func_access_rodata[func]
                    else:
                        func_instance = Func_Access_Data(func)
                        self.all_func_access_rodata[func] = func_instance

                    func_instance.add_global(name, label, ea)
        
        if lastlabel:
            size_of_all_const[lastlabel] = end - laststart
        return size_of_all_const

    def traverse_all_data_with_label(self):
        label_with_size = {}
        global_segs = self.global_seg_start
        for seg_name, seg_start in global_segs.items():
            seg_end =  idc.get_segm_end(seg_start)
            size = self.traverse_all_data_with_label_in_seg(seg_name, seg_start, seg_end)
            label_with_size[seg_name] = size
        self.label_with_size = label_with_size
        return label_with_size 
    
    def get_global_seg_start(self,segs_name):
        global_seg_start = {}
        for seg in idautils.Segments():
            if idc.get_segm_name(seg) in segs_name:
                global_seg_start[idc.get_segm_name(seg) ] = seg
        
        if not '.roooodata' in global_seg_start:
            start, _ = self.add_rodata_segment()
            global_seg_start['.roooodata'] = start
        self.global_seg_start = global_seg_start
        return global_seg_start

    def add_rodata_segment(self):
        last_seg_end = idc.get_first_seg()
        # print(hex(last_seg_end))
        for s in idautils.Segments():
            start = idc.get_segm_start(s)
            end = idc.get_segm_end(s)
            if int(start) != int(last_seg_end):
                # found
                idaapi.add_segm(0, last_seg_end, start, "roooodata", "CONST")
                print("Adding segment from 0x%x to 0x%x" % (last_seg_end, start))
                print("OK")
                break
            else:
                last_seg_end = end
        idc.plan_and_wait(ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea())
        # idc.plan_and_wait(idc.MinEA(), idc.MaxEA())
        self.start = last_seg_end
        self.end = start
        return last_seg_end, start
        

class Func_Access_Data:
    def __init__(self, func):
        self.function = func
        # self.global_vars = None
        # self.index = []
        self.rodata_access = []
        self.data_access = []
        self.bss_access = []
    
    def add_global(self, seg, label, ea):
        if seg == '':
            self.addrodata(label, ea)
        elif seg == '.data':
            self.adddata(label, ea)
        elif seg ==  'bss':
            self.addbss(label,ea)
    
    def addrodata(self, label, ea):
        self.rodata_access.append(label)
    
    def adddata(self, label, ea):
        self.data_access.append(label)
    
    def addbss(self, label, ea):
        self.bss_access.append(label)

    def get_all_global_access(self):
        return self.rodata_access + self.data_access + self.bss_access
        


def fromDataToFunc(ea, deep):
    if deep > 5:
        print('No Xref function is found ' + hex(ea))
        return []
    funcs = []
    refs = idautils.DataRefsTo(ea)
    for r in refs:
        if idc.get_segm_name(r) == '.text':
            funcs.append(idc.get_func_attr(r, idc.FUNCATTR_START))
        elif idc.get_segm_name(r) == '.data' or idc.get_segm_name(r) == '.bss':
            # orign = r
            # r = r-1
            cnt = 1
            while not idc.get_name(r):
                r -= 1
                cnt += 1
                if cnt > 100:
                    print('cannot find a real label in .data'+ hex(ea))
                    break
            if cnt < 100:
                funcs = funcs + fromDataToFunc(r, deep+1)
        else:
            print("Ref in Seg {} at Addr {}".format( idc.get_segm_name(r), r))

    if not funcs:
        print('No Xref function is found ' + hex(ea))
    return funcs
                    
def collect_all_rodata(analyzer, addr, path):
    
    if addr in path:
        print('find big big loop')
        return Counter()
    else:
        path.add(addr)

    if addr in analyzer.all_func_access_rodata:
        faccess = analyzer.all_func_access_rodata[addr]
        all_access = Counter(faccess.get_all_global_access())
    else:
        all_access = Counter()

    if addr in analyzer.call_graph:
        for func in analyzer.call_graph[addr]:
            if func == addr:
                # print('find a loop')
                continue
            all_access = all_access + collect_all_rodata(analyzer, func, path)

    else:
        print('Function {} cannot be identified!'.format(hex(addr)))
    
    path.discard(addr)

    return all_access

# def get_global_seg_start(segs_name,analyzer):
#     global_seg_start = {}
#     for seg in idautils.Segments():
#         if idc.get_segm_name(seg) in segs_name:
#             global_seg_start[idc.get_segm_name(seg) ] = seg
    
#     if not '.roooodata' in global_seg_start:
#         start, _ = analyzer.add_rodata_segment()
#         global_seg_start['.roooodata'] = start
    
#     return global_seg_start

def main(arch):    
    analyzer = Analyzer()
    segs_name = set(['.roooodata', '.data', '.bss'])
    analyzer.get_global_seg_start(segs_name)
    analyzer.set_platform(arch)
    analyzer.gen_call_graph()
    print(analyzer.start,analyzer.end)
    size_of_all_rodata =  analyzer.traverse_all_data_with_label()
    for func in analyzer.all_func_access_rodata.values():
        print(hex(func.function))
        print(func.rodata_access)
        print(func.data_access)
        print(func.bss_access)
    all_access_rodata = collect_all_rodata(analyzer, analyzer.main,set())
    print(all_access_rodata)
    print(size_of_all_rodata)

if __name__ == "__main__":
    ida_auto.auto_wait()
    arch = idc.ARGV[1]
    main(arch) # run ida input the arch of file
    ida_pro.qexit(0)