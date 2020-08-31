import subprocess
import os
import sys
import multiprocessing
import json

from pwn import info, debug, context, warn
context.log_level = "info"
#context.log_level = "debug"

IDA_PATH = "idat"
SCRIPT_BASE = "./script/"

BOUND_CHECK = SCRIPT_BASE + "bound_check.py"
LUMINA_CHECK = SCRIPT_BASE + "lumina_check.py"

IDB_BASE = "./idb/"
LOG_PATH = "./log/"
OUTPUT_PATH = "./output/"

IA32_PATH = IDB_BASE + "ia32/"
MIPS_PATH = IDB_BASE + "mips/"

CPU_NUM = os.cpu_count()

def run_ida_script(bin_abs_path, script_path=None, args=None, handler=None):
    output = None
    
    basename = os.path.basename(bin_abs_path)
    arch = bin_abs_path.split("/")[-2]
    output_path = os.path.join(OUTPUT_PATH, arch, basename+".result")
    log_path = os.path.join(LOG_PATH, arch, basename+".log")
    if os.path.exists(log_path):
        os.remove(log_path)
    if os.path.exists(output_path):
        os.remove(output_path)
    
    if script_path == None:
        command = f"{IDA_PATH} -A -B {bin_abs_path}"
    else:
        if args != None:
            args = " ".join(args)
        else:
            args = ""
        
        command = f"{IDA_PATH} -A -S\"{script_path} {output_path} {arch} {args}\" {bin_abs_path}"
        command = f"IDALOG=\"{log_path}\" {command} "

try:
    debug(F"Running script for {bin_abs_path}...")
    debug(command)
    subprocess.run(command, shell=True).check_returncode()
    debug("Done")
    except subprocess.CalledProcessError as e:
        warn(f"error happened in {bin_abs_path}, {e}")
        return None
    
    if os.path.exists(output_path):
        if handler!=None and script_path!=None :
            output = handler(output_path)

return output


def worker(paths, script=None, args=None, handler=None):
    
    result = {}
    
    for path in paths:
        tmp = run_ida_script(path, script, args, handler)
        debug(path)
        #info(path)
        if tmp != None:
            result[path] = tmp

return result

def bound_handler(output_path):
    with open(output_path, "r") as output_file:
        data = output_file.read()
        info(data)
        return data

def bound_handler_main(result):
    final_result = 0
    for item in result:
        for _, r in item.items():
            if r == "1":
                final_result += 1
            else:
                print(_)
    print(final_result)


def main():
    count = 0
    pool = multiprocessing.Pool(processes=CPU_NUM)
    procs = []
    
    worker_paths = []
    for _ in range(CPU_NUM):
        worker_paths.append(list())

    #for dir_path in [IA32_PATH]:
    #for dir_path in [MIPS_PATH]:
    for dir_path in [IA32_PATH, MIPS_PATH]:
        for bin_path in os.listdir(dir_path):
            
            #if count >= 32: break
            
            bin_abs_path = os.path.join(dir_path, bin_path)
            assert os.path.exists(bin_abs_path)
            worker_paths[count % CPU_NUM].append(bin_abs_path)
            count += 1


for i in range(CPU_NUM):
    # generate idb
    #procs.append(pool.apply_async(worker, args=(worker_paths[i], )))
    
    # other idapython scripts  (paths, script_path, args, handler)
    procs.append(pool.apply_async(worker, args=(worker_paths[i], BOUND_CHECK, None, bound_handler, )))
    
    pool.close()
    pool.join()
    
    result = []
    for item in procs:
        result.append(item.get())
    
    #bound handler
    bound_handler_main(result)

if __name__ == "__main__":
    main()
