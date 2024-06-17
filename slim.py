#!/usr/bin/env python3
 
import os
from os import listdir
from os import sys
 
def get_files():
 
    #files = os.listdir("/root/crashes/")
    files = os.listdir(sys.argv[1])
    return files
 
# argv[1]: crashes dir
# argv[2]: program-name
# argv[3]: param
def triage_files(files):
 
    len_argv = len(sys.argv)
    # 漏洞类型的统计
    cout_crashes = {"SEGV": 0, "HBO": 0, "UNKNOWN":0}
    
    folder = os.path.exists("analyze_output")
    if not folder:
        os.makedirs("analyze_output")
    
    for x in files:
        if len_argv == 4:
            original_output = os.popen(sys.argv[2] + " " + sys.argv[3] + " " + x + " 2>&1").read()
        else:
            original_output = os.popen(sys.argv[2] + " " + os.path.join(sys.argv[1] ,x) + " 2>&1").read()
        output = original_output
 
        # Getting crash reason
        crash = ''
        if "SEGV" in output:
            crash = "SEGV"
            cout_crashes["SEGV"] += 1
        elif "heap-buffer-overflow" in output:
            crash = "HBO"
            cout_crashes["HBO"] += 1
        else:
            crash = "UNKNOWN"
            cout_crashes["UNKNOWN"] += 1
 
        address = ''
        operation = ''
        if crash == "HBO":
            output = output.split("\n")
            counter = 0
            target_line = ''
            while counter < len(output):
                if output[counter] == "=================================================================":
                    target_line = output[counter + 1]
                    target_line2 = output[counter + 2]
                    counter += 1
                else:
                    counter += 1
            target_line = target_line.split(" ")
            address = target_line[5].replace("0x","")
 
 
            target_line2 = target_line2.split(" ")
            operation = target_line2[0]
 
 
        elif crash == "SEGV":
            output = output.split("\n")
            counter = 0
            while counter < len(output):
                if output[counter] == "=================================================================":
                    target_line = output[counter + 1]
                    target_line2 = output[counter + 2]
                    counter += 1
                else:
                    counter += 1
            if "unknown address" in target_line:
                address = "00000000"
            else:
                address = None
 
            if "READ" in target_line2:
                operation = "READ"
            elif "WRITE" in target_line2:
                operation = "WRITE"
            else:
                operation = None
 
        log_name = (x + "." + crash + "." + address + "." + operation)
        fn = os.path.join("analyze_output", log_name)
        f = open(fn,"w+")
        f.write(original_output)
        f.close()
 
    print("Numbers of the crash:")
    for ele in cout_crashes.items():
        print(ele)
 
if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Please input \"crash_analyze.py --help \"")
    elif sys.argv[1] == "--help":
        print("argv[1]: crashes dir\n",\
                "argv[2]: program-name\n",\
                "argv[3]: param"
        )
    else:
        files = get_files()
        triage_files(files)