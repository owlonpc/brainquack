#!/usr/bin/env python3

import glob
import subprocess
import os

test_files = glob.glob("tests/*.bf")
max_len = max(len(f) for f in test_files)

for test_file in test_files:
    stdin_file = test_file + ".stdin"
    stdout_file = test_file + ".stdout"
    
    stdin_data = ""
    if os.path.exists(stdin_file):
        with open(stdin_file, "r") as f:
            stdin_data = f.read()
    
    with open(stdout_file, "r") as f:
        expected = f.read()
    
    result = subprocess.run(["./bq", test_file], input=stdin_data, 
                          text=True, capture_output=True)
        
    if result.stdout == expected:
        status = "\033[42mPASS\033[0m"
        print(f"{test_file + ':':<{max_len + 1}} {status}")
    else:
        status = "\033[41mFAIL\033[0m"
        print(f"{test_file + ':':<{max_len + 1}} {status}")
        print(f"    expected: {repr(expected)}")
        print(f"    got:      {repr(result.stdout)}")