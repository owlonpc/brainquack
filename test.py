#!/usr/bin/env python3

import glob, subprocess, os

files = glob.glob("tests/*.bf")
pad = max(len(f) for f in files) + 1

for f in files:
    stdout = open(f + ".stdout")
    stdin = open(f + ".stdin", "r") if os.path.exists(f + ".stdin") else open(os.devnull)

    result = subprocess.run(["./bq", f], input=stdin.read(), text=True, capture_output=True)
    expected = stdout.read()
    passed = result.stdout == expected

    status = "\033[42mPASS\033[0m" if passed else "\033[41mFAIL\033[0m"
    print(f"{f + ':':<{pad}} {status}")
    if not passed:
        print(f"    expected: {repr(expected)}")
        print(f"    got:      {repr(result.stdout)}")