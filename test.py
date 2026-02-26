#!/usr/bin/env python3

import glob, subprocess, os, sys, signal

def exitstatus(code):
    if code < 0:
        try:
            return f"killed by {signal.Signals(-code).name}"
        except ValueError:
            return f"killed by signal {-code}"
    return f"exited with code {code}"

files = glob.glob("tests/*.bf")
pad = max(len(f) for f in files) + 1
failed = False

for f in files:
    stdout = open(f + ".stdout")
    stdin = open(f + ".stdin", "r") if os.path.exists(f + ".stdin") else open(os.devnull)

    result = subprocess.run(["./bq", f], input=stdin.read(), text=True, capture_output=True)
    expected = stdout.read()
    passed = result.stdout == expected and result.returncode == 0

    status = "\033[42mPASS\033[0m" if passed else "\033[41mFAIL\033[0m"
    print(f"{f + ':':<{pad}} {status}")
    if not passed:
        failed = True
        if result.returncode != 0:
            print(f"  {exitstatus(result.returncode)}")
        print(f"  expected: {repr(expected)}")
        print(f"  got:      {repr(result.stdout)}")

sys.exit(1 if failed else 0)