#!/usr/bin/env python3
#
# MIT License
#
# Copyright (c) 2021 CrowdStrike Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import contextlib
import os
import random
import string
import subprocess
import shutil
import sys
import time

def rs(l):
    return ''.join(random.choices(string.ascii_lowercase, k=l))

def get_author(working_dir):
    proc = g(working_dir, f"log -1 --pretty=format:'%an'")
    return proc.stdout.strip().decode()

def git_latest_commitmsg(working_dir):
    proc = g(working_dir, f"log -1 --pretty=format:'%B'")
    return proc.stdout.strip().decode()

def file_desinfect(path):
    with open(path, "rb") as reader:
        content = reader.read()

    with subprocess.Popen(["/detab"], stdin=subprocess.PIPE, stdout=subprocess.PIPE) as proc:
        stdout, _ = proc.communicate(input=content)

    with open(path, "wb") as writer:
        writer.write(stdout)

def d(path):
    for entry in os.listdir(path):
        fpath = os.path.join(path, entry)

        if os.path.isdir(fpath) and not os.path.basename(fpath).startswith("."):
            d(fpath)

        if os.path.isfile(fpath):
            file_desinfect(fpath)

def g(w, c):
    return subprocess.run(f"git --git-dir {w}/.git {c}", capture_output=True, cwd=w, shell=True)

def p(old, new, ref):
    td = f"/tmp/repo-{rs(10)}"
    subprocess.run(f"git clone ~/repositories/hashfunctions.git {td}", capture_output=True, shell=True, check=True)

    author = get_author(td)
    commit_msg = git_latest_commitmsg(td).replace("'", "")

    if author == 'Order of 0x20':
        return

    print("040 == 32 == 0x20!")
    d(td)

    g(td, f"config user.name 'Order of 0x20'")
    g(td, f"config user.email 'confidential'")

    g(td, f"add .")
    g(td, f"commit -m '{commit_msg} 0x20!'")
    g(td, f"push")

    shutil.rmtree(td)

def main(lines):
    for line in lines:
        old, new, ref = line.strip().split(" ")

        with contextlib.suppress(Exception):
            p(old, new, ref)

if __name__ == "__main__":
    main(sys.stdin)
