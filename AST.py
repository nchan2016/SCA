# This file extracts ASTs from C files

import sys
import os
import clang.cindex
from sys import argv

def main():
    f1_name = "result1.txt"
    f2_name = "result2.txt"
    f1 = open(f1_name, "w")
    output = os.popen("cd /usr/local/src/openssl-1.0.2h/crypto/mdc2 && sudo clang -Xclang -ast-dump -ast-dump-filter=MDC2_Update -fsyntax-only mdc2dgst.c").read()
    f1.write(output)
    f1.close()
    parse(f1_name, "result1_parsed.txt")
    f2 = open(f2_name, "w")
    output = os.popen("cd updated_OpenSSL/openssl-1.1.0/crypto/mdc2/ && sudo clang -Xclang -ast-dump -ast-dump-filter=MDC2_Update -fsyntax-only mdc2dgst.c").read()
    f2.write(output)
    f2.close()
    parse(f2_name, "result2_parsed.txt")
    diff("result1_parsed.txt", "result2_parsed.txt")
    return 0

def diff(file1, file2, output = "differences.txt"):
    command = "diff " + file1 + " " + file2 + " >> " + output
    os.system(command)

def parse(filename, output):
    f_raw = open(filename, "r")
    write_to_file = False
    f_parsed = open(output, "w")
    for line in f_raw:
        if "FunctionDecl" in line:
            if "MDC2_Update" in line:
                write_to_file = not write_to_file
            else:
                write_to_file = False
        if write_to_file:
            f_parsed.write(line)
    f_raw.close()
    f_parsed.close()
    return 0


if __name__ == "__main__":
    main()
