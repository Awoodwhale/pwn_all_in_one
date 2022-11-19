#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import sys, os, subprocess

LIBS_PATH = "/home/woodwhale/workspace/ctftools/pwntools/glibc-all-in-one/libs/" # 使用自己glibc/libs的目录
BINARY = ""
LIBC = ""
BIT = ""

def check_args():
    if not (3 >= len(sys.argv) >= 2) :
        print("\033[31mParameter error!Try again!\033[0m")
        print("\033[35mUsage   :  libcpatcher elfname (libc_addr)\033[0m")
        print("\033[35mExample :  libcpatcher hacknote 2.23-0ubuntu3_amd64\033[0m")
        exit(0)

def choose_libc():
    print("\033[32mYou can choose: \033[0m")
    libs_list = os.listdir(LIBS_PATH)
    libs_list.sort()
    for i in range(0,len(libs_list)):
        print(f"\033[31m{i+1}\033[0m \033[33m:\033[0m \033[36m{libs_list[i]}\033[0m")
    i = int(input("\033[32mChoose: \033[0m"),10) - 1
    if i >= len(libs_list) :
        print("\033[31mChoose error!Try again!\033[0m")
        exit(0)
    return libs_list[i]

def init():
    global BINARY, LIBC, BIT
    BINARY = sys.argv[1]
    LIBC = sys.argv[2] if len(sys.argv) == 3 else choose_libc()
    BIT = subprocess.check_output([f"file {BINARY}"],shell=True).decode().split(" ")[2]

def libcpatcher():
    global BINARY, LIBC, BIT
    error = "\033[31mText file busy!\033[0m"
    try:
        print("\n\033[31mBefor patch \033[0m")
        print(subprocess.check_output([f"ldd {BINARY}"],shell=True).decode())
        if "64" in BIT and "amd64" in LIBC:
            subprocess.check_output([f"patchelf --set-interpreter {LIBS_PATH}{LIBC}/ld-linux-x86-64.so.2 --set-rpath {LIBS_PATH}{LIBC} {BINARY}"],shell=True)
        elif "32" in BIT and "i386" in LIBC :
            subprocess.check_output([f"patchelf --set-interpreter {LIBS_PATH}{LIBC}/ld-linux.so.2 --set-rpath {LIBS_PATH}{LIBC} {BINARY}"],shell=True)
        else:
            error = "\033[31mlibc Bit error!Try again!\033[0m"
            exit(0)
        print("\033[32m======================================================================\033[0m \n")
        print("\033[31mAfter patch \033[0m")
        print(subprocess.check_output([f"ldd {BINARY}"],shell=True).decode())
    except:
        print(error)
        exit(0)
    
def main():
    check_args()
    init()
    libcpatcher()
    
if __name__ == '__main__':
    main()
