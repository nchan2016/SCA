# This file uses vul_get.py to fetch all vulnerabilities for the top C libraries
import os

def main():
    os.system("python3 getRepos.py")
    vul_get()
    return 0

def vul_get():
    f = open("repo_names.txt", "r")
    print("Top repos: \n")
    for line in f:
        print(line)
    #print('\n'*2)
    f.close()
    f2 = open("repo_names.txt", "r")
    print("Repo CVES: \n")
    for line in f2:
        command = "python3 vul_get.py " + line
        print(line)
        print(": ")
        os.system(command)
        
if __name__ == '__main__':
    main()
