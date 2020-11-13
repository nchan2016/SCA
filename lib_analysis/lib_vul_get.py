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
    f2 = open("repo_with_owners.txt", "r")
    print("Repo CVES: ")
    for line in f2:
        line = line.split("/")
        line[1] = line[1].strip('\n')
        line.reverse()
        line = ' '.join(line)
        command = "python3 vul_get.py " + line
        print(line + ":")
        os.system(command)
        
if __name__ == '__main__':
    main()
