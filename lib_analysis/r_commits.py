import re
import json
import requests
from bs4 import BeautifulSoup
from github import Github
Git = None
from sys import argv
import time

def main():
    path1 = "/home/nick/home/SCA/lib_analysis/Phase2/repos/"
    path2 = "/home/nick/home/SCA/lib_analysis/lib_JSONs/"
    Found_CVEs = 0
    try:
        repo_file = path1 + argv[1]
    except IndexError:
        # Example input: "openssl/log.txt"
        input1 = input("Please enter repo file: ")
        repo_file = path1 + input1
        #print(repo_file)
        #repo_file = "/home/nick/home/SCA/OpenSSL_Repo/openssl/log.txt"
    try:
        fname = path2 + argv[2]
    except IndexError:
        # Example input: "openssl.json"
        input2 = input("Please enter Json file name: ")
        fname = path2 + input2
    libname = input1.replace("/log.txt","")
    with open(fname, 'r') as json_file:
        data = json.load(json_file)
        #Checks JSON file for fixed versions
        for cve in data[libname]:
            if cve['Fixed Version'] != None:
                #Searches commits for CVE IDs
                commit = search_commits(repo_file, str(cve['CVE']))
                if commit != None:
                    Found_CVEs += 1
                    print(cve['CVE'])
                    print(commit)
                    print('\n')
    print(Found_CVEs)
    print("\n")
    return 0

def compare():
    found_commits = []
    with open("r_commits_results.txt", 'r') as f1:
        for line in f1:
            found_commits.append(line)
    f1.close()
    with open("/home/nick/home/SCA/lib_analysis/commit_search/found_openssl.txt", 'r') as f2:
        for line in f2:
            if 'CVE' in line and line in found_commits:
                found_commits.remove(line)
    f2.close()
    for x in found_commits:
        print(x)

def search_commits(repo_file, CVE):
    # Read the git log and search for CVEs and record the commit ID
    cur_commit = ''
    prev_line = ''
    f1 = open(repo_file, encoding = "ISO-8859-1")
    for line in f1:
        if "Author:" in line:
            try:
                #print(prev_line)
                cur_commit = prev_line.split(' ')[1]
                #print(cur_commit)
            except IndexError:
                cur_commit = prev_line
        if CVE in line:
            #print(cur_commit)
            f1.close()
            return cur_commit
        prev_line = line
    f1.close()
    return None

if __name__ == '__main__':
    main()
