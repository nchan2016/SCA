# This file takes a single vulnerability and its fixed version and tells if fixed version notes CVE
import re
import json
import requests
from bs4 import BeautifulSoup
from github import Github
Git = None
from sys import argv
import time

def main():
    ACCESS_TOKEN = get_Token()
    global Git
    Git = Github(login_or_token=ACCESS_TOKEN)
    #ex: openssl/openssl
    try:
        repo_name = argv[1]
    except IndexError:
        repo_name = input("Please enter repo: ")
    libname = repo_name.split("/")[1]
    repo = Git.get_repo(repo_name)
    try:
        fname = argv[2]
    # Json file from vul_get
    except IndexError:
        fname = input("Please enter Json file name: ")
    with open(fname, 'r') as json_file:
        data = json.load(json_file)
        CVEs = []
        commits = []
        find_function(repo, '55d83bf7c10c7b205fffa23fa7c3977491e56c07')
        for cve in data[libname]:
            if cve['Fixed Version'] != None:
                #print(cve['CVE'])
                CVEs.append(cve['CVE'])
                #print(cve['Fixed Version'])
                #commits.append(search_commits_v2(repo, cve['CVE']))
                #if commit == 1:
                    #print("Commit not found\n")
                #else:
                    #url = get_url(repo, commit.name)
                    #check_log(url, cve['CVE'])
                    #time.sleep(10)
        commits = search_commits_v2(repo, CVEs)
    return 0

def get_Token():
    f = open("token.txt","r")
    for line in f:
        if "Git_Token" in line:
            s = line.strip('\n').split(' ')
            token = s[-1]
            f.close()
            print(token)
            return token
    print("Token not found")
    return -1

# Old code ignore below


# def search_commits(r, version):
#    version = version.replace('.', '')
#    v_array = list(version)
#    v_index = 0
#    is_true = False
#    potential_commits = []
#    tag_length = 1000
#    tags = r.get_tags()
#    for t in tags:
#        is_true = False
#        for char in t.name:
#            if v_array[v_index] == char:
#                if v_index == len(v_array) - 1:
#                    is_true = True
#                    break
#                else:
#                    v_index = v_index + 1
#
#         if is_true:
#            potential_commits.append(t)
#            v_index = 0
#        else:
#            v_index = 0
#    if len(potential_commits) == 0:
#        return 1
#    for w in potential_commits:
#        if len(w.name) < tag_length:
#            exact_commit = w
#            tag_length = len(w.name)
#    return exact_commit

# This version searches the git log
def search_commits_v2(r, CVEs):
    #test_CVE = "CVE-2016-6303"
    result = {}
    t = r.get_commits()
    for i in t:
        #print(i.commit.sha)
        m = i.commit.message
        if "CVE" in m:
            for c in CVEs:
                if c in m:
                    result.update({c : i.commit.sha})
                    print([c, i.commit.sha])
                    affected_functions = find_function(r, i.commit.sha)
                    for af in affected_functions:
                        print(af)
        #print(m)
    return result

def get_url(repo, tag):
    repo_url = repo._git_url.value
    repo_array = repo_url.split(":")
    repo_array[1] = repo_array[1].replace(".git", "/commits/")
    repo_array[1] = "https:" + repo_array[1]
    result = repo_array[1] + tag
    return result

def find_function(repo, sha):
    methods = []
    patch = repo.get_commit(sha)
    for f in patch.files:
        methods.append(parse_function_name(f))
    return methods
    #for m in methods:
        #print(m)

def parse_function_name(f):
    function_name = []
    if f.patch != None:
        for i in f.patch:
                if i == '(':
                    break
                function_name.append(i)
        f_string = ''.join(function_name)
        f_string = f_string.split(' ')
        #print(f_string[-1])
        return f_string[-1]
    else:
        return None



def check_log(url, CVE_ID):
    r = requests.get(url)
    soup = BeautifulSoup(r.content, 'lxml')
    words = soup.find(text=lambda text: text and CVE_ID in text)
    if CVE_ID == "CVE-2006-4339":
        words = soup.find(text=lambda text: text and "CVE" in text)
        print("Nothing")
    if words != None:
        print("CVE found\n")
    else:
        print("CVE not found\n")

    return 0

if __name__ == '__main__':
    main()
