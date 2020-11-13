# This file takes a single vulnerability and its fixed version and tells if fixed version notes CVE
import re
import json
import requests
from bs4 import BeautifulSoup
from github import Github
Git = None
from sys import argv

def main():
    ACCESS_TOKEN = get_Token()
    global Git
    Git = Github(ACCESS_TOKEN)
    try:
        repo_name = argv[1]
    except IndexError:
        repo_name = input("Please enter repo: ")
    libname = repo_name.split("/")[1]
    repo = Git.get_repo(repo_name)
    try:
        fname = argv[2]
    except IndexError:
        fname = input("Please enter Json file name: ")
    with open(fname, 'r') as json_file:
        data = json.load(json_file)
        for cve in data[libname]:
            if cve['Fixed Version'] != None:
                print(cve['CVE'])
                print(cve['Fixed Version'])
                commit = search_commits(repo, cve['Fixed Version'])
                if commit == 1:
                    print("Commit not found\n")
                else:
                    url = get_url(repo, commit.name)
                    check_log(url, cve['CVE'])
    return 0

def get_Token():
    f = open("token.txt","r")
    for line in f:
        if "Git_Token" in line:
            s = line.strip('\n').split(' ')
            token = s[-1]
            f.close()
            return token
    print("Token not found")
    return -1

def search_commits(r, version):
    version = version.replace('.', '')
    v_array = list(version)
    v_index = 0
    is_true = False
    potential_commits = []
    tag_length = 1000
    tags = r.get_tags()
    for t in tags:
        is_true = False
        for char in t.name:
            if v_array[v_index] == char:
                if v_index == len(v_array) - 1:
                    is_true = True
                    break
                else:
                    v_index = v_index + 1

        if is_true:
            potential_commits.append(t)
            v_index = 0
        else:
            v_index = 0
    if len(potential_commits) == 0:
        return 1
    for w in potential_commits:
        if len(w.name) < tag_length:
            exact_commit = w
            tag_length = len(w.name)
    return exact_commit

def get_url(repo, tag):
    repo_url = repo._git_url.value
    repo_array = repo_url.split(":")
    repo_array[1] = repo_array[1].replace(".git", "/commits/")
    repo_array[1] = "https:" + repo_array[1]
    result = repo_array[1] + tag
    return result


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
