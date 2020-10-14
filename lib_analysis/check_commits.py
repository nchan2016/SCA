# This file takes a single vulnerability and its fixed version and tells if fixed version notes CVE
import re
import requests
from bs4 import BeautifulSoup
from github import Github
#User will have to provide below
ACCESS_TOKEN = 'c3117f9784d6522c4818951742b50856e4985873'
Git = Github(ACCESS_TOKEN)
from sys import argv

def main():
    repo = Git.get_repo(argv[1])
    cve_ID = argv[2]
    version = argv[3]
    commit = search_commits(repo, version)
    if commit == 1:
        print("Commit not found")
        return 0
    url = get_url(repo, commit.name)
    check_log(url, cve_ID)
    return 0

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
    if words != None:
        print("CVE found")

    return 0

if __name__ == '__main__':
    main()
