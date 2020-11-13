# This file extracts the names of the most popular git repos
import webbrowser
from github import Github
#User will have to provide below
#ACCESS_TOKEN = get_Token()
g = None


def main():
    stars = 40000
    language = "C"
    tag = "library"
    ACCESS_TOKEN = get_Token()
    global g 
    g = Github(ACCESS_TOKEN)
    keywords = get_keywords(stars, language, tag)
    repos = get_repos(keywords)
    write_repos(repos)

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
    
def write_repos(repos):
    f = open("repo_names.txt", "w")
    for r in repos:
        f.write(f'{r[0]}\n')
    f.close()
    f2 = open("repo_with_owners.txt", "w")
    for t in repos:
        f2.write(f'{t[1]}\n')
    f2.close()

def get_repos(keywords):
    git_repos = []
    count = 20
    query = '+'.join(keywords)
    print(query)
    result = g.search_repositories(query, 'stars', 'desc')

    print(f'Found {result.totalCount} repo(s)')

    for repo in result:
        if repo.stargazers_count >= 3000 and count != 0:
            print(f'{repo.clone_url}, {repo.language}, {repo.stargazers_count} stars')
            git_repos.append(repo.clone_url)
            count = count - 1
        else:
            break
    git_repos = parse_repo_names(git_repos)
    return git_repos

def parse_repo_names(repos):
    #just get repo names for vul_get.py
    #repo_name for check_commits.py
    result = []
    for i in repos:
        line = i.split('/')
        repo_name = line[-2:]
        repo_name[-1] = repo_name[-1].replace(".git", '')
        repo_name = '/'.join(repo_name)
        result.append((line[-1].replace(".git", ''), repo_name))
    return result
    

def get_keywords(stars, language, tag):
    keywords = [tag, "language:" + language]#, "stars:>=" + str(stars)]
    return keywords


if __name__ == '__main__':
    main()
