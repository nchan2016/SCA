# This file extracts the names of the most popular git repos
import webbrowser
from github import Github
#User will have to provide below
ACCESS_TOKEN = '04fed68f42d29f8b22bfa9427af712abca90197b'
g = Github(ACCESS_TOKEN)


def main():
    stars = 40000
    language = "C"
    tag = "library"
    keywords = get_keywords(stars, language, tag)
    repos = get_repos(keywords)
    write_repos(repos)
    
def write_repos(repos):
    f = open("repo_names.txt", "w")
    for r in repos:
        f.write(f'{r}\n')

def get_repos(keywords):
    git_repos = []
    query = '+'.join(keywords)
    print(query)
    result = g.search_repositories(query, 'stars', 'desc')

    print(f'Found {result.totalCount} repo(s)')

    for repo in result:
        if repo.stargazers_count >= 4000:
            print(f'{repo.clone_url}, {repo.language}, {repo.stargazers_count} stars')
            git_repos.append(repo.clone_url)
        else:
            break
    git_repos = parse_repo_names(git_repos)
    return git_repos

def parse_repo_names(repos):
    result = []
    for i in repos:
        line = i.split('/')
        result.append(line[-1].strip(".git"))
    return result

    

def get_keywords(stars, language, tag):
    keywords = [tag, "language:" + language]#, "stars:>=" + str(stars)]
    return keywords


if __name__ == '__main__':
    main()
