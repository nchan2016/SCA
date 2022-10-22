import os


#Checks total amount of commits with CVE's in its logs
def main():
    directory = r'/home/nick/home/SCA/lib_analysis/commit_search'
    CVE_fixed_total = 0
    CVE_found_total = 0
    for filename in os.listdir(directory):
        if filename.endswith(".txt"):
            c = count(filename, CVE_fixed_total, CVE_found_total)
            CVE_found_total = c[1]
            CVE_fixed_total = c[0]
        else:
            continue
    print("\nIn total....")
    print("Total number of CVE fixes: ", CVE_fixed_total)
    print("Total number of CVEs in commits: ", CVE_found_total)
    return 0

def count(filename, CVE_fixed_total, CVE_found_total):
    CVEs = 0
    fixed = 0
    c = [0, 0]
    t = ""
    f = open(filename, 'r')
    for line in f:
        if "CVE-" in line:
            t = line
            CVEs = CVEs + 1
        if "CVE found" in line:
            fixed = fixed + 1
            print(t, fixed)
    if CVEs != 0:
        print(filename.replace(".json", "") + ":")
        print("Number of CVE fixes: ", CVEs)
        print("Number of found CVEs in commits: ", fixed)
        print("\n")
    CVE_fixed_total = CVE_fixed_total + CVEs
    CVE_found_total = CVE_found_total + fixed
    c[0] = CVE_fixed_total
    c[1] = CVE_found_total
    return c


if __name__ == "__main__":
    main()
