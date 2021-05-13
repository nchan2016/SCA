import os

def main():
    directory = r'/home/nick/home/SCA/lib_analysis/lib_JSONs'
    fixed_total = 0
    CVE_total = 0
    vul_libs = 0
    lib_total = 0
    fix_libs = 0
    for filename in os.listdir(directory):
        cmd = "rm " + filename
        if filename.endswith(".json"):
            lib_total = lib_total + 1
            c = count(filename, CVE_total, fixed_total)
            if c[1] > fixed_total:
                fix_libs = fix_libs + 1
                fixed_total = c[1]
            if c[0] > CVE_total:
                vul_libs = vul_libs + 1
                CVE_total = c[0]
            else:
                os.system(cmd)
        else:
            continue
    print("\nIn total....")
    print("Total number of CVES: ", CVE_total)
    print("Total number of fixed CVEs: ", fixed_total)
    print("Total number of libraries: ", lib_total)
    print("Total number of libraries with vulnerabilities: ", vul_libs)
    print("Total number of libraries with fixes to CVEs", fix_libs)
    return 0

def count(filename, CVE_total, fixed_total):
    CVEs = 0
    fixed = 0
    c = [0, 0]
    t = ""
    print(filename.replace(".json", "") + ":")
    f = open(filename, 'r')
    for line in f:
        if "CVE" in line:
            t = line
            CVEs = CVEs + 1
        elif "Fixed" in line and "null" not in line:
            fixed = fixed + 1
            print(t, fixed)
    print("Number of CVEs: ", CVEs)
    print("Fixed: ", fixed)
    print("\n")
    CVE_total = CVE_total + CVEs
    fixed_total = fixed_total + fixed
    c[0] = CVE_total
    c[1] = fixed_total
    return c


if __name__ == "__main__":
    main()
