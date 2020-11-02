import os

def main():
    directory = r'/home/nick/home/SCA/lib_analysis/lib_JSONs'
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            count(filename)
        else:
            continue
    return 0

def count(filename):
    CVEs = 0
    Fixed_CVEs = 0
    print(filename.replace(".json", "") + ":")
    f = open(filename, 'r')
    for line in f:
        if "CVE" in line:
            CVEs = CVEs + 1
        elif "Fixed" in line and "null" not in line:
            Fixed_CVEs = Fixed_CVEs + 1
    print("Number of CVEs: ", CVEs)
    print("Fixed: ", Fixed_CVEs)


if __name__ == "__main__":
    main()
