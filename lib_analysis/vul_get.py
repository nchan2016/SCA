# This file takes names of libraries and searches for relevant cves
import json
import os
from sys import argv

def main():
    filename = argv[1]
    libname = argv[2]
    CVEs = []
    with open(filename, 'r') as file:
        data = file.read().replace('\n', '')
    y = json.loads(data)
    #print(y["configurations"])
    #print(y["configurations"]["nodes"][1]["cpe_match"][0])
    for n in y["CVE_Items"]:
        for x in n["configurations"]["nodes"]:
            if check_key(x, "children"):
                if check_child(x["children"], libname):
                    print(n["cve"]["CVE_data_meta"]["ID"])
            else:
                for w in x["cpe_match"]:
                    if w["vulnerable"] == True and libname in w["cpe23Uri"]:
                        if n["cve"]["CVE_data_meta"]["ID"] not in CVEs:
                            CVEs.append(n["cve"]["CVE_data_meta"]["ID"])
                        break
    for c in CVEs:
        print(c)
    return 0

def check_child(children, libname):
    for x in children:
        if check_key(x, "children"):
            print(x)
            return check_child(children["children"], libname)
        for t in x["cpe_match"]:
            if libname in t["cpe23Uri"]:
                return True

def get_all_vul(directory, lib):
    os.system("cd CVE_JSONs/JSON")
    CVEs = []
    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            for i in extract_from_json(filename, lib):
                CVEs.append(i)
    return CVEs

def extract_from_json(fname, lib):
    CVEs = []
    with open(filename, 'r') as file:
        data = file.read().replace('\n', '')
    y = json.loads(data)
    #print(y["configurations"])
    #print(y["configurations"]["nodes"][1]["cpe_match"][0])
    for n in y["CVE_Items"]:
        for x in n["configurations"]["nodes"]:
            if check_key(x, "children"):
                if check_child(x["children"], libname):
                    print(n["cve"]["CVE_data_meta"]["ID"])
            else:
                for w in x["cpe_match"]:
                    if w["vulnerable"] == True and libname in w["cpe23Uri"]:
                        if n["cve"]["CVE_data_meta"]["ID"] not in CVEs:
                            CVEs.append(n["cve"]["CVE_data_meta"]["ID"])
                        break

def check_key(d, key):
    if key in d.keys():
        return d[key] != None
    else:
        return False


if __name__ == '__main__':
    main()
