# This file takes names of libraries and searches for relevant cves
import json
from sys import argv

def main():
    filename = argv[1]
    libname = argv[2]
    with open(filename, 'r') as file:
        data = file.read().replace('\n', '')
    y = json.loads(data)
    #print(y["configurations"])
    #print(y["configurations"]["nodes"][1]["cpe_match"][0])
    for n in y["CVE_Items"]:
        for x in n["configurations"]["nodes"]:
            if x["operator"] == "AND":
                if check_and(x["children"], libname):
                    print(n["cve"]["CVE_data_meta"]["ID"])
            else:
                for w in x["cpe_match"]:
                    if w["vulnerable"] == True and libname in w["cpe23Uri"]:
                        #print("hello")
                        print(n["cve"]["CVE_data_meta"]["ID"])
                        break
            #x["cpe_match"]["vulnerable"] == "true":
    return 0

def check_and(children, libname):
    for x in children:
        if x["operator"] == "AND":
            return check_and(children["children"])
        for t in x["cpe_match"]:
            if libname in t["cpe23Uri"]:
                return True



if __name__ == '__main__':
    main()
