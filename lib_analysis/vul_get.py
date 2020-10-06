# This file takes names of libraries and searches for relevant cves
import json
import os
import re
from packaging import version
from sys import argv

def main():
    libname = argv[1]
    CVEs = []
    CVEs = get_all_vul("CVE_JSONs/JSON/", libname)
    return 0

class CVE:
    def __init__(self, CVE_id):
        self.CVE_id = CVE_id
        self.vul_versions = []
        self.l_version = None
        self.fix_version = None
    def get_latest(self, v_versions):
        return 0
    def add_version(self, version):
        self.vul_versions.append(version)
    def set_l_version(self, version):
        self.l_version = version
    def set_fix_version(self, version):
        self.fix_version = version
    def find_l_version2(self):
        if self.vul_versions == []:
            return 0
        elif self.l_version != None:
            return 0
        for t in self.vul_versions:
            if self.l_version == None:
                self.l_version = t
            else:
                if version.parse(letter_Version(t)) > version.parse(letter_Version(self.l_version)):
                    self.l_version = t
        return 0
    #def find_l_version(self):
        #array_length = 0
        #if self.vul_versions == []:
            #return 0
        #else:
            #for v in self.vul_versions:
                #v = v.split(".")
            #array_length = len(self.vul_versions[0])
            #version_array = [0] * (array_length + 1)
            #for t in self.vul_versions:
                #for x in range(len(t)):
                    #if version_array[x] == 0:
                        #version_array[x] = t[x]
                    #elif any(c.isalpha() for c in t[x]):
                        #temp = re.compile("([0-9]+)([a-zA-Z]+)")
                        #res = temp.match(t[x]).groups()
                        #if version_array[x].isdecimal():
                            #if int(res[0]) > int(version_array[x])
                        #res2 = temp.match(version_array[x]).groups()
                        #if int(res2[0]) > 
                    #elif int(t[x]) > int(version_array[x]):
                        #version_array[x] = t[x]


def check_child(children, libname):
    for x in children:
        if check_key(x, "children"):
            return check_child(children["children"], libname)
        if check_Key_Error(x, "cpe_match") == 0:
            for t in x["cpe_match"]:
                if check_Key_Error(t, "cpe23Uri") == 0:
                    if libname in t["cpe23Uri"]:
                        return True

def get_all_vul(directory, lib):
    year = 2020
    os.system("cd CVE_JSONs/JSON")
    CVEs = []
    for x in range(year, 2001, -1):
        filename = "{}nvdcve-1.1-{}.json".format(directory, x)
        for i in extract_from_json(filename, lib):
            print(i.CVE_id)
            i.find_l_version2()
            if i.fix_version != None:
                print("Fixed version")
                print(i.fix_version)
            elif i.l_version != None:
                print("Latest vulnerable version")
                print(i.l_version)
            print("Vulnerable versions")
            for x in i.vul_versions:
                print(x)
            CVEs.append(i)
    return CVEs

def parse_Uri(lib, array):
    b = False
    for a in array:
        if b:
            if lib != a:
                return a
        elif lib == a:
            b = True

def extract_from_json(fname, libname):
    CVEs = []
    with open(fname, 'r') as file:
        data = file.read().replace('\n', '')
    y = json.loads(data)
    for n in y["CVE_Items"]:
        for x in n["configurations"]["nodes"]:
            if check_key(x, "children"):
                if check_child(x["children"], libname):
                    if check_Key_Error(x, "cpe_match") == 0:
                        c_ID = n["cve"]["CVE_data_meta"]["ID"]
                        C_CVE = get_Versions(x["cpe_match"], ID, libname)
                        CVEs.append(C_CVE)
            else:
                if check_Key_Error(x, "cpe_match") == 0:
                    for w in x["cpe_match"]:
                        if w["vulnerable"] == True and libname in w["cpe23Uri"]:
                            if n["cve"]["CVE_data_meta"]["ID"] not in CVEs:
                                ID = n["cve"]["CVE_data_meta"]["ID"]
                                c = get_Versions(x["cpe_match"], ID, libname)
                                CVEs.append(c)
                            break
    return CVEs

def get_Versions(d, ID, libname):
    C = CVE(ID)
    for w in d:
        if w["vulnerable"] == True and libname in w["cpe23Uri"]:
            if check_key(w, "versionEndIncluding"):
                C.set_l_version(str(w["versionEndIncluding"]))
            elif check_key(w, "versionEndExcluding"):
                C.set_fix_version(str(w["versionEndExcluding"]))
            else:
                Uri = w["cpe23Uri"].split(":")
                vul_version = parse_Uri(libname, Uri)
                C.add_version(vul_version)
    return C

def letter_Version(version):
    v_array = version.split(".")
    v2 = v_array
    for v in range(len(v_array)):
        if any(c.isalpha() for c in v_array[v]):
            p = list(v_array[v])
            for t in range(len(p)):
                if p[t].isalpha():
                    p[t] = str(ord(p[t]))
            v2 = v2[:v] + p + v2[(v+1):]
    result = ".".join(v2)
    return result



def check_Key_Error(d, key):
    t = d.get(key)
    if t:
        return 0
    else:
        return 1

def check_key(d, key):
    if key in d.keys():
        return d[key] != None
    else:
        return False


if __name__ == '__main__':
    main()
