# This file takes names of libraries and searches for relevant cves
import json
import os
import re
from packaging import version
from sys import argv

def main():
    libname = argv[1]
    publisher = argv[2]
    CPE = ":" + libname 
    CVEs = []
    CVEs = get_all_vul("CVE_JSONs/JSON/", CPE, publisher)
    t = write_json(CVEs, libname)
    if t != 0:
        print("Unable to write json")
    return 0

class CVE:
    def __init__(self, CVE_id, d):
        self.CVE_id = CVE_id
        self.vul_versions = []
        self.access_vector = None
        self.l_version = None
        self.fix_version = None
        self.description = d
    def get_latest(self, v_versions):
        return 0
    def add_version(self, version):
        self.vul_versions.append(version)
    def set_l_version(self, version):
        self.l_version = version
    def set_fix_version(self, version):
        self.fix_version = version
    def set_access_vector(self, vector):
        self.access_vector = vector
    def find_l_version2(self):
        if self.vul_versions == []:
            return 0
        elif self.l_version != None:
            return 0
        for t in self.vul_versions:
            if self.l_version == None:
                self.l_version = t
            elif t != None:
                if version.parse(letter_Version(t)) > version.parse(letter_Version(self.l_version)):
                    self.l_version = t
        return 0
    def find_fix_version(self):
        if self.fix_version != None:
            return 0
        elif self.l_version == None:
            return 0
        else:
            punct_stripped_sent = self.description.replace(",", '')
            pattern = re.compile("\.(?!\d)")
            punct_stripped_sent = pattern.sub(' ', punct_stripped_sent)
            s_array = self.description.split(" ")
            for string in s_array:
                if '.' in string and string[0].isdigit():
                    if self.fix_version == None:
                        if version.parse(letter_Version(string)) > version.parse(letter_Version(self.l_version)):
                            self.set_fix_version(string)
                    else:
                        if version.parse(letter_Version(string)) > version.parse(letter_Version(self.fix_version)):
                            self.set_fix_version(string)
            return 0


def check_child(children, libname, publisher):
    for x in children:
        if check_key(x, "children"):
            return check_child(children["children"], libname)
        if check_Key_Error(x, "cpe_match") == 0:
            for t in x["cpe_match"]:
                if check_Key_Error(t, "cpe23Uri") == 0:
                    if libname in t["cpe23Uri"] and publisher in t["cpe23Uri"]:
                        return True

def write_json(CVEs, libname):
    data = {}
    data[libname] = []
    for c in CVEs:
        data[libname].append({
            'CVE': c.CVE_id,
            'Fixed Version': c.fix_version,
            'Latest Version': c.l_version,
            'Access Vector': c.access_vector
        })
    fname = "lib_JSONs/"+ libname + ".json"
    with open(fname, 'w') as outfile:
        json.dump(data, outfile, indent=2)
    return 0

def get_all_vul(directory, lib, publisher):
    year = 2020
    os.system("cd CVE_JSONs/JSON")
    CVEs = []
    for x in range(year, 2001, -1):
        filename = "{}nvdcve-1.1-{}.json".format(directory, x)
        for i in extract_from_json(filename, lib, publisher):
            print(i.CVE_id)
            #i.find_l_version2()
            if i.fix_version != None:
                print("Fixed version")
                print(i.fix_version)
            elif i.l_version != None:
                print("Latest vulnerable version")
                print(i.l_version)
            else:
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

def extract_from_json(fname, libname, publisher):
    CVEs = []
    with open(fname, 'r') as file:
        data = file.read().replace('\n', '')
    y = json.loads(data)
    for n in y["CVE_Items"]:
        for x in n["configurations"]["nodes"]:
            if check_key(x, "children"):
                if check_child(x["children"], libname, publisher):
                    if check_Key_Error(x, "cpe_match") == 0:
                        c_ID = n["cve"]["CVE_data_meta"]["ID"]
                        description = n["cve"]["description"]["description_data"][0]["value"]
                        C_CVE = get_Versions(x["cpe_match"], ID, libname, description)
                        C_CVE.set_access_vector(n["impact"]["baseMetricV2"]["cvssV2"]["vectorString"])
                        CVEs.append(C_CVE)
            else:
                if check_Key_Error(x, "cpe_match") == 0:
                    for w in x["cpe_match"]:
                        if w["vulnerable"] == True and libname in w["cpe23Uri"] and publisher in w["cpe23Uri"]:
                            if n["cve"]["CVE_data_meta"]["ID"] not in CVEs:
                                ID = n["cve"]["CVE_data_meta"]["ID"]
                                description = n["cve"]["description"]["description_data"][0]["value"]
                                c = get_Versions(x["cpe_match"], ID, libname, description)
                                c.set_access_vector(n["impact"]["baseMetricV2"]["cvssV2"]["vectorString"])
                                CVEs.append(c)
                            break
    return CVEs

def get_Versions(d, ID, libname, description):
    libname = libname.replace(':', '')
    C = CVE(ID, description)
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
    C.find_l_version2()
    C.find_fix_version()
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
