from sys import argv
import json

def main() :
    err = import_json("/home/nick/home/SCA/lib_analysis/lib_JSONs/openssl.json")
    if err != 0:
        print(err)
    return 0

def import_json(filename):
    f = open(filename, 'r')
    data = json.load(f)
    if_fixed = False
    exploit_availible= False
    for cve in data["openssl"]:
        print(cve["CVE"])
        if cve["Fixed Version"] != "null":
            if_fixed = True
        else:
            if_fixed = False
        if cve.get("Exploit Availible"):
            if cve["Exploit Availible"] == "True":
                exploit_availible = True
            else:
                exploit_availible = False
        else:
            exploit_availible = False
        access_vector = cve["Access Vector"]
        update_factor = find_update_factor(if_fixed)
        value_dict = parse_access(access_vector)
        MF_init = find_MF_init(value_dict)
        print("Access vector:    ", access_vector)
        print("MF_init: ", MF_init)
        MF_final = (update_factor + MF_init)/2
        print("MF_final: ", MF_final)
        MI = find_MI(value_dict)
        Risk = (MI + MF_final)/2
        print("MI: ", MI)
        print("Risk: ", Risk)
        print("\n")
    return 0

def find_MI(value_dict):
    return (value_dict["B_C"] + value_dict["B_I"] + value_dict["B_A"])/3

def find_MF_init(value_dict):
    MF_init = (value_dict["B_AR"] + value_dict["B_AC"] + value_dict["B_AU"])/3
    return MF_init

def find_update_factor(if_fixed):
    if if_fixed:
        return (1.0 + 0.87)/2
    else:
        return 1.0

def parse_access(access_vector):
    vector_list = access_vector.split('/')
    vector_dict = {
            "B_AR" : vector_list[0][-1],
            "B_AC" : vector_list[1][-1],
            "B_AU" : vector_list[2][-1],
            "B_C" : vector_list[3][-1],
            "B_I" : vector_list[4][-1],
            "B_A" : vector_list[5][-1]
    }
    value_dict = parse_cvss(vector_dict)
    return value_dict

def parse_cvss(vector_dict):
    result = {
            "B_AR" : 0,
            "B_AC" : 0,
            "B_AU" : 0,
            "B_C" : 0,
            "B_I" : 0,
            "B_A" : 0
    }
    #B_AR
    if vector_dict["B_AR"] == 'L':
        result["B_AR"] = 0.395
    elif vector_dict["B_AR"] == 'A':
        result["B_AR"] = 0.646
    elif vector_dict["B_AR"] == 'N':
        result["B_AR"] = 1.0
    #B_AC
    if vector_dict["B_AC"] == 'H':
        result["B_AC"] = 0.35
    elif vector_dict["B_AC"] == 'M':
        result["B_AC"] = 0.61
    elif vector_dict["B_AC"] == 'L':
        result["B_AC"] = 0.71
    #B_AU
    if vector_dict["B_AU"] == 'M':
        result["B_AU"] = 0.45
    elif vector_dict["B_AU"] == 'S':
        result["B_AU"] = 0.56
    elif vector_dict["B_AU"] == 'N':
        result["B_AU"] = 0.704
    #B_C
    if vector_dict["B_C"] == 'N':
        result["B_C"] = 0.0
    elif vector_dict["B_C"] == 'P':
        result["B_C"] = 0.275
    elif vector_dict["B_C"] == 'C':
        result["B_C"] = 0.660
    #B_I
    if vector_dict["B_I"] == 'N':
        result["B_I"] = 0.0
    elif vector_dict["B_I"] == 'P':
        result["B_I"] = 0.275
    elif vector_dict["B_I"] == 'C':
        result["B_I"] = 0.660
    #B_A
    if vector_dict["B_A"] == 'N':
        result["B_A"] = 0.0
    elif vector_dict["B_A"] == 'P':
        result["B_A"] = 0.275
    elif vector_dict["B_A"] == 'C':
        result["B_A"] = 0.660
    return result


if __name__ == '__main__':
    main()







