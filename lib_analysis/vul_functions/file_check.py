from sys import argv
import os
import time
# This file looks at a map file generated by the linker and compares it with 
# object files and the archive files to find out what third-party functions
# are used.

# gcc -c <source-file.c>
# ld -Map output.map -N -o <name of executable> <object_file> -lssl -lcrypto
def main():
    prev_line = ""
    archive_files = []
    functions = []
    object_files = fetch_files("/home/nick/home/SCA/OpenVPN_analysis/openvpn/src/openvpn")
    for i in range(len(argv)):
        if i == 1:
            map_file = argv[i]
        if i == 2:
            object_file = argv[i]
        elif i > 2:
            archive_files.append(argv[i])
    f1 = open(map_file, "r")
    lines = f1.readlines()
    for o in object_files:
        print(o)
        obj_file = " " + o + " "
        for line in lines:
            for a in archive_files:
                if a in prev_line and obj_file in line:
                    #print(line)
                    functions.append(parse_function(line, o))
            prev_line = line
    f1.close()
    f2 = open("object_file_functions.txt", "w")
    for f in functions:
        f2.write(f)
    f2.close()
    return 0

def parse_function(f, obj_file):
    f = f.replace(' ','')
    f = f.replace(obj_file, '')
    f = f.replace('(', '')
    f = f.replace(')', '')
    result = "  " + f
    print(result)
    return f

def fetch_files(path):
    # Extracting all the contents in the directory corresponding to path
    l_files = os.listdir(path)
    object_files = []
    # Iterating over all the files
    for file in l_files:

        # Instantiating the path of the file
        file_path = path + '/' + file
        #print(file_path)
        # Checking whether the given file is a directory or not
        if os.path.isfile(file_path):
            if str(file_path).endswith('.o'):
                object_files.append(str(file))
            #try:
                # Printing the file pertaining to file_path
                #os.startfile(file_path, 'print')
            #except:
                # Catching if any error occurs and alerting the user
                #print(f'ALERT: {file} could not be printed! Please check\
                #the associated softwares, or the file type.')
        else:
            print(f'ALERT: {file} is not a file, so can not be printed!')
    #for o in object_files:
        #print(o)
    return object_files


if __name__ == '__main__':
    main()
