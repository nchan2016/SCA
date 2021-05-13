from sys import argv

def main():
    fname1 = argv[1] + ".txt"
    fname2 = argv[1] + "parsed" + ".txt"
    f1 = open(fname1, "r")
    f2 = open(fname2, "w")
    for line in f1:
        if 'CVE' in line:
            f2.write(line)


if __name__ == '__main__':
    main()
