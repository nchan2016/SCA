# The purpose of this file is to extract json's from the nvd database

import requests

def main():
    for year in range(2002, 2021):
        url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-' + str(year) + '.json.zip'
        filename = str(year) + ".json.zip"
        print(url)
        r = requests.get(url, allow_redirects=True)
        open(filename, 'wb').write(r.content)
    return 0

if __name__ == "__main__":
    main()


