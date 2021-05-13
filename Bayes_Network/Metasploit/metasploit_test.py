from pymetasploit3.msfrpc import MsfRpcClient

def main():
    client = MsfRpcClient('lzy5A7I6', port = 55552, ssl = True)
    shell = client.sessions.session(list(client.sessions.list.keys())[0])
    shell.write('search openssl')
    print(shell.read())
    shell.stop()

if __name__ == '__main__':
    main()
