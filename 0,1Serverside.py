#FOR PYTHON 3
__version__ = '0.1'
import socket, cmd, getpass

# Things I learned:
# refactoring, versions, and '__main__'
# cmd module and class
# overriding class methods
# getpass.getuser()

def encode_with_key(string, key):#Encrypting and decrypting
    list_of_numbers = ''
    for letter in string:
        list_of_numbers += str(ord(letter)*key) + ' '
    return list_of_numbers.encode()

def decode_with_key(byte, key):
    string_of_bytes = ''
    list_of_bytes = (byte.decode('utf-8')).split()
    for b in list_of_bytes:
        string_of_bytes += chr(int(int(b)//key))
    return string_of_bytes

class recv_commands(cmd.Cmd):
    def __init__(self, key, connect):#VERY IMPORTANT lets me use key and socket outside main
        self.key = key
        self.connect = connect
    def do_exit(self, arg):
        return 0#To make continue_loop 0
    def do_loggedin(self, arg):
        message = encode_with_key(str(getpass.getuser()), self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)#Makes sure that lenofmsg is exactly 5 long by adding zeros
        print('loggedin', lenofmsg)
        self.connect.send(str(lenofmsg).encode())
        self.connect.send(message)
        return 1
    def do_WHOAMI(self, arg):
        message = encode_with_key(str(getpass.getuser()), self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('whoami', lenofmsg)
        self.connect.send(str(lenofmsg).encode())
        self.connect.send(message)
        return 1
    def do_killattack(self, arg):
        return 0

def main():
    #Setting up
    server = socket.socket()
    ip = '127.0.0.1'
    port = 6000
    server.bind((ip, port))
    server.listen(1)
    while True:#For multiple requests
        connect, addr = server.accept()
        lenofmsg = int(connect.recv(2).decode('utf-8'))
        key = round(int(round(int(connect.recv(lenofmsg).decode('utf-8'))**(1/2))))#Sqrt of key
        print('key', key)
        continue_loop = 1#Stopping the loop uses this var
        while continue_loop:
            lenofmsg_rtrnd = int(connect.recv(5).decode('utf-8'))#Standard protocol for my project
            msg_recvd = str(decode_with_key(connect.recv(lenofmsg_rtrnd), key))#Then receive real msg
            print('message recvd', msg_recvd)
            continue_loop = recv_commands(key, connect).onecmd(msg_recvd)
        print('Bye')
        connect.close()

if __name__ == '__main__':
    main()
