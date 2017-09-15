'FOR PYTHON 3'
_version_ = '0.1'
import socket
import cmd

def encode_with_key(string, key):#Encrypting and decrypting
    list_of_numbers = ''
    for letter in string:
        list_of_numbers += str(ord(letter)*key) + ' '
    return list_of_numbers.encode()
def decode_with_key(byte, key):
    string_of_bytes = ''
    list_of_bytes = byte.decode('utf-8').split()
    for b in list_of_bytes:
        string_of_bytes += chr(int(eval(b)//key))
    return string_of_bytes

def main():
    #Setting up
    server = socket.socket()
    ip = '127.0.0.1'
    port = 6000

    server.bind((ip, port))
    server.listen(1)
    while True:#For multiple requests
        cnct, addr = server.accept()
        lenofmsg = int(cnct.recv(2).decode('utf-8'))
        key = round(int(round(int(cnct.recv(lenofmsg).decode('utf-8'))**(1/2))))#Sqrt of key
        print('key', key)
        toprint = decode_with_key(cnct.recv(4096), key)
        print(toprint)
        if toprint == 'Ping':
            cnct.send(encode_with_key('Pong', key))
        else:
            cnct.send(encode_with_key('Wrong!', key))
        cnct.close()

if __name__ == '__main__':
    main()
