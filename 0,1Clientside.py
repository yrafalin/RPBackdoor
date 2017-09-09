'FOR PYTHON 3'
_version_ = '0.1'
import socket
import random
import cmd

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
        string_of_bytes += chr(int(eval(b)//key))
    return string_of_bytes

def main():
    #Setting up
    client = socket.socket()
    #ip = input('Server IP: ')
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
    client.send(encode_with_key('Ping', key))
    print(decode_with_key(client.recv(4096), key))
    client.close()

if __name__ == '__main__':
    main()
