'FOR PYTHON 3'
import socket
import random

#Setting up
client = socket.socket()
#ip = input('Server IP: ')
ip = socket.gethostname()
port = 6000

try:
    client.connect((ip, port))
except:
    print('Connection Failed')
    raise SystemExit

#The encryption algorithm takes a random number and multiplies all of
#the charachter's ASCII values by it. It gets the key to the other side
#by sending it squared.
key = random.randrange(0, 2**12)#Picking encryption key
print('key', key)
def codify(string):#Encrypting and decrypting
    global key
    lofl = ''
    for l in string:
        lofl += str(ord(l)*key) + ' '
    return lofl.encode()
def decodify(byte):
    global key
    sofb = ''
    lofb = byte.decode('utf-8').split()
    for b in lofb:
        sofb += chr(int(eval(b)//key))
    return sofb

client.send(str(key**2).encode())#Multiplying key for security
client.send(codify('Ping'))
print(decodify(client.recv(4096)))
client.close()
