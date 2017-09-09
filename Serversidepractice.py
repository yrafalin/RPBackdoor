'FOR PYTHON 3'
import socket

#Setting up
server = socket.socket()
ip = socket.gethostname()
port = 6000

server.bind((ip, port))

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

server.listen(1)
while True:#For multiple requests
    cnct, addr = server.accept()
    key = round(int(eval(cnct.recv(12).decode('utf-8')))**(1/2))#Sqrt of key
    print('key', key)
    toprint = decodify(cnct.recv(4096))
    print(toprint)
    if toprint == 'Ping':
        cnct.send(codify('Pong'))
    else:
        cnct.send(codify('Wrong!'))
    cnct.close()
