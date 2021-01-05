import angr
e = open("./yolomolo",'rb').read()
avoids = []
index=0
while True:
    index=e.find(b'\xB9\x00\x00\x00\x00',index+1)
    if(index==-1):
        break
    addr=0x400000+index
    avoids.append(hex(addr))

print(len(avoids))
print(avoids)