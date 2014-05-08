'''
pyGCTInject.py 1.0
Written sometime in 2013 by dantarion@gmail.com
'''
import struct
f = open("./boot.dol","rb")
def readDol(f):
    f.seek(0)
    CODE_OFFSETS = []
    CODE_TARGETS = []
    CODE_SIZES = []
    DATA_OFFSETS = []
    DATA_TARGETS = []
    DATA_SIZES = []

    for i in range(0,7):
        CODE_OFFSETS.append(struct.unpack(">I",f.read(4))[0])
    for i in range(0,11):
        DATA_OFFSETS.append(struct.unpack(">I",f.read(4))[0])
    for i in range(0,7):
        CODE_TARGETS.append(struct.unpack(">I",f.read(4))[0])
    for i in range(0,11):
        DATA_TARGETS.append(struct.unpack(">I",f.read(4))[0])
    for i in range(0,7):
        CODE_SIZES.append(struct.unpack(">I",f.read(4))[0])
    for i in range(0,11):
        DATA_SIZES.append(struct.unpack(">I",f.read(4))[0])
        
    BSS_ADDR = struct.unpack(">I",f.read(4))[0]
    BSS_SIZE = struct.unpack(">I",f.read(4))[0]
    ENTRY = struct.unpack(">I",f.read(4))[0]

    print( hex(BSS_ADDR),hex(BSS_SIZE),hex(ENTRY))

    for i in range(0,7):
        print ("Text{0:2} File:{1:08X} SIZE{3:08X} MEM:{2:08X} - {4:08X}".\
              format(i,CODE_OFFSETS[i],CODE_TARGETS[i],CODE_SIZES[i],CODE_TARGETS[i]+CODE_SIZES[i]))
    for i in range(0,11):
        print ("Data{0:2} File:{1:08X} SIZE{3:08X} MEM:{2:08X} - {4:08X}".\
              format(i,DATA_OFFSETS[i],DATA_TARGETS[i],DATA_SIZES[i],DATA_TARGETS[i]+DATA_SIZES[i]))
readDol(f)
files = ["dolphinloader.bin","codehandler.bin","RSBE01.gct"]
pos = []
data = []
ptrs = [0x805a9320,0x80001800,0x80570000]
patches = []
lengths = []
f2 = open("boot_injected.dol","w+b")
f.seek(0)
f2.write(f.read())
vi_patch = bytearray.fromhex("7CE33B783887003438A7003838C7004C")
for i,filename in enumerate(files):
    print (filename)
    pos.append(f2.tell())
    curF = open(filename,"rb")
    
    f2.write(curF.read())
    lengths.append(curF.tell())
    for patch in patches:
        if patch[0] > ptrs[i] and patch[0] < ptrs[i]+lengths[i]:
            f2.seek(pos[i]+patch[0]-ptrs[i])
            print (hex(struct.unpack(">H",f2.read(2))[0]))
            f2.seek(pos[i]+patch[0]-ptrs[i])
            print ("patched",filename,"at",hex(f2.tell()),hex(patch[0]-ptrs[i]))
            f2.write(patch[1])
    curF.close()
f2.seek(0x3C)
for n in pos:
    f2.write(struct.pack(">I",n))
f2.seek(0xCC)
for n in lengths:
    f2.write(struct.pack(">I",n))
f2.seek(0x84)
for n in ptrs:
    f2.write(struct.pack(">I",n))

f2.seek(0xE0)
f2.write(struct.pack(">I",0x805a9320))
readDol(f2)
f2.close()



    
