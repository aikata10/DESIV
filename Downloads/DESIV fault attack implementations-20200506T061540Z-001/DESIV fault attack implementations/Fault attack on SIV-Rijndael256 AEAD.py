#!/usr/bin/env python
# coding: utf-8

from array import array

with open('final.txt', 'rb') as fp:
   data = [[int(num) for num in line.split()] for line in fp]
ot=[] #Taking tag T as input from the file final.txt which is written by the SIV-Rijndael's C code
ot.append([])
for i in range (4):
    pk=[]
    for j in range (8):
        pk.append(data[0][i*8+j])
    ot[0].append(pk)
fp.close()
with open('final_faulty.txt', 'rb') as fp:
   data = [[int(num) for num in line.split()] for line in fp]

ft=[] #Taking faulty tag T' as input from the file final_faulty.txt which is written by the SIV-Rijndael's C code
ft.append([])
for i in range (4):
    pk=[]
    for j in range (8):
        pk.append(data[0][i*8+j])
    ft[0].append(pk)
fp.close()
with open('key.txt', 'rb') as fp:
   data = [[int(num) for num in line.split()] for line in fp]

keys=[] #Taking last key as input from the file final.txt which is written by the SIV-Rijndael's C code
pk=()
for i in range (8):
    for j in range (4):
        pk=pk+((data[0][i*4+j]),)
keys.append(pk)
fp.close()

#Inverse s-box
ISB = [ 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d ]

def inSbox(x):  #Inverse s-box function
    return (ISB[x]);

def galoisMult(a, b):  #Function for multiplication in Galoi field
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

#s-box
sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,  
        0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
        0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
        0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
        0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
        0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
        0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
        0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
        0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
        0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
        0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
        0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
        0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
        0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
        0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
        0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
        0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
        0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
        0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
        0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
        0x54, 0xbb, 0x16]

#Function to clone a key or message
def cloning (list1):
    list3 = []
    for l in list1:
        list2 = l[:]
        list3.append(list2)
    return list3

#Function to print the value of a key or a message
def printKeyOrMessage (key):
    for i in range(len(key)):
        for j in range(len(key[i])):
            print ("%02x" %key[i][j]," ",end="")
        print ()
        
#Function to perform inverseSubBytes operation
def inSubBytes (message):
    tempMessage = cloning(message)
    for i in tempMessage:
        for j in range(len(i)):
            i[j] = inSbox(i[j])
    return tempMessage

#Function to perform inverseShiftRows operation
def inShiftRows (message):
    tempMessage = cloning(message)
    for i in range(len(message)):
        if (i==0 or i==1):
            shift = i        
        else:
            shift = i+1
        for j in range(len(message[i])):
            tempMessage[i][(j+shift)%8] = message[i][j] 
    return tempMessage

#Function to perform inverseMixColumns operation
def inMixColumns (message):
    matrix = [[0x0e,0x0b,0x0d,0x09],
              [0x09,0x0e,0x0b,0x0d],
              [0x0d,0x09,0x0e,0x0b],
              [0x0b,0x0d,0x09,0x0e]]
    tempMessage = cloning(message)
    for i in range(4):
        for j in range(len(message[i])):
            temp = 0
            for k in range(4):
                temp ^= galoisMult(matrix[i][k],message[k][j])
            tempMessage[i][j] = temp
    return tempMessage

#Function to perform subBytes operation
def subBytes (message):
    tempMessage = cloning(message)
    for i in tempMessage:
        for j in range(len(i)):
            i[j] = sBox(i[j])
    return tempMessage

#Function to perform shiftRows operation
def shiftRows (message):
    tempMessage = cloning(message)
    for i in range(len(message)):
        if (i==0 or i==1):
            shift = i        
        else:
            shift = i+1
        for j in range(len(message[i])):
            tempMessage[i][(j-shift)%8] = message[i][j] 
    return tempMessage

#Function to perform mixColumns operation
def mixColumns (message):
    matrix = [[0x02,0x03,0x01,0x01],
              [0x01,0x02,0x03,0x01],
              [0x01,0x01,0x02,0x03],
              [0x03,0x01,0x01,0x02]]
    tempMessage = cloning(message)
    for i in range(4):
        for j in range(len(message[i])):
            temp = 0
            for k in range(4):
                temp ^= galoisMult(matrix[i][k],message[k][j])
            tempMessage[i][j] = temp
    return tempMessage

#Function to calculate the difference of two messages
def XOR (message1,message2):
    diff = []
    for i in range(len(message1)):
        line = []
        for j in range(len(message1[i])):
            line.append(message1[i][j]^message2[i][j])
        diff.append(line)
    return diff

#Function to get the previous round key from the current round key
def getPreviousKey(key):
    prevKey=[]
    
    t7=[]
    t7.append(key[0][2]^key[0][3])
    t7.append(key[1][2]^key[1][3])
    t7.append(key[2][2]^key[2][3])
    t7.append(key[3][2]^key[3][3])
    
    t6=[]
    t6.append(key[0][2]^key[0][1])
    t6.append(key[1][2]^key[1][1])
    t6.append(key[2][2]^key[2][1])
    t6.append(key[3][2]^key[3][1])
    
    t5=[]
    t5.append(key[0][0]^key[0][1])
    t5.append(key[1][0]^key[1][1])
    t5.append(key[2][0]^key[2][1])
    t5.append(key[3][0]^key[3][1])
    
    t4=[]
    t4.append(key[0][0]^0xef^sbox[t7[1]])
    t4.append(key[1][0]^sbox[t7[2]])
    t4.append(key[2][0]^sbox[t7[3]])
    t4.append(key[3][0]^sbox[t7[0]])

    t3=[]
    t3.append(t7[0]^t6[0])
    t3.append(t7[1]^t6[1])
    t3.append(t7[2]^t6[2])
    t3.append(t7[3]^t6[3])
    
    t2=[]
    t2.append(t6[0]^t5[0])
    t2.append(t6[1]^t5[1])
    t2.append(t6[2]^t5[2])
    t2.append(t6[3]^t5[3])
    
    t1=[]
    t1.append(t5[0]^t4[0])
    t1.append(t5[1]^t4[1])
    t1.append(t5[2]^t4[2])
    t1.append(t5[3]^t4[3])
    
    t0=[]
    t0.append(t4[0]^0xfa^sbox[t3[1]])
    t0.append(t4[1]^sbox[t3[2]])
    t0.append(t4[2]^sbox[t3[3]])
    t0.append(t4[3]^sbox[t3[0]])
    
    for i in range (4):
        tt0=[]
        tt0.append(t0[i])
        tt0.append(t1[i])
        tt0.append(t2[i])
        tt0.append(t3[i])
        tt0.append(t4[i])
        tt0.append(t5[i])
        tt0.append(t6[i])
        tt0.append(t7[i])
        prevKey.append(tt0)    
    return prevKey

#Function to change the format of the key from tuple to matrix
def getLastKey(i):
    lastKey = []
    for j in range(4):
        t = []
        if j<2:
            for k in range(8):
                t.append(i[4*((k+j)%8)+j])
        else:
            for k in range(8):
                t.append(i[4*((k+j+1)%8)+j])
        lastKey.append(t)
    return lastKey

#Function to match the pattern of the differential state after 12th round MixColumn
def isPatternFollowed(diff, diagNo):
    temp=0
    c0=diagNo
    c1=(diagNo+1)%8
    c2=(diagNo+2)%8
    c3=(diagNo+3)%8
    c4=(diagNo+4)%8
    c5=(diagNo+5)%8
    c6=(diagNo+6)%8
    c7=(diagNo+7)%8
    zeroValue = 0;
    for i in range(4):
        zeroValue += diff[i][c1]
        zeroValue += diff[i][c2]
        zeroValue += diff[i][c3]
        zeroValue += diff[i][c6]
    if(zeroValue==0):
        if(diff[1][c0]==diff[2][c0] and diff[0][c0]==galoisMult(diff[1][c0],2) and diff[3][c0]==galoisMult(diff[1][c0],3)):
            if(diff[0][c4]==diff[1][c4] and diff[3][c4]==galoisMult(diff[0][c4],2) and diff[2][c4]==galoisMult(diff[0][c4],3)):
                if(diff[0][c5]==diff[3][c5] and diff[2][c5]==galoisMult(diff[0][c5],2) and diff[1][c5]==galoisMult(diff[0][c5],3)):
                    if(diff[2][c7]==diff[3][c7] and diff[1][c7]==galoisMult(diff[2][c7],2) and diff[0][c7]==galoisMult(diff[2][c7],3)):
                        temp=1
    return temp

#Function to change the format of the key from matrix to tuple
def convertToTuple(k):
    t = (k[0][0],k[1][7],k[2][5],k[3][4],
        k[0][1],k[1][0],k[2][6],k[3][5],
        k[0][2],k[1][1],k[2][7],k[3][6],
        k[0][3],k[1][2],k[2][0],k[3][7],
        k[0][4],k[1][3],k[2][1],k[3][0],
        k[0][5],k[1][4],k[2][2],k[3][1],
        k[0][6],k[1][5],k[2][3],k[3][2],
        k[0][7],k[1][6],k[2][4],k[3][3])
    return t

def diag0(fault): #Function to return the keyspace if the fault is done in 0th  Diagonal
    # Column 2 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][2] ^ i) ^ inSbox(ft[fault][0][2] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][6] ^ j) ^ inSbox(ft[fault][3][6] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)
    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][2] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][2] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][1] ^ j) ^ inSbox(ft[fault][1][1] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][2] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][2] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][7] ^ j) ^ inSbox(ft[fault][2][7] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C2 = list(k0123)

    # Column 6 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][6] ^ i) ^ inSbox(ft[fault][0][6] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][5] ^ j) ^ inSbox(ft[fault][1][5] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][6] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][6] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][3] ^ j) ^ inSbox(ft[fault][2][3] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][6] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][6] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][2] ^ j) ^ inSbox(ft[fault][3][2] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C6 = list(k0123)
   
    # Column 1 --------------------------------------------
    k23=set()
    for i in C2:
        for j in C6:
            a2 = i[2]^j[2]
            a3 = i[3]^j[3]
            k23.add((a2,a3))
    k23_t = list(k23)
    k123=set()
    k0123=set()
    for i in range (256):  
        for j in k23_t:
                lhs = inSbox(ot[fault][1][0] ^ i) ^ inSbox(ft[fault][1][0] ^ i)^inSbox(ot[fault][3][5] ^ j[1]) ^ inSbox(ft[fault][3][5] ^ j[1]) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][2][6] ^ j[0]) ^ inSbox(ft[fault][2][6] ^ j[0])
                if(lhs==rhs):
                    t=(i,j[0],j[1])
                    k123.add(t)
    k123_t=list(k123)
    for i in range (len(k123_t)):
        for j in range (256):
            a2=k123_t[i][1]
            a3=k123_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][2][6]^a2)^inSbox(ft[fault][2][6]^a2),3)^inSbox(ot[fault][3][5]^a3)^inSbox(ft[fault][3][5]^a3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][1]^j)^inSbox(ft[fault][0][1]^j),7)
            if lhs==rhs:
                t=(j,k123_t[i][0],k123_t[i][1],k123_t[i][2])
                k0123.add(t)
    C1 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C126 = set()
    for i in C2:
        for j in C6:
            a2 = i[2]^j[2]
            a3 = i[3]^j[3]
            for k in C1:
                if(k[2]==a2 and k[3]==a3):
                    t = (k[0],k[1],k[2],k[3],i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3])
                    C126.add(t)
    
    # Column 5 --------------------------------------------
    k01=set()
    for i in C126:
        a0 = i[4]^i[8]
        a11 = sbox[i[10]]^i[1]
        a12 = i[5]^i[9]
        if(a11==a12):
            k01.add((a0,a11))
    k01_t = list(k01)
    k012 = set()
    for i in range (256):   
        for j in k01_t:
                lhs = inSbox(ot[fault][0][5] ^ j[0]) ^ inSbox(ft[fault][0][5] ^ j[0]) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][1][4] ^ j[1]) ^ inSbox(ft[fault][1][4] ^ j[1]),5)^galoisMult(inSbox(ot[fault][2][2] ^ i) ^ inSbox(ft[fault][2][2] ^ i),7)
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a2=k012_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][0][5]^a0)^inSbox(ft[fault][0][5]^a0),7)^galoisMult(inSbox(ot[fault][3][1]^j)^inSbox(ft[fault][3][1]^j),5) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][2][2]^a2)^inSbox(ft[fault][2][2]^a2)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C5 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C1256 = set()
    for i in C126:
        a0 = i[4]^i[8]
        a11 = sbox[i[10]]^i[1]
        a12 = i[5]^i[9]
        if(a11==a12):
            for j in C5:
                if(j[0]==a0 and j[1]==a11):
                    t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],j[0],j[1],j[2],j[3],i[8],i[9],i[10],i[11])
                    C1256.add(t)
    
    # Column 0 --------------------------------------------
    k23=set()
    for i in C1256:
        a2 = i[10]^i[2]
        a3 = i[11]^i[3]
        k23.add((a2,a3))
    k23_t = list(k23)
    k023=set()
    k0123=set()
    for i in range (256):  
        for j in k23_t:
            lhs=inSbox(ot[fault][2][5]^j[0])^inSbox(ft[fault][2][5]^j[0])^inSbox(ot[fault][3][4]^j[1])^inSbox(ft[fault][3][4]^j[1]) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][0][0]^i)^inSbox(ft[fault][0][0]^i)                
            if(lhs==rhs):
                t=(i,j[0],j[1])
                k023.add(t)
    k023_t=list(k023)
    for i in range (len(k023_t)):
        for j in range (256):
            a0=k023_t[i][0]
            a3=k023_t[i][2]
            lhs = galoisMult(inSbox(ot[fault][1][7] ^ j) ^ inSbox(ft[fault][1][7] ^ j),7)^galoisMult(inSbox(ot[fault][3][4] ^a3) ^ inSbox(ft[fault][3][4] ^ a3),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][0][0]^a0)^inSbox(ft[fault][0][0]^a0)
            if lhs==rhs:
                t=(k023_t[i][0],j,k023_t[i][1],k023_t[i][2])    
                k0123.add(t)
    C0 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C01256 = set()
    for i in C1256:
        a2 = i[10]^i[2]
        a3 = i[11]^i[3]
        for j in C0:
            if(j[2]==a2 and j[3]==a3):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15])
                C01256.add(t)
    
    # Column 4 (k04, k13) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C012456_t=set()
    for i in C01256:
        a0=i[4]^i[12]
        a1=inSbox(a0 ^ i[0] ^ 0xc5)
        t=(i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],a0,a1,i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19])
        C012456_t.add(t)
    
    # Column 3 ------------------------------------------------------
    k1 = set()
    for i in C012456_t:
        a1 = i[1]^i[19]^i[13]
        k1.add(a1)
    k1_t = list(k1)
    k013=set()
    for i in k1_t:
        for j in range (256):
            for k in range (256):
                lhs=galoisMult(inSbox(ot[fault][0][3]^j)^inSbox(ft[fault][0][3]^j),5)^galoisMult(inSbox(ot[fault][1][2]^i)^inSbox(ft[fault][1][2]^i),7) #using byte-inter-relation equations
                rhs=inSbox(ot[fault][3][7]^k)^inSbox(ft[fault][3][7]^k)
                if(lhs==rhs):
                    t=(j,i,k)
                    k013.add(t)
    k013_t = list(k013)
    k0123=set()
    for i in k013_t:
        a0 = i[0]
        a3 = i[2]
        for j in range (256):
            lhs = inSbox(ot[fault][0][3] ^ a0) ^ inSbox(ft[fault][0][3] ^ a0) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][0] ^ j) ^ inSbox(ft[fault][2][0] ^ j),7)^galoisMult(inSbox(ot[fault][3][7] ^ a3) ^ inSbox(ft[fault][3][7] ^ a3),4)
            if(lhs==rhs):
                t=(i[0],i[1],j,i[2])
                k0123.add(t)
    C3 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0123456_t = set()
    for i in C012456_t:
        a1 = i[1]^i[19]^i[13]
        for j in C3:
            if(j[1]==a1 ):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],j[0],j[1],j[2],j[3],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21])
                C0123456_t.add(t)
    
    # Column 7 ------------------------------------------------------
    k0123 = set()
    for i in C0123456_t:
        a0 = i[22]^i[12]
        a1 = i[23]^i[13]
        a3 = i[11]^i[15]
        a2 = sbox[a3]^i[14]
        k0123.add((a0,a1,a2,a3))
    k0123_t = set()
    for i in k0123:
        lhs = inSbox(ot[fault][0][7] ^ i[0]) ^ inSbox(ft[fault][0][7] ^ i[0]) #using byte-inter-relation equations
        rhs = inSbox(ot[fault][1][6] ^ i[1]) ^ inSbox(ft[fault][1][6] ^ i[1])^inSbox(ot[fault][3][3] ^ i[3]) ^ inSbox(ft[fault][3][3] ^ i[3])
        if(lhs==rhs):
            lhs1 = galoisMult(inSbox(ot[fault][3][3] ^ i[3]) ^ inSbox(ft[fault][3][3] ^ i[3]),3) #using byte-inter-relation equations
            rhs1 = galoisMult(inSbox(ot[fault][1][6] ^ i[1]) ^ inSbox(ft[fault][1][6] ^ i[1]),2)^galoisMult(inSbox(ot[fault][2][4] ^ i[2]) ^ inSbox(ft[fault][2][4] ^ i[2]),7)
            if(lhs1==rhs1):
                k0123_t.add(i)
    C7=list(k0123_t)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t = set()
    for i in C0123456_t:
        a0 = i[22]^i[12]
        a1 = i[23]^i[13]
        a3 = i[11]^i[15]
        a2 = sbox[a3]^i[14]
        for j in C7:
            if(j[3]==a3 and j[2]==a2 and j[1]==a1 and j[0]==a0):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],j[0],j[1],j[2],j[3])
                C01234567_t.add(t)
    
    # Column 4 (k21, k30) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t:
        a2=i[28]^i[2]
        a3=sbox[i[12]]^i[3]
        t=(i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],a2,a3,i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27],i[28],i[29])
        C01234567.add(t)
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,0)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14

def diag1(fault): #Function to return the keyspace if the fault is done in 1st Diagonal
    
    # Column 3 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][3] ^ i) ^ inSbox(ft[fault][0][3] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][7] ^ j) ^ inSbox(ft[fault][3][7] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)
    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][3] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][3] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][2] ^ j) ^ inSbox(ft[fault][1][2] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][3] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][3] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][0] ^ j) ^ inSbox(ft[fault][2][0] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C3 = list(k0123)

    # Column 7 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][7] ^ i) ^ inSbox(ft[fault][0][7] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][6] ^ j) ^ inSbox(ft[fault][1][6] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][7] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][7] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][4] ^ j) ^ inSbox(ft[fault][2][4] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][7] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][7] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][3] ^ j) ^ inSbox(ft[fault][3][3] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C7 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C37 = set()
    for i in C7:
        a2 = sbox[i[3]]^i[2]
        for j in C3:
            if(j[2]==a2):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3])
                C37.add(t)

    # Column 6 --------------------------------------------
    k01=set()
    for i in C37:
        a0 = i[0]^i[4]
        a1 = i[1]^i[5]
        k01.add((a0,a1))
    k01_t = list(k01)
    k012 = set()
    for i in range (256):   
        for j in k01_t:
                lhs = inSbox(ot[fault][0][6] ^ j[0]) ^ inSbox(ft[fault][0][6] ^ j[0]) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][1][5] ^ j[1]) ^ inSbox(ft[fault][1][5] ^ j[1]),5)^galoisMult(inSbox(ot[fault][2][3] ^ i) ^ inSbox(ft[fault][2][3] ^ i),7)
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a2=k012_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][0][6]^a0)^inSbox(ft[fault][0][6]^a0),7)^galoisMult(inSbox(ot[fault][3][2]^j)^inSbox(ft[fault][3][2]^j),5) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][2][3]^a2)^inSbox(ft[fault][2][3]^a2)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C6 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C367 = set()
    for i in C37:
        a0 = i[0]^i[4]
        a1 = i[1]^i[5]
        for j in C6:
            if(j[0]==a0 and j[1]==a1):
                t = (i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3],i[4],i[5],i[6],i[7])
                C367.add(t)

    # Column 2 --------------------------------------------
    k3 = set()
    for i in C367:
        k3.add(i[3]^i[11])
    k3_t = list(k3)
    k123=set()
    k0123=set()
    for i in range (256):  
        for j in range(256):
            for k in k3_t:
                lhs = inSbox(ot[fault][1][1] ^ i) ^ inSbox(ft[fault][1][1] ^ i)^inSbox(ot[fault][3][6] ^ k) ^ inSbox(ft[fault][3][6] ^ k) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][2][7] ^ j) ^ inSbox(ft[fault][2][7] ^ j)
                if(lhs==rhs):
                    t=(i,j,k)
                    k123.add(t)
    k123_t=list(k123)
    for i in range (len(k123_t)):
        for j in range (256):
            a2=k123_t[i][1]
            a3=k123_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][2][7]^a2)^inSbox(ft[fault][2][7]^a2),3)^inSbox(ot[fault][3][6]^a3)^inSbox(ft[fault][3][6]^a3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][2]^j)^inSbox(ft[fault][0][2]^j),7)
            if lhs==rhs:
                t=(j,k123_t[i][0],k123_t[i][1],k123_t[i][2])
                k0123.add(t)
    C2 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C2367 = set()
    for i in C367:
        a3 = i[3]^i[11]
        for j in C2:
            if(j[3]==a3):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11])
                C2367.add(t)
    
    # Column 5 (k05, k14) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C23567_t=set()
    for i in C2367:
        a0=i[0]^i[8]
        a1=i[1]^i[9]
        t=(i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],a0,a1,i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15])
        C23567_t.add(t)

    # Column 1 --------------------------------------------
    k123 = set()
    for i in C23567_t:
        a1 = sbox[i[12]]^i[9]
        a2 = i[12]^i[2]
        a3 = i[13]^i[3]
        k123.add((a1,a2,a3))
    k123_t = list(k123)
    k0123_t2=set()
    k0123=set()
    for i in range (256):  
        for j in k123_t:
            lhs=inSbox(ot[fault][2][6]^j[1])^inSbox(ft[fault][2][6]^j[1])^inSbox(ot[fault][3][5]^j[2])^inSbox(ft[fault][3][5]^j[2]) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][0][1]^i)^inSbox(ft[fault][0][1]^i)                
            if(lhs==rhs):
                t=(i,j[0],j[1],j[2])
                k0123_t2.add(t)
    k0123_t = list(k0123_t2)
    for i in range(len(k0123_t)):
        a0 = k0123_t[i][0]
        a1 = k0123_t[i][1]
        a3 = k0123_t[i][3]
        lhs = galoisMult(inSbox(ot[fault][1][0] ^ a1) ^ inSbox(ft[fault][1][0] ^ a1),7)^galoisMult(inSbox(ot[fault][3][5] ^a3) ^ inSbox(ft[fault][3][5] ^ a3),3) #using byte-inter-relation equations
        rhs = inSbox(ot[fault][0][1]^a0)^inSbox(ft[fault][0][1]^a0)
        if lhs==rhs:
            t=(k0123_t[i][0],k0123_t[i][1],k0123_t[i][2],k0123_t[i][3])    
            k0123.add(t)
    C1 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C123567_t = set()
    for i in C23567_t:
        a1 = sbox[i[12]]^i[9]
        a2 = i[12]^i[2]
        a3 = i[13]^i[3]
        for j in C1:
            if(j[1]==a1 and j[2]==a2 and j[3]==a3):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17])
                C123567_t.add(t)

    # Column 4 -------------------------------------------------------
    k0 = set()
    for i in C123567_t:
        a0 = i[0]^i[12]
        k0.add(a0)
    k0_t = list(k0)
    k013=set()
    for i in k0_t:
        for j in range (256):
            for k in range (256):
                lhs=galoisMult(inSbox(ot[fault][0][4]^i)^inSbox(ft[fault][0][4]^i),5)^galoisMult(inSbox(ot[fault][1][3]^j)^inSbox(ft[fault][1][3]^j),7) #using byte-inter-relation equations
                rhs=inSbox(ot[fault][3][0]^k)^inSbox(ft[fault][3][0]^k)
                if(lhs==rhs):
                    t=(i,j,k)
                    k013.add(t)
    k013_t = list(k013)
    k0123=set()
    for i in k013_t:
        a0 = i[0]
        a3 = i[2]
        for j in range (256):
            lhs = inSbox(ot[fault][0][4] ^ a0) ^ inSbox(ft[fault][0][4] ^ a0) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][1] ^ j) ^ inSbox(ft[fault][2][1] ^ j),7)^galoisMult(inSbox(ot[fault][3][0] ^ a3) ^ inSbox(ft[fault][3][0] ^ a3),4)
            if(lhs==rhs):
                t=(i[0],i[1],j,i[2])
                k0123.add(t)
    C4 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C1234567_t = set()
    for i in C123567_t:
        a0 = i[0]^i[12]
        for j in C4:
            if(j[0]==a0 ):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],j[0],j[1],j[2],j[3],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21])
                C1234567_t.add(t)

    # Column 0 -------------------------------------------------------
    k0123 = set()
    for i in C1234567_t:
        a0 = sbox[i[13]]^0xc5^i[12]
        a1 = i[13]^i[23]
        a2 = i[14]^i[24]
        a3 = sbox[i[8]]^i[15]
        k0123.add((a0,a1,a2,a3))
    k0123_t = set()
    for i in k0123: 
        lhs=inSbox(ot[fault][0][0]^i[0])^inSbox(ft[fault][0][0]^i[0])^inSbox(ot[fault][3][4]^i[3])^inSbox(ft[fault][3][4]^i[3]) #using byte-inter-relation equations
        rhs=inSbox(ot[fault][1][7]^i[1])^inSbox(ft[fault][1][7]^i[1])
        if(lhs==rhs):
            lhs1=galoisMult(inSbox(ot[fault][1][7]^i[1])^inSbox(ft[fault][1][7]^i[1]),2)^galoisMult(inSbox(ot[fault][3][4]^i[3])^inSbox(ft[fault][3][4]^i[3]),3) #using byte-inter-relation equations
            rhs1=galoisMult(inSbox(ot[fault][2][5]^i[2])^inSbox(ft[fault][2][5]^i[2]),7)
            if(lhs1==rhs1):
                k0123_t.add(i)
    C0 = list(k0123_t)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t = set()
    for i in C1234567_t:
        a0 = sbox[i[13]]^0xc5^i[12]
        a1 = i[13]^i[23]
        a2 = i[14]^i[24]
        a3 = sbox[i[8]]^i[15]
        for j in C0:
            if(j[0]==a0 and j[1]==a1 and j[2]==a2 and j[3]==a3):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25])
                C01234567_t.add(t) 

    # Column 5 (k22, k31) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t:
        a2=i[2]^i[6]
        a3=i[3]^i[7]
        t=(i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],a2,a3,i[22],i[23],i[24],i[25],i[26],i[27],i[28],i[29])
        C01234567.add(t)
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,1)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14

def diag2(fault): #Function to return the keyspace if the fault is done in 2nd  Diagonal
    
# Column 4 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][4] ^ i) ^ inSbox(ft[fault][0][4] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][0] ^ j) ^ inSbox(ft[fault][3][0] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)

    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][4] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][4] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][3] ^ j) ^ inSbox(ft[fault][1][3] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][4] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][4] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][1] ^ j) ^ inSbox(ft[fault][2][1] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C4= list(k0123)

    # Column 0 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][0] ^ i) ^ inSbox(ft[fault][0][0] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][7] ^ j) ^ inSbox(ft[fault][1][7] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][0] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][0] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][5] ^ j) ^ inSbox(ft[fault][2][5] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][0] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][0] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][4] ^ j) ^ inSbox(ft[fault][3][4] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C0 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C04=set()
    for i in C0:
        for j in C4:
            if(j[1]==inSbox(0xc5^i[0]^j[0])):
                C04.add((i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3]))

    # Column 7 --------------------------------------------
    k12=set()
    for i in C04:
        a1=i[1]^i[5]
        a2=i[2]^i[6]
        k12.add((a1,a2))
    k12_t=list(k12)
    k012=set()
    for i in range (len(k12_t)):
        for j in range (256):
            a1=k12_t[i][0]
            a2=k12_t[i][1]
            lhs = inSbox(ot[fault][0][7] ^ j) ^ inSbox(ft[fault][0][7] ^ j) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][6] ^ a1) ^ inSbox(ft[fault][1][6] ^ a1),5)^galoisMult(inSbox(ot[fault][2][4] ^ a2) ^ inSbox(ft[fault][2][4] ^ a2),7)
            if lhs==rhs:
                k012.add((j,a1,a2))
    k0123=set()
    for i in k012:   
        for j in range (256):
                lhs=galoisMult(inSbox(ot[fault][0][7]^i[0])^inSbox(ft[fault][0][7]^i[0]),7)^galoisMult(inSbox(ot[fault][3][3]^j)^inSbox(ft[fault][3][3]^j),5) #using byte-inter-relation equations
                rhs=inSbox(ot[fault][2][4]^i[2])^inSbox(ft[fault][2][4]^i[2])
                if(lhs==rhs):
                    k0123.add((i[0],i[1],i[2],j))
    C7=list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C047=set()
    for i in C04:
        for j in C7:
            a1=i[1]^i[5]
            a2=i[2]^i[6]
            if(j[1]==a1 and j[2]==a2):
                C047.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],j[0],j[1],j[2],j[3]))

    # Column 3 --------------------------------------------    
    k02=set()
    for i in C047:
        a0=inSbox(i[3]^i[7])
        a2=sbox[i[11]]^i[10]
        k02.add((a0,a2))

    k012=set()
    k0123=set()
    for i in range (256):  
        for j in k02:
                lhs = galoisMult(inSbox(ot[fault][0][3] ^ j[0]) ^ inSbox(ft[fault][0][3] ^ j[0]),7)^inSbox(ot[fault][1][2] ^ i) ^ inSbox(ft[fault][1][2] ^ i) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][2][0] ^ j[1]) ^ inSbox(ft[fault][2][0] ^ j[1]),2)
                if(lhs==rhs):
                    t=(j[0],i,j[1])
                    k012.add(t)
    k012_t=list(k012)
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a1=k012_t[i][1]
            lhs=galoisMult(inSbox(ot[fault][3][7]^j)^inSbox(ft[fault][3][7]^j),2)^galoisMult(inSbox(ot[fault][1][2]^a1)^inSbox(ft[fault][1][2]^a1),3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][3]^a0)^inSbox(ft[fault][0][3]^a0),7)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C3 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0347 = set()
    for i in C047:
        for j in C3:
            a0=inSbox(i[3]^i[7])
            a2=sbox[i[11]]^i[10]
            if(j[0]==a0 and j[2]==a2):
                    t = (i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11])
                    C0347.add(t)

    # Column 2 --------------------------------------------  
    k3=set()
    for i in C0347:
        k3.add(i[7]^i[15])
    k013=set()
    k0123=set()
    for i in range (256):  
        for j in range (256):
            for k in k3:
                lhs = galoisMult(inSbox(ot[fault][1][1] ^ j) ^ inSbox(ft[fault][1][1] ^ j),7)^galoisMult(inSbox(ot[fault][3][6] ^k) ^ inSbox(ft[fault][3][6] ^ k),3) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][0][2] ^ i) ^ inSbox(ft[fault][0][2] ^ i)
                if(lhs==rhs):
                    t=(i,j,k)
                    k013.add(t)
    k013_t=list(k013)
    for i in range (len(k013_t)):
        for j in range (256):
            a0=k013_t[i][0]
            a3=k013_t[i][2]
            lhs=inSbox(ot[fault][2][7]^j)^inSbox(ft[fault][2][7]^j)^inSbox(ot[fault][3][6]^a3)^inSbox(ft[fault][3][6]^a3) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][0][2]^a0)^inSbox(ft[fault][0][2]^a0)
            if lhs==rhs:
                t=(k013_t[i][0],k013_t[i][1],j,k013_t[i][2])
                k0123.add(t)
    C2 = list(k0123)
    C02347 = set()
    for i in C0347:
        a3=i[7]^i[15]
        for j in C2:
            if(j[3]==a3):
                t = (i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15])
                C02347.add(t)

    # Column 6 (k06,k15) -------------------------------------------- 
    # Merging the keyspaces using  key-schedule equations
    C023467_t=set()
    for i in C02347:
        a0=i[8]^i[16]
        a1=i[9]^i[17]
        C023467_t.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],a0,a1,i[16],i[17],i[18],i[19]))

    # Column 5 -------------------------------------------- 
    k01=set()
    for i in C023467_t:
        a0=i[16]^i[4]
        a1=i[5]^i[17]
        k01.add((a0,a1))
    k013=set()    
    for i in k01:
        for j in range (256):
            lhs=galoisMult(inSbox(ot[fault][0][5]^i[0])^inSbox(ft[fault][0][5]^i[0]),5)^galoisMult(inSbox(ot[fault][1][4]^i[1])^inSbox(ft[fault][1][4]^i[1]),7) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][3][1]^j)^inSbox(ft[fault][3][1]^j)
            if(lhs==rhs):
                k013.add((i[0],i[1],j))
    k0123=set()
    for i in k013:
        for j in range(256):
            lhs = inSbox(ot[fault][0][5] ^ i[0]) ^ inSbox(ft[fault][0][5] ^ i[0])
            rhs = galoisMult(inSbox(ot[fault][2][2] ^ j) ^ inSbox(ft[fault][2][2] ^ j),7)^galoisMult(inSbox(ot[fault][3][1] ^ i[2]) ^ inSbox(ft[fault][3][1] ^ i[2]),4) #using byte-inter-relation equations
            if(lhs==rhs):
                k0123.add((i[0],i[1],j,i[2]))
    C5=list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0234567_t=set()
    for i in C023467_t:
        a0=i[16]^i[4]
        a1=i[5]^i[17]
        for j in C5:
            if(j[0]==a0 and j[1]==a1):
                C0234567_t.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],j[0],j[1],j[2],j[3],i[16],i[17],i[18],i[19],i[20],i[21]))

    # Column 1 --------------------------------------------    
    k023=set()
    for i in C0234567_t:
        a0=i[12]^i[16]
        a2=i[2]^i[18]
        a3=i[3]^i[19]
        k023.add((a0,a2,a3))

    k0123_t=set()
    for i in k023:
        for j in range (256):
            lhs = inSbox(ot[fault][0][1] ^ i[0]) ^ inSbox(ft[fault][0][1] ^ i[0]) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][0] ^ j) ^ inSbox(ft[fault][1][0] ^ j)^inSbox(ot[fault][3][5] ^ i[2]) ^ inSbox(ft[fault][3][5] ^ i[2])
            if(lhs==rhs):
                lhs1 = galoisMult(inSbox(ot[fault][3][5] ^ i[2]) ^ inSbox(ft[fault][3][5] ^ i[2]),3) #using byte-inter-relation equations
                rhs1 = galoisMult(inSbox(ot[fault][1][0] ^ j) ^ inSbox(ft[fault][1][0] ^ j),2)^galoisMult(inSbox(ot[fault][2][6] ^ i[1]) ^ inSbox(ft[fault][2][6] ^ i[1]),7)
                if(lhs1==rhs1):
                    k0123_t.add((i[0],j,i[1],i[2]))
    C1=list(k0123_t)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t = set()
    for i in C0234567_t:
            for j in C1:
                a0=i[12]^i[16]
                a2=i[2]^i[18]
                a3=i[3]^i[19]
                if(j[3]==a3 and j[2]==a2 and j[0]==a0):
                    C01234567_t.add((i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25]))
    
    # Column 6 (k23,k32) --------------------------------------------     
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t:
        a2_1=i[6]^i[10]
        a3=i[7]^i[11]
        a2_2=inSbox(i[5]^i[21])
        if(a2_1==a2_2):
            C01234567.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],a2_1,a3,i[26],i[27],i[28],i[29]))
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,2)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14

def diag3(fault): #Function to return the keyspace if the fault is done in 3rd  Diagonal
    
    # Column 5 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][5] ^ i) ^ inSbox(ft[fault][0][5] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][1] ^ j) ^ inSbox(ft[fault][3][1] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)

    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][5] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][5] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][4] ^ j) ^ inSbox(ft[fault][1][4] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][5] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][5] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][2] ^ j) ^ inSbox(ft[fault][2][2] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C5= list(k0123)

    # Column 1 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][1] ^ i) ^ inSbox(ft[fault][0][1] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][0] ^ j) ^ inSbox(ft[fault][1][0] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][1] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][1] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][6] ^ j) ^ inSbox(ft[fault][2][6] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][1] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][1] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][5] ^ j) ^ inSbox(ft[fault][3][5] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C1 = list(k0123)

    #Column 0 --------------------------------------------
    k23=set()
    for i in C1:
        for j in C5:
            a2=i[2]^j[2]
            a3=i[3]^j[3]
            k23.add((a2,a3))

    k023=set()
    for i in k23:   
        for j in range (256):
                lhs=galoisMult(inSbox(ot[fault][0][0]^j)^inSbox(ft[fault][0][0]^j),7)^galoisMult(inSbox(ot[fault][3][4]^i[1])^inSbox(ft[fault][3][4]^i[1]),5) #using byte-inter-relation equations
                rhs=inSbox(ot[fault][2][5]^i[0])^inSbox(ft[fault][2][5]^i[0])
                if(lhs==rhs):
                    t=(j,i[0],i[1])
                    k023.add(t)
    k023_t=list(k023)
    k0123=set()
    for i in range (len(k023_t)):
        for j in range (256):
            a0=k023_t[i][0]
            a2=k023_t[i][1]
            lhs = inSbox(ot[fault][0][0] ^ a0) ^ inSbox(ft[fault][0][0] ^ a0) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][7] ^ j) ^ inSbox(ft[fault][1][7] ^ j),5)^galoisMult(inSbox(ot[fault][2][5] ^ a2) ^ inSbox(ft[fault][2][5] ^ a2),7)
            if lhs==rhs:
                t=(k023_t[i][0],j,k023_t[i][1],k023_t[i][2])
                k0123.add(t)
    C0 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C015 = set()
    for i in C1:
        for j in C5:
            for k in C0:
                a2=i[2]^j[2]
                a3=i[3]^j[3]
                if(k[3]==a3 and k[2]==a2):
                    t = (k[0],k[1],k[2],k[3],i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3])
                    C015.add(t)

    #Column 4 --------------------------------------------
    k01=set()
    for i in C015:
        a0=i[4]^i[8]
        a1=inSbox(0xc5^i[0]^a0)
        k01.add((a0,a1))
    k01_t = list(k01)

    k012=set()
    k0123=set()
    for i in range (256):  
        for j in k01_t:
                lhs = galoisMult(inSbox(ot[fault][0][4] ^ j[0]) ^ inSbox(ft[fault][0][4] ^ j[0]),7)^inSbox(ot[fault][1][3] ^ j[1]) ^ inSbox(ft[fault][1][3] ^ j[1]) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][2][1] ^ i) ^ inSbox(ft[fault][2][1] ^ i),2)
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k012.add(t)
    k012_t=list(k012)
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a1=k012_t[i][1]
            lhs=galoisMult(inSbox(ot[fault][3][0]^j)^inSbox(ft[fault][3][0]^j),2)^galoisMult(inSbox(ot[fault][1][3]^a1)^inSbox(ft[fault][1][3]^a1),3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][4]^a0)^inSbox(ft[fault][0][4]^a0),7)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C4 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0145 = set()
    for i in C015:
        for j in C4:
            a0=i[4]^i[8]
            a1=inSbox(0xc5^i[0]^a0)
            if(j[0]==a0 and j[1]==a1):
                    t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],j[0],j[1],j[2],j[3],i[8],i[9],i[10],i[11])
                    C0145.add(t)

    #Column 7 (k10, k24) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C01457_t=set()
    for i in C0145:
        a1=i[1]^i[9]
        a2=i[2]^i[10]
        C01457_t.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],a1,a2))
    # Column 2 (27),3(03), and 6(23) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C01234567_t=set()
    for i in C01457_t:
        a03=inSbox(i[11]^i[3])
        a23=inSbox(i[13]^i[5])
        a27=a23^i[6]
        C01234567_t.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],a27,a03,i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],a23,i[16],i[17]))

    # Column 2  --------------------------------------------
    #Column 2
    k013=set()
    for i in range (256):
        for j in range (256):
            for k in range (256):
                lhs = inSbox(ot[fault][0][2] ^ i) ^ inSbox(ft[fault][0][2] ^ i)
                rhs = inSbox(ot[fault][1][1] ^ j) ^ inSbox(ft[fault][1][1] ^ j)^inSbox(ot[fault][3][6] ^ k) ^ inSbox(ft[fault][3][6] ^ k) #using byte-inter-relation equations
                if(lhs==rhs):
                    k013.add((i,j,k))
    k0123=set()

    for i in k013:
        for j in range(256):
            lhs = galoisMult(inSbox(ot[fault][3][6] ^ i[2]) ^ inSbox(ft[fault][3][6] ^ i[2]),3)
            rhs = galoisMult(inSbox(ot[fault][1][1] ^ i[1]) ^ inSbox(ft[fault][1][1] ^ i[1]),2)^galoisMult(inSbox(ot[fault][2][7] ^ j) ^ inSbox(ft[fault][2][7] ^ j),7) #using byte-inter-relation equations
            if(lhs==rhs):
                k0123.add((i[0],i[1],j,i[2]))
    # Merging the keyspaces using  key-schedule equations
    C01234567_t1=set()
    for i in C01234567_t:
        for j in k0123:
            if(i[8]==j[2]):
                C01234567_t1.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],j[0],j[1],i[8],j[3],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20]))

    # Column 6 -----------------------------------------------
    k0123=set()
    for i in C01234567_t1:
        a0=i[8]^i[17]
        a1=i[9]^i[18]
        a2=i[21]
        a3=i[7]^i[11]
        k0123.add((a0,a1,a2,a3))
    k0123_t=set()
    for i in k0123:
        lhs = inSbox(ot[fault][0][6] ^ i[0]) ^ inSbox(ft[fault][0][6] ^ i[0]) #using byte-inter-relation equations
        rhs = galoisMult(inSbox(ot[fault][2][3] ^ i[2]) ^ inSbox(ft[fault][2][3] ^ i[2]),7)^galoisMult(inSbox(ot[fault][3][2] ^ i[3]) ^ inSbox(ft[fault][3][2] ^ i[3]),4)
        if(lhs==rhs):
            lhs1=galoisMult(inSbox(ot[fault][0][6]^i[0])^inSbox(ft[fault][0][6]^i[0]),5)^galoisMult(inSbox(ot[fault][1][5]^i[1])^inSbox(ft[fault][1][5]^i[1]),7) #using byte-inter-relation equations
            rhs1=inSbox(ot[fault][3][2]^i[3])^inSbox(ft[fault][3][2]^i[3])
            if(lhs1==rhs1):
                k0123_t.add(i)
    C6=list(k0123_t) 
    C01234567_t2=set()
    # Merging the keyspaces using  key-schedule equations
    for i in C01234567_t1:
        for j in C6:
            a0=i[8]^i[17]
            a1=i[9]^i[18]
            a2=i[21]
            a3=i[7]^i[11]
            if(a0==j[0] and a1==j[1] and a2==j[2] and a3==j[3]):
                C01234567_t2.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],a0,a1,i[21],a3,i[22],i[23]))

    # Column 3 -----------------------------------------------
    k01=set()
    for i in C01234567_t2:
        a0=i[12]
        a1=i[22]^i[25]
        k01.add((a0,a1))

    for i in range (256):  
        for j in k01:
                lhs = galoisMult(inSbox(ot[fault][1][2] ^ j[1]) ^ inSbox(ft[fault][1][2] ^ j[1]),7)^galoisMult(inSbox(ot[fault][3][7] ^i) ^ inSbox(ft[fault][3][7] ^ i),3) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][0][3] ^ j[0]) ^ inSbox(ft[fault][0][3] ^ j[0])
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k013.add(t)
    k013_t=list(k013)
    k0123=set()
    for i in range (len(k013_t)):
        for j in range (256):
            a0=k013_t[i][0]
            a3=k013_t[i][2]
            lhs=inSbox(ot[fault][2][0]^j)^inSbox(ft[fault][2][0]^j)^inSbox(ot[fault][3][7]^a3)^inSbox(ft[fault][3][7]^a3) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][0][3]^a0)^inSbox(ft[fault][0][3]^a0)
            if lhs==rhs:
                t=(k013_t[i][0],k013_t[i][1],j,k013_t[i][2])
                k0123.add(t)
    C3 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t3 = set()
    for i in C01234567_t2:
        for j in C3:
            a1=i[22]^i[25]
            if(j[0]==i[12]  and j[1]==a1):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],a1,j[2],j[3],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26])
                C01234567_t3.add(t)

    # Column 7 -----------------------------
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t3:
        a0=i[12]^i[24]
        a3_1=i[11]^i[15]
        a3_2=inSbox(i[14]^i[29])
        if(a3_1==a3_2):
            C01234567.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27],a0,i[28],i[29],a3_1))
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,3)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14

def diag4(fault): #Function to return the keyspace if the fault is done in 4th  Diagonal
    
    # Column 6 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][6] ^ i) ^ inSbox(ft[fault][0][6] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][2] ^ j) ^ inSbox(ft[fault][3][2] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)

    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][6] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][6] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][5] ^ j) ^ inSbox(ft[fault][1][5] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    # Merging the keyspaces using  key-schedule equations
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][6] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][6] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][3] ^ j) ^ inSbox(ft[fault][2][3] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C6= list(k0123)

    # Column 2 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][2] ^ i) ^ inSbox(ft[fault][0][2] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][1] ^ j) ^ inSbox(ft[fault][1][1] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][2] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][2] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][7] ^ j) ^ inSbox(ft[fault][2][7] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    # Merging the keyspaces using  key-schedule equations
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][2] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][2] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][6] ^ j) ^ inSbox(ft[fault][3][6] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C2 = list(k0123)

    #Column 5 --------------------------------------------
    k01=set()
    for i in C2:
        for j in C6:
            a0=i[0]^j[0]
            a1=i[1]^j[1]
            k01.add((a0,a1))
    k01_t = list(k01)

    k012=set()
    k0123=set()
    for i in range (256):  
        for j in k01_t:
                lhs = galoisMult(inSbox(ot[fault][0][5] ^ j[0]) ^ inSbox(ft[fault][0][5] ^ j[0]),7)^inSbox(ot[fault][1][4] ^ j[1]) ^ inSbox(ft[fault][1][4] ^ j[1]) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][2][2] ^ i) ^ inSbox(ft[fault][2][2] ^ i),2)
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k012.add(t)
    k012_t=list(k012)
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a1=k012_t[i][1]
            lhs=galoisMult(inSbox(ot[fault][3][1]^j)^inSbox(ft[fault][3][1]^j),2)^galoisMult(inSbox(ot[fault][1][4]^a1)^inSbox(ft[fault][1][4]^a1),3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][5]^a0)^inSbox(ft[fault][0][5]^a0),7)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C5 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C256 = set()
    for i in C2:
        for j in C6:
            for k in C5:
                a0=i[0]^j[0]
                a1=i[1]^j[1]
                if(k[0]==a0 and k[1]==a1):
                    t = (i[0],i[1],i[2],i[3],k[0],k[1],k[2],k[3],j[0],j[1],j[2],j[3])
                    C256.add(t)

    #Column 1 --------------------------------------------
    k123=set()
    for i in C256:
        a1=i[5]^sbox[i[10]]
        a2=i[2]^i[10]
        a3=i[3]^i[11]
        k123.add((a1,a2,a3))
    k0123=set()
    for i in k123:   
        for j in range (256):
                lhs=galoisMult(inSbox(ot[fault][0][1]^j)^inSbox(ft[fault][0][1]^j),7)^galoisMult(inSbox(ot[fault][3][5]^i[2])^inSbox(ft[fault][3][5]^i[2]),5) #using byte-inter-relation equations
                rhs=inSbox(ot[fault][2][6]^i[1])^inSbox(ft[fault][2][6]^i[1])
                if(lhs==rhs):
                    t=(j,i[0],i[1],i[2])
                    k0123.add(t)
    k0123_t=list(k0123)
    k0123=set()
    for i in range (len(k0123_t)):
            a0=k0123_t[i][0]
            a1=k0123_t[i][1]
            a2=k0123_t[i][2]
            lhs = inSbox(ot[fault][0][1] ^ a0) ^ inSbox(ft[fault][0][1] ^ a0)
            rhs = galoisMult(inSbox(ot[fault][1][0] ^ a1) ^ inSbox(ft[fault][1][0] ^ a1),5)^galoisMult(inSbox(ot[fault][2][6] ^ a2) ^ inSbox(ft[fault][2][6] ^ a2),7) #using byte-inter-relation equations
            if lhs==rhs:
                t=(k0123_t[i][0],k0123_t[i][1],k0123_t[i][2],k0123_t[i][3])
                k0123.add(t)
    C1 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C1256 = set()
    for i in C256:
        a1=i[5]^sbox[i[10]]
        a2=i[2]^i[10]
        a3=i[3]^i[11]
        for j in C1:
            if(j[3]==a3 and j[2]==a2 and j[1]==a1):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11])
                C1256.add(t)

    #Column 4 --------------------------------------------
    k0=set()
    for i in C1256:
        a0=i[8]^i[0]
        k0.add(a0)

    k013=set()
    k0123=set()
    for i in range (256):  
        for j in k0:
            for k in range (256):
                lhs = galoisMult(inSbox(ot[fault][1][3] ^ k) ^ inSbox(ft[fault][1][3] ^ k),7)^galoisMult(inSbox(ot[fault][3][0] ^i) ^ inSbox(ft[fault][3][0] ^ i),3) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][0][4] ^ j) ^ inSbox(ft[fault][0][4] ^ j)
                if(lhs==rhs):
                    t=(j,k,i)
                    k013.add(t)
    k013_t=list(k013)
    for i in range (len(k013_t)):
        for j in range (256):
            a0=k013_t[i][0]
            a3=k013_t[i][2]
            lhs=inSbox(ot[fault][2][1]^j)^inSbox(ft[fault][2][1]^j)^inSbox(ot[fault][3][0]^a3)^inSbox(ft[fault][3][0]^a3) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][0][4]^a0)^inSbox(ft[fault][0][4]^a0)
            if lhs==rhs:
                t=(k013_t[i][0],k013_t[i][1],j,k013_t[i][2])
                k0123.add(t)
    C4 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C12456 = set()
    for i in C1256:
        for j in C4:
            a0=i[8]^i[0]
            if(j[0]==a0 ):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],j[0],j[1],j[2],j[3],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15])
                C12456.add(t)

    #Column 0 (k00, k25 , k34)--------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C012456_t=set()
    for i in C12456:
        a0=i[8]^0xc5^sbox[i[9]]
        a2=i[2]^i[14]
        a3=i[3]^i[15]
        t = (a0,a2,a3,i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19])
        C012456_t.add(t)

    #Column 3 and 7 --------------------------------------------
    C01234567_t=set()
    #column 7 reduction
    for i in C012456_t:
        a24=i[1]^i[13]
        a03=inSbox(i[2]^i[14])
        a07=a03^i[19]
        for j in range (256):
            lhs = inSbox(ot[fault][0][7] ^ a07) ^ inSbox(ft[fault][0][7] ^ a07) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][4] ^ a24) ^ inSbox(ft[fault][2][4] ^ a24),7)^galoisMult(inSbox(ot[fault][3][3] ^ j) ^ inSbox(ft[fault][3][3] ^ j),4)
            if(lhs==rhs):
                C01234567_t.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],a03,i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],a07,a24,j))
    C01234567_t1=set()
    for i in C01234567_t:
        for j in range (256):
            lhs=galoisMult(inSbox(ot[fault][0][7]^i[24])^inSbox(ft[fault][0][7]^i[24]),5)^galoisMult(inSbox(ot[fault][1][6]^j)^inSbox(ft[fault][1][6]^j),7) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][3][3]^i[26])^inSbox(ft[fault][3][3]^i[26])
            if(lhs==rhs):
                C01234567_t1.add((i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],j,i[25],i[26]))
    #Column 3 reduction
    k0123=set()
    for i in C01234567_t1:
        a1=i[21]^i[25]
        a2=i[26]^sbox[i[27]]
        a3=i[27]^i[10]
        k0123.add((i[11],a1,a2,a3))

    k0123_t=set()
    for i in k0123:
            lhs = inSbox(ot[fault][0][3] ^ i[0]) ^ inSbox(ft[fault][0][3] ^ i[0]) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][2] ^ i[1]) ^ inSbox(ft[fault][1][2] ^ i[1])^inSbox(ot[fault][3][7] ^ i[3]) ^ inSbox(ft[fault][3][7] ^ i[3])
            if(lhs==rhs):
                lhs1 = galoisMult(inSbox(ot[fault][3][7] ^ i[3]) ^ inSbox(ft[fault][3][7] ^ i[3]),3) #using byte-inter-relation equations
                rhs1 = galoisMult(inSbox(ot[fault][1][2] ^ i[1]) ^ inSbox(ft[fault][1][2] ^ i[1]),2)^galoisMult(inSbox(ot[fault][2][0] ^ i[2]) ^ inSbox(ft[fault][2][0] ^ i[2]),7)
                if(lhs1==rhs1):
                    k0123_t.add(i)
    C3=list(k0123_t)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t3 = set()
    for i in C01234567_t1:
            for j in C3:
                a1=i[21]^i[25]
                a2=i[26]^sbox[i[27]]
                a3=i[27]^i[10]
                if(j[3]==a3 and j[2]==a2 and j[1]==a1 and j[0]==i[11]):
                    t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],j[1],j[2],j[3],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27])
                    C01234567_t3.add(t)

    #Column 0 k17
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t3:
        a1=i[16]^i[28]
        t = (i[0],a1,i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27],i[28],i[29],i[30])
        C01234567.add(t)
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,4)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14

def diag5(fault): #Function to return the keyspace if the fault is done in 5th  Diagonal
    
    # Column 7 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][7] ^ i) ^ inSbox(ft[fault][0][7] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][3] ^ j) ^ inSbox(ft[fault][3][3] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)

    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][7] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][7] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][6] ^ j) ^ inSbox(ft[fault][1][6] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    # Merging the keyspaces using  key-schedule equations
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][7] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][7] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][4] ^ j) ^ inSbox(ft[fault][2][4] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C7= list(k0123)

    # Column 3 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][3] ^ i) ^ inSbox(ft[fault][0][3] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][2] ^ j) ^ inSbox(ft[fault][1][2] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][3] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][3] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][0] ^ j) ^ inSbox(ft[fault][2][0] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][3] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][3] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][7] ^ j) ^ inSbox(ft[fault][3][7] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C3 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C37 = set()
    for i in C3:
        for j in C7:
            if ((inSbox(i[2]^j[2]))==j[3]):
                t = (i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3])
                C37.add(t)
    # Column 6 --------------------------------------------
    k01=set()
    for i in C37:
        a0=i[0]^i[4]
        a1=i[1]^i[5]
        k01.add((a0,a1))
    k01_t = list(k01)

    k012=set()
    k0123=set()
    for i in range (256):  
        for j in k01_t:
                lhs = galoisMult(inSbox(ot[fault][0][6] ^ j[0]) ^ inSbox(ft[fault][0][6] ^ j[0]),7)^inSbox(ot[fault][1][5] ^ j[1]) ^ inSbox(ft[fault][1][5] ^ j[1]) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][2][3] ^ i) ^ inSbox(ft[fault][2][3] ^ i),2)
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k012.add(t)
    k012_t=list(k012)
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a1=k012_t[i][1]
            lhs=galoisMult(inSbox(ot[fault][3][2]^j)^inSbox(ft[fault][3][2]^j),2)^galoisMult(inSbox(ot[fault][1][5]^a1)^inSbox(ft[fault][1][5]^a1),3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][6]^a0)^inSbox(ft[fault][0][6]^a0),7)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C6 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C367 = set()
    for i in C37:
        a0=i[0]^i[4]
        a1=i[1]^i[5]
        for k in C6:
            if(k[0]==a0 and k[1]==a1):
                t = (i[0],i[1],i[2],i[3],k[0],k[1],k[2],k[3],i[4],i[5],i[6],i[7])
                C367.add(t)

    # Column 2 -------------------------------------------- 
    k3=set()
    for i in C367:
        k3.add((i[3]^i[11]))
    k023=set()
    for i in k3:   
        for j in range (256):
            for k in range (256):
                lhs=galoisMult(inSbox(ot[fault][0][2]^j)^inSbox(ft[fault][0][2]^j),7)^galoisMult(inSbox(ot[fault][3][6]^i)^inSbox(ft[fault][3][6]^i),5) #using byte-inter-relation equations
                rhs=inSbox(ot[fault][2][7]^k)^inSbox(ft[fault][2][7]^k)
                if(lhs==rhs):
                    t=(j,k,i)
                    k023.add(t)
    k023_t=list(k023)
    k0123=set()
    for i in range (len(k023_t)):
        for j in range (256):
            a0=k023_t[i][0]
            a2=k023_t[i][1]
            lhs = inSbox(ot[fault][0][2] ^ a0) ^ inSbox(ft[fault][0][2] ^ a0)
            rhs = galoisMult(inSbox(ot[fault][1][1] ^ j) ^ inSbox(ft[fault][1][1] ^ j),5)^galoisMult(inSbox(ot[fault][2][7] ^ a2) ^ inSbox(ft[fault][2][7] ^ a2),7) #using byte-inter-relation equations
            if lhs==rhs:
                t=(k023_t[i][0],j,k023_t[i][1],k023_t[i][2])
                k0123.add(t)
    C2 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C2367 = set()
    for i in C367:
        a3=i[3]^i[11]
        for j in C2:
            if(j[3]==a3):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11])
                C2367.add(t)

    # Column 5 --------------------------------------------
    k01=set()
    for i in C2367:
        a0=i[8]^i[0]
        a1=i[1]^i[9]
        k01.add((a0,a1))

    k013=set()
    k0123=set()
    for i in range (256):  
        for j in k01:
                lhs = galoisMult(inSbox(ot[fault][1][4] ^ j[1]) ^ inSbox(ft[fault][1][4] ^ j[1]),7)^galoisMult(inSbox(ot[fault][3][1] ^i) ^ inSbox(ft[fault][3][1] ^ i),3) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][0][5] ^ j[0]) ^ inSbox(ft[fault][0][5] ^ j[0])
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k013.add(t)
    k013_t=list(k013)
    for i in range (len(k013_t)):
        for j in range (256):
            a0=k013_t[i][0]
            a3=k013_t[i][2]
            lhs=inSbox(ot[fault][2][2]^j)^inSbox(ft[fault][2][2]^j)^inSbox(ot[fault][3][1]^a3)^inSbox(ft[fault][3][1]^a3) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][0][5]^a0)^inSbox(ft[fault][0][5]^a0)
            if lhs==rhs:
                t=(k013_t[i][0],k013_t[i][1],j,k013_t[i][2])
                k0123.add(t)
    C5 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C23567 = set()
    for i in C2367:
        for j in C5:
            a0=i[8]^i[0]
            a1=i[1]^i[9]
            if(j[0]==a0 and j[1]==a1):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],j[0],j[1],j[2],j[3],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15])
                C23567.add(t)

    # Column 1 (K10, K26, K35) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C123567_t=set()
    for i in C23567:
        a1=sbox[i[14]]^i[9]
        a2=i[2]^i[14]
        a3=i[3]^i[15]
        t = (a1,a2,a3,i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19])
        C123567_t.add(t)

    # Column 0  --------------------------------------------
    k23=set()
    for i in C123567_t:
        a2=i[1]^i[13]
        a3=i[2]^i[14]
        k23.add((a2,a3))

    for i in k23:
        for j in range (256):
                lhs = inSbox(ot[fault][0][0] ^ j) ^ inSbox(ft[fault][0][0] ^ j) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][2][5] ^ i[0]) ^ inSbox(ft[fault][2][5] ^ i[0]),7)^galoisMult(inSbox(ot[fault][3][4] ^ i[1]) ^ inSbox(ft[fault][3][4] ^ i[1]),4)
                if(lhs==rhs):
                    t=(j,i[0],i[1])
                    k023.add(t)
    k0123=set()
    for i in k023:
        for j in range (256):
            lhs=galoisMult(inSbox(ot[fault][0][0]^i[0])^inSbox(ft[fault][0][0]^i[0]),5)^galoisMult(inSbox(ot[fault][1][7]^j)^inSbox(ft[fault][1][7]^j),7) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][3][4]^i[2])^inSbox(ft[fault][3][4]^i[2])
            if(lhs==rhs):
                t=(i[0],j,i[1],i[2])
                k0123.add(t)
    C0 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0123567_t = set()
    for i in C123567_t:
        for j in C0:
            a2=i[1]^i[13]
            a3=i[2]^i[14]
            if(j[3]==a3 and j[2]==a2):
                t = (j[0],j[1],j[2],j[3],i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22])
                C0123567_t.add(t)

    # Column 4  --------------------------------------------
    k0123=set()
    for i in C0123567_t:
        a1=i[24]^i[1]
        a0=sbox[a1]^0xc5^i[0]
        a2=i[2]^i[25]
        a3=i[3]^sbox[i[11]]
        k0123.add((a0,a1,a2,a3))

    k0123_t=set()
    for i in k0123:
            lhs = inSbox(ot[fault][0][4] ^ i[0]) ^ inSbox(ft[fault][0][4] ^ i[0]) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][3] ^ i[1]) ^ inSbox(ft[fault][1][3] ^ i[1])^inSbox(ot[fault][3][0] ^ i[3]) ^ inSbox(ft[fault][3][0] ^ i[3])
            if(lhs==rhs):
                lhs1 = galoisMult(inSbox(ot[fault][3][0] ^ i[3]) ^ inSbox(ft[fault][3][0] ^ i[3]),3) #using byte-inter-relation equations
                rhs1 = galoisMult(inSbox(ot[fault][1][3] ^ i[1]) ^ inSbox(ft[fault][1][3] ^ i[1]),2)^galoisMult(inSbox(ot[fault][2][1] ^ i[2]) ^ inSbox(ft[fault][2][1] ^ i[2]),7)
                if(lhs1==rhs1):
                    k0123_t.add(i)
    C4=list(k0123_t)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t = set()
    for i in C0123567_t:
        for j in C4:
            a1=i[24]^i[1]
            a0=sbox[a1]^0xc5^i[0]
            a2=i[2]^i[25]
            a3=i[3]^sbox[i[11]]
            if(j[3]==a3 and j[2]==a2 and j[1]==a1 and j[0]==a0):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],j[0],j[1],j[2],j[3],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26])
                C01234567_t.add(t)

    # Column 1  --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t:
        a0=i[15]^i[19]
        t = (i[0],i[1],i[2],i[3],a0,i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27],i[28],i[29],i[30])
        C01234567.add(t)
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,5)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14

def diag6(fault): #Function to return the keyspace if the fault is done in 6th  Diagonal
    
    # Column 0 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][0] ^ i) ^ inSbox(ft[fault][0][0] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][4] ^ j) ^ inSbox(ft[fault][3][4] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)
    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][0] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][0] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][7] ^ j) ^ inSbox(ft[fault][1][7] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][0] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][0] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][5] ^ j) ^ inSbox(ft[fault][2][5] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C0 = list(k0123)

    # Column 4 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][4] ^ i) ^ inSbox(ft[fault][0][4] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][3] ^ j) ^ inSbox(ft[fault][1][3] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][4] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][4] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][1] ^ j) ^ inSbox(ft[fault][2][1] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][4] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][4] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][0] ^ j) ^ inSbox(ft[fault][3][0] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C4 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C04 = set()
    for i in C0:
        for j in C4:
            if (inSbox(i[0]^j[0]^0xc5)==j[1]):
                t = (i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3])
                C04.add(t)

    # Column 7 --------------------------------------------
    k12=set()
    for i in C04:
        a1 = i[1]^i[5]
        a2 = i[2]^i[6]
        k12.add((a1,a2))
    k12_t = list(k12)
    k123=set()
    k0123=set()
    for i in range (256):  
        for j in k12_t:
                lhs = inSbox(ot[fault][1][6] ^ j[0]) ^ inSbox(ft[fault][1][6] ^ j[0])^inSbox(ot[fault][3][3] ^ i) ^ inSbox(ft[fault][3][3] ^ i) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][2][4] ^ j[1]) ^ inSbox(ft[fault][2][4] ^ j[1])
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k123.add(t)
    k123_t=list(k123)
    for i in range (len(k123_t)):
        for j in range (256):
            a2=k123_t[i][1]
            a3=k123_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][2][4]^a2)^inSbox(ft[fault][2][4]^a2),3)^inSbox(ot[fault][3][3]^a3)^inSbox(ft[fault][3][3]^a3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][7]^j)^inSbox(ft[fault][0][7]^j),7)
            if lhs==rhs:
                t=(j,k123_t[i][0],k123_t[i][1],k123_t[i][2])
                k0123.add(t)
    C7 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C047 = set()
    for i in C04:
        a1 = i[1]^i[5]
        a2 = i[2]^i[6]
        for k in C7:
            if(k[2]==a2 and k[1]==a1):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],k[0],k[1],k[2],k[3])
                C047.add(t)
    
    # Column 3 --------------------------------------------
    k02=set()
    for i in C047:
        a0=inSbox(i[7]^i[3])
        a2=sbox[i[11]]^i[10]
        k02.add((a0,a2))
    k02_t = list(k02)
    k012=set()
    for i in range (256):   
        for j in k02_t:
                lhs = inSbox(ot[fault][0][3] ^ j[0]) ^ inSbox(ft[fault][0][3] ^ j[0])
                rhs = galoisMult(inSbox(ot[fault][1][2] ^ i) ^ inSbox(ft[fault][1][2] ^ i),5)^galoisMult(inSbox(ot[fault][2][0] ^ j[1]) ^ inSbox(ft[fault][2][0] ^ j[1]),7) #using byte-inter-relation equations
                if(lhs==rhs):
                    t=(j[0],i,j[1])
                    k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a2=k012_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][0][3]^a0)^inSbox(ft[fault][0][3]^a0),7)^galoisMult(inSbox(ot[fault][3][7]^j)^inSbox(ft[fault][3][7]^j),5) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][2][0]^a2)^inSbox(ft[fault][2][0]^a2)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C3 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0347 = set()
    for i in C047:
        a0=inSbox(i[7]^i[3])
        a2=sbox[i[11]]^i[10]
        for j in C3:
            if(j[0]==a0 and j[2]==a2):
                t = (i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11])
                C0347.add(t)
    
    # Column 6 --------------------------------------------
    k01=set()
    for i in C0347:
        a0=i[4]^i[12]
        a1=i[5]^i[13]
        k01.add((a0,a1))
    k013=set()
    k0123=set()
    for i in range (256):  
        for j in k01:
            lhs = galoisMult(inSbox(ot[fault][1][5] ^ j[1]) ^ inSbox(ft[fault][1][5] ^ j[1]),7)^galoisMult(inSbox(ot[fault][3][2] ^i) ^ inSbox(ft[fault][3][2] ^ i),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][0][6] ^ j[0]) ^ inSbox(ft[fault][0][6] ^ j[0])
            if(lhs==rhs):
                t=(j[0],j[1],i)
                k013.add(t)
    k013_t=list(k013)
    for i in range (len(k013_t)):
        for j in range (256):
            a0=k013_t[i][0]
            a3=k013_t[i][2]
            lhs=inSbox(ot[fault][2][3]^j)^inSbox(ft[fault][2][3]^j)^inSbox(ot[fault][3][2]^a3)^inSbox(ft[fault][3][2]^a3) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][0][6]^a0)^inSbox(ft[fault][0][6]^a0)
            if lhs==rhs:
                t=(k013_t[i][0],k013_t[i][1],j,k013_t[i][2])
                k0123.add(t)
    C6 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C03467 = set()
    for i in C0347:
        for j in C6:
            a0=i[4]^i[12]
            a1=i[5]^i[13]
            if(j[0]==a0 and j[1]==a1):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],j[0],j[1],j[2],j[3],i[12],i[13],i[14],i[15])
                C03467.add(t)
    
    # Column 2 (k36) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C023467_t=set()
    for i in C03467:
        a3=i[19]^i[7]
        t=(i[0],i[1],i[2],i[3],a3,i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19])
        C023467_t.add(t)
    
    # Column 1  --------------------------------------------
    k3=set()
    for i in C023467_t:
        k3.add((i[4]^i[16]))
    k023=set()
    k3_t=list(k3)
    for i in k3:
        for j in range (256):
            for k in range (256):
                lhs = inSbox(ot[fault][0][1] ^ j) ^ inSbox(ft[fault][0][1] ^ j) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][2][6] ^ k) ^ inSbox(ft[fault][2][6] ^ k),7)^galoisMult(inSbox(ot[fault][3][5] ^ i) ^ inSbox(ft[fault][3][5] ^ i),4)
                if(lhs==rhs):
                    t=(j,k,i)
                    k023.add(t)
    k0123=set()
    for i in k023:
        for j in range (256):
            lhs=galoisMult(inSbox(ot[fault][0][1]^i[0])^inSbox(ft[fault][0][1]^i[0]),5)^galoisMult(inSbox(ot[fault][1][0]^j)^inSbox(ft[fault][1][0]^j),7) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][3][5]^i[2])^inSbox(ft[fault][3][5]^i[2])
            if(lhs==rhs):
                t=(i[0],j,i[1],i[2])
                k0123.add(t)
    C1 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0123467_t = set()
    for i in C023467_t:
        for j in C1:
            a3=(i[4]^i[16])
            if(j[3]==a3 ):
                t = (i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20])
                C0123467_t.add(t)
    
    # Column 5  --------------------------------------------
    k0123=set()
    k0123_t=set()
    for i in C0123467_t:
        a0=i[4]^i[13]
        a1=i[5]^sbox[i[19]]
        a2=i[2]^i[6]
        a3=i[3]^i[7]
        k0123.add((a0,a1,a2,a3))
    for i in k0123:
        lhs = inSbox(ot[fault][0][5] ^ i[0]) ^ inSbox(ft[fault][0][5] ^ i[0]) #using byte-inter-relation equations
        rhs = inSbox(ot[fault][1][4] ^ i[1]) ^ inSbox(ft[fault][1][4] ^ i[1])^inSbox(ot[fault][3][1] ^ i[3]) ^ inSbox(ft[fault][3][1] ^ i[3])
        if(lhs==rhs):
            lhs1 = galoisMult(inSbox(ot[fault][3][1] ^ i[3]) ^ inSbox(ft[fault][3][1] ^ i[3]),3) #using byte-inter-relation equations
            rhs1 = galoisMult(inSbox(ot[fault][1][4] ^ i[1]) ^ inSbox(ft[fault][1][4] ^ i[1]),2)^galoisMult(inSbox(ot[fault][2][2] ^ i[2]) ^ inSbox(ft[fault][2][2] ^ i[2]),7)
            if(lhs1==rhs1):
                k0123_t.add(i)
    C5=list(k0123_t)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t = set()
    for i in C0123467_t:
        for j in C5:
            a0=i[4]^i[13]
            a1=i[5]^sbox[i[19]]
            a2=i[2]^i[6]
            a3=i[3]^i[7]
            if(j[3]==a3 and j[2]==a2 and j[1]==a1 and j[0]==a0):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],j[0],j[1],j[2],j[3],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24])
                C01234567_t.add(t)
    
    # Column 2  -------------------------------------------- 
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t:
        a0=i[17]^i[21]
        a1=i[18]^i[22]
        a2=i[23]^i[6]
        t=(i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],a0,a1,a2,i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27],i[28])
        C01234567.add(t)    
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,6)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14
    
def diag7(fault): #Function to return the keyspace if the fault is done in 7th  Diagonal
    
    # Column 1 --------------------------------------------
    k03=set()
    for i in range (256):   
        for j in range (256):
            lhs = inSbox(ot[fault][0][1] ^ i) ^ inSbox(ft[fault][0][1] ^ i) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][3][5] ^ j) ^ inSbox(ft[fault][3][5] ^ j)
            if(lhs==rhs):
                t=(i,j)
                k03.add(t)
    k01_t=list(k03)
    k013=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][1] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][1] ^ k01_t[i][0]),3) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][1][0] ^ j) ^ inSbox(ft[fault][1][0] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],j,k01_t[i][1])
                k013.add(t)
    k01_t=list(k013)
    k0123=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][1] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][1] ^ k01_t[i][0]),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][6] ^ j) ^ inSbox(ft[fault][2][6] ^ j)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j,k01_t[i][2])
                k0123.add(t)
    C1 = list(k0123)

    # Column 5 --------------------------------------------
    k01=set()
    for i in range (256): 
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][0][5] ^ i) ^ inSbox(ft[fault][0][5] ^ i),2) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][1][4] ^ j) ^ inSbox(ft[fault][1][4] ^ j),3)
            if(lhs==rhs):
                t=(i,j)
                k01.add(t)
    k01_t=list(k01)
    k012=set()
    for i in range (len(k01_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][5] ^ k01_t[i][0]) ^ inSbox(ft[fault][0][5] ^ k01_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][2][2] ^ j) ^ inSbox(ft[fault][2][2] ^ j),3)
            if(lhs==rhs):
                t=(k01_t[i][0],k01_t[i][1],j)
                k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            lhs = inSbox(ot[fault][0][5] ^ k012_t[i][0]) ^ inSbox(ft[fault][0][5] ^ k012_t[i][0]) #using byte-inter-relation equations
            rhs = galoisMult(inSbox(ot[fault][3][1] ^ j) ^ inSbox(ft[fault][3][1] ^ j),3)
            if(lhs==rhs):
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C5 = list(k0123)

    # Column 0 --------------------------------------------
    k23=set()
    for i in C1:
        for j in C5:
            t = (i[2]^j[2],i[3]^j[3])
            k23.add(t)
    k23_t = list(k23)
    k123=set()
    k0123=set()
    for i in range (256):  
        for j in k23_t:
                lhs = inSbox(ot[fault][1][7] ^ i) ^ inSbox(ft[fault][1][7] ^ i)^inSbox(ot[fault][3][4] ^ j[1]) ^ inSbox(ft[fault][3][4] ^ j[1]) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][2][5] ^ j[0]) ^ inSbox(ft[fault][2][5] ^ j[0])
                if(lhs==rhs):
                    t=(i,j[0],j[1])
                    k123.add(t)
    k123_t=list(k123)
    for i in range (len(k123_t)):
        for j in range (256):
            a2=k123_t[i][1]
            a3=k123_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][2][5]^a2)^inSbox(ft[fault][2][5]^a2),3)^inSbox(ot[fault][3][4]^a3)^inSbox(ft[fault][3][4]^a3) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][0][0]^j)^inSbox(ft[fault][0][0]^j),7)
            if lhs==rhs:
                t=(j,k123_t[i][0],k123_t[i][1],k123_t[i][2])
                k0123.add(t)
    C0 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C015 = set()
    for i in C1:
        for j in C5:
            a2 = i[2]^j[2]
            a3 = i[3]^j[3]
            for k in C0:
                if(k[2]==a2 and k[3]==a3):
                    t = (k[0],k[1],k[2],k[3],i[0],i[1],i[2],i[3],j[0],j[1],j[2],j[3])
                    C015.add(t)

    # Column 4 --------------------------------------------
    k01=set()
    for i in C015:
        a0 = i[4]^i[8]
        a1 = inSbox( a0 ^ i[0] ^ 0xc5)
        k01.add((a0,a1))
    k01_t = list(k01)
    k012=set()
    for i in range (256):   
        for j in k01_t:
                lhs = inSbox(ot[fault][0][4] ^ j[0]) ^ inSbox(ft[fault][0][4] ^ j[0]) #using byte-inter-relation equations
                rhs = galoisMult(inSbox(ot[fault][1][3] ^ j[1]) ^ inSbox(ft[fault][1][3] ^ j[1]),5)^galoisMult(inSbox(ot[fault][2][1] ^ i) ^ inSbox(ft[fault][2][1] ^ i),7)
                if(lhs==rhs):
                    t=(j[0],j[1],i)
                    k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a2=k012_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][0][4]^a0)^inSbox(ft[fault][0][4]^a0),7)^galoisMult(inSbox(ot[fault][3][0]^j)^inSbox(ft[fault][3][0]^j),5) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][2][1]^a2)^inSbox(ft[fault][2][1]^a2)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C4 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0145 = set()
    for i in C015:
        a0 = i[4]^i[8]
        a1 = inSbox( a0 ^ i[0] ^ 0xc5)
        for j in C4:
            if(j[0]==a0 and j[1]==a1):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],j[0],j[1],j[2],j[3],i[8],i[9],i[10],i[11])
                C0145.add(t)

    # Column 7 --------------------------------------------
    k12 = set()
    for i in C0145:
        a1 = i[1]^i[9]
        a2 = i[2]^i[10]
        k12.add((a1,a2))
    k123=set()
    for i in k12:   #for k06, k15 and k32 reduction using equation  1:1:1
        for j in range (256):
            lhs = galoisMult(inSbox(ot[fault][1][6] ^ i[0]) ^ inSbox(ft[fault][1][6] ^ i[0]),7)^galoisMult(inSbox(ot[fault][3][3] ^ j) ^ inSbox(ft[fault][3][3] ^ j),2) #using byte-inter-relation equations
            rhs = inSbox(ot[fault][2][4] ^ i[1]) ^ inSbox(ft[fault][2][4] ^ i[1])
            if(lhs==rhs):
                t=(i[0],i[1],j)
                k123.add(t)
    k123_t=list(k123)

    k0123=set()
    for i in range (len(k123_t)):
        for j in range (256):
            a1=k123_t[i][0]
            a2=k123_t[i][1]
            a3=k123_t[i][2]
            lhs=galoisMult(inSbox(ot[fault][3][3]^a3)^inSbox(ft[fault][3][3]^a3),3)^inSbox(ot[fault][0][7]^j)^inSbox(ft[fault][0][7]^j) #using byte-inter-relation equations
            rhs=galoisMult(inSbox(ot[fault][1][6]^a1)^inSbox(ft[fault][1][6]^a1),7)
            if lhs==rhs:
                t=(j, k123_t[i][0],k123_t[i][1],k123_t[i][2])
                k0123.add(t)
    C7 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C01457 = set()
    for i in C0145:
        a1 = i[1]^i[9]
        a2 = i[2]^i[10]
        for j in C7:
            if(j[1]==a1 and j[2]==a2):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],j[0],j[1],j[2],j[3])
                C01457.add(t)

    # Column 3 (k03 k20) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C013457_t=set()
    for i in C01457:
        a0=inSbox(i[3]^i[11])
        a2=i[18]^sbox[i[19]]
        t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],a0,a2,i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19])
        C013457_t.add(t)

    # Column 6 --------------------------------------------
    k02=set()
    for i in C013457_t:
        a0=i[8]^i[18]
        a2=inSbox(i[5]^i[15])
        k02.add((a0,a2))
    k012=set()
    for i in k02:   #for k06, k15 and k32 reduction using equation  1:1:1
        for j in range (256):
                lhs = galoisMult(inSbox(ot[fault][0][6] ^ i[0]) ^ inSbox(ft[fault][0][6] ^ i[0]),3) #using byte-inter-relation equations
                rhs = inSbox(ot[fault][1][5] ^ j) ^ inSbox(ft[fault][1][5] ^ j)^galoisMult(inSbox(ot[fault][2][3] ^ i[1]) ^ inSbox(ft[fault][2][3] ^ i[1]),7)
                if(lhs==rhs):
                    t=(i[0],j,i[1])
                    k012.add(t)
    k012_t=list(k012)
    k0123=set()
    for i in range (len(k012_t)):
        for j in range (256):
            a0=k012_t[i][0]
            a1=k012_t[i][1]
            lhs=inSbox(ot[fault][0][6]^a0)^inSbox(ft[fault][0][6]^a0)^inSbox(ot[fault][3][2]^j)^inSbox(ft[fault][3][2]^j) #using byte-inter-relation equations
            rhs=inSbox(ot[fault][1][5]^a1)^inSbox(ft[fault][1][5]^a1)
            if lhs==rhs:
                t=(k012_t[i][0],k012_t[i][1],k012_t[i][2],j)
                k0123.add(t)
    C6 = list(k0123)
    # Merging the keyspaces using  key-schedule equations
    C0134567_t = set()
    for i in C013457_t:
        a0=i[8]^i[18]
        a2=inSbox(i[5]^i[15])
        for j in C6:
            if(j[0]==a0 and j[2]==a2):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],j[0],j[1],j[2],j[3],i[18],i[19],i[20],i[21])
                C0134567_t.add(t)

    # Column 3 (k12) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C0134567_t2=set()
    for i in C0134567_t:
        a1=i[19]^i[23]
        t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],a1,i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25])
        C0134567_t2.add(t)

    # Column 2 --------------------------------------------------
    k0123=set()
    C2 = []
    for i in C0134567_t2:
        a0 = i[15]^i[19]
        a1 = i[16]^i[20]
        a2 = i[6]^i[21]
        a3 = i[7]^i[22]
        k0123.add((a0,a1,a2,a3))
    for i in k0123:
        lhs1 = inSbox(ot[fault][0][2] ^ i[0]) ^ inSbox(ft[fault][0][2] ^ i[0]) #using byte-inter-relation equations
        rhs1 = galoisMult(inSbox(ot[fault][2][7] ^ i[2]) ^ inSbox(ft[fault][2][7] ^ i[2]),7)^galoisMult(inSbox(ot[fault][3][6] ^i[3]) ^ inSbox(ft[fault][3][6] ^ i[3]),4)
        if(lhs1==rhs1):
            lhs2=galoisMult(inSbox(ot[fault][0][2]^i[0])^inSbox(ft[fault][0][2]^i[0]),5)^galoisMult(inSbox(ot[fault][1][1]^i[1])^inSbox(ft[fault][1][1]^i[1]),7) #using byte-inter-relation equations
            rhs2=inSbox(ot[fault][3][6]^i[3])^inSbox(ft[fault][3][6]^i[3])
            if(lhs2==rhs2):
                C2.append(i)
    # Merging the keyspaces using  key-schedule equations
    C01234567_t = set()
    for i in C0134567_t2:
        a0 = i[15]^i[19]
        a1 = i[16]^i[20]
        a2 = i[6]^i[21]
        a3 = i[7]^i[22]
        for j in C2:
            if(j[0]==a0 and j[1]==a1 and j[2]==a2 and j[3]==a3):
                t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7], a0, a1, a2, a3, i[8],i[9],i[10],i[11],i[12],i[13],i[14],i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26])
                C01234567_t.add(t)

    # Column 3 (k37) --------------------------------------------
    # Merging the keyspaces using  key-schedule equations
    C01234567=set()
    for i in C01234567_t:
        a3 = i[11]^i[30]
        t = (i[0],i[1],i[2],i[3],i[4],i[5],i[6],i[7],i[8],i[9],i[10],i[11],i[12],i[13],i[14], a3, i[15],i[16],i[17],i[18],i[19],i[20],i[21],i[22],i[23],i[24],i[25],i[26],i[27],i[28],i[29],i[30])
        C01234567.add(t)
    
    key14 = set()
    for k in C01234567:
        key = getLastKey(k)
        ot_bSB14 = inSubBytes(inShiftRows(XOR(ot[fault],key)))
        ft_bSB14 = inSubBytes(inShiftRows(XOR(ft[fault],key)))
        for j in range (4):
            ot_bSB14[j][1]=ot_bSB14[j][1]^6
            ft_bSB14[j][1]=ft_bSB14[j][1]^6
        prevKey = getPreviousKey(key)
        ot_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ot_bSB14,prevKey))))
        ft_bSB13 = inSubBytes(inShiftRows(inMixColumns(XOR(ft_bSB14,prevKey))))   
        diff=XOR(ot_bSB13,ft_bSB13)
        if(isPatternFollowed(diff,7)): #using 12th round MixColumn property
            key14.add(convertToTuple(key))
    return key14

def findKeyspace():
    for i in range(len(keys)):
        temp = [] #Variable to store all the reduced Keyspace
        temp.append(list(diag0(i)))     # Calling Diagonal 0 function and appending the returned Subkey-space to temp
        temp.append(list(diag1(i)))     # Calling Diagonal 1 function and appending the returned Subkey-space to temp
        temp.append(list(diag2(i)))     # Calling Diagonal 2 function and appending the returned Subkey-space to temp
        temp.append(list(diag3(i)))     # Calling Diagonal 3 function and appending the returned Subkey-space to temp
        temp.append(list(diag4(i)))     # Calling Diagonal 4 function and appending the returned Subkey-space to temp
        temp.append(list(diag5(i)))     # Calling Diagonal 5 function and appending the returned Subkey-space to temp
        temp.append(list(diag6(i)))     # Calling Diagonal 6 function and appending the returned Subkey-space to temp
        temp.append(list(diag7(i)))     # Calling Diagonal 7 function and appending the returned Subkey-space to temp
        keyspace = set()
        for j in range(len(temp)):      # Printing the size of total Subkey-space returned
            for k in temp[j]:
                keyspace.add(k)
        print("Keyspace size : ",len(keyspace))       
        ctr=0
        found = 0
        for j in keyspace:
            ctr+=1
            if j==keys[i]:
                found = 1
                print("key found in position : ",ctr) 
        if(found == 0):
            print("key not found")
    print()

findKeyspace()

