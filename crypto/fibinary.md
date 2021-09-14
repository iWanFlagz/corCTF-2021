# fibinary
```
Warmup your crypto skills with the superior number system!
```

## Challenge
> TL;DR: For each binary string, read from right to left. If the program encounters '1', add the value of `fib[index]` to `n`. After reading the entire binary string, convert the value of `n` to ascii character. 

We are given an `enc.py` script:
``` python
fib = [1, 1]
for i in range(2, 11):
        fib.append(fib[i - 1] + fib[i - 2])

def c2f(c):
        n = ord(c)
        b = ''
        for i in range(10, -1, -1):
                if n >= fib[i]:
                        n -= fib[i]
                        b += '1'
                else:
                        b += '0'
        return b

flag = open('flag.txt', 'r').read()
enc = ''
for c in flag:
        enc += c2f(c) + ' '
with open('flag.enc', 'w') as f:
        f.write(enc.strip())
```

And a `flag.enc`:
```
10000100100 10010000010 10010001010 10000100100 10010010010 10001000000 10100000000 10000100010 00101010000 10010010000 00101001010 10000101000 10000010010 00101010000 10010000000 10000101000 10000010010 10001000000 00101000100 10000100010 10010000100 00010101010 00101000100 00101000100 00101001010 10000101000 10100000100 00000100100
```

Observation made: 
- The value of `n` will not go below 0 as it decreases only if `n >= fib[i]`
- For each encrypted binary, the first matched "1" (reading from right to left) implies the value of n. 
- The largest printable character is 0x126 which is clearly smaller than the sum of [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]

Idea of script: For each binary string, read from right to left. If the program encounters '1', add the value of `fib[index]` to `n`. After reading the entire binary string, convert the value of `n` to ascii character. 

Proof of Concept:
``` python
fib = [1, 1]
for i in range(2, 11):
	fib.append(fib[i - 1] + fib[i - 2])

flag = ''

def decrypt_flag(s):
    val = 0
    length = len(s)
    index = 0
    for i in range(length - 1, -1, -1):
        if int(s[i]) == 1:
            val = fib[index] + val
        index = index + 1
    return chr(val)

enc_flag = open('flag.enc', 'r').read().split()
for i in enc_flag:
    flag += decrypt_flag(i)

print("Flag: " + flag)
```

Output of the script:
``` bash
$ python3 solve.py
Flag: corctf{b4s3d_4nd_f1bp!113d}
```

Flag: `corctf{b4s3d_4nd_f1bp!113d}`