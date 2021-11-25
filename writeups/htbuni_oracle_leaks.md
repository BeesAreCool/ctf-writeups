# HackTheBox University Qualifiers - Crypto - Oracle Leaks!

## RSA Byte Length Oracle 

Steam Technologies is a service provider which uses strictly steam-powered computers. They have recently developed a new type of oracle taking advantage of the steam-power architecture. They offer a huge price in case someone decrypts the message from their service. Are you up for the challenge?

## Triage

The summary of the challenge is we are given a prompt that allows us to access an rsa byte length decryption oracle. This is all done on a flag that is padded out to 127 bytes long, just short of the full 128.

```python
	def pad(self, pt):
		res = 0x02 << 8 * (self.n_size - 2)
		random_pad = os.urandom(self.n_size - 3 - get_length(pt))
		for idx, val in enumerate(random_pad):
			if val == 0:
				val = 1
			res += val << (len(random_pad) - idx + get_length(pt)) * 8
		res += pt
		return res

	def encrypt(self,pt):
		pt = bytes_to_long(pt)
		padded_pt = self.pad(pt)
		print(hex(padded_pt))
		ct = pow(padded_pt, self.e, self.n)
		return long_to_bytes(ct).hex()
```

As a quick note, for RSA we are able to multiply the plaintext by arbitrary values only by manipulating the ciphertext. This is because the public key is provided and the fact the following equation holds true `enc(a)*enc(b) = enc(a*b)`. Knowing this, we can check the byte length of plaintexts such as `pt*2` as well as `pt`. 

This led to my plan of attack, we can determine the high bits of the plaintext by doing a binary search to multiply the plaintext by increasingly large numbers until it passes a certain length threshold. This doubles as essentially performing integer division. For instance, if we know that we can multiply the plaintext by 17 and it is 127 bytes long, but multiplying by 18 makes it 128 bytes long, we can figure out a range of possible values for the plaintext. In this example, it would be between `(2^128)/18 and (2^128)/17`. We can then attempt to find N divided by our value by calculating the range of possible values for `N/pt` and searching for a value that just barely rolls over N and leaves us with a byte-wise short value.

Additionally, one we know the approximate size of our plaintext, we can convert it into a different but related plaintext of relatively equal size. By attempting to find the smallest value X where `pt*x > N && pt * (x-1) < N` we will get a new plaintext qt where `qt = N % pt`. We can then recover the high bits of qt through the same process. Combining the values for high bits of qt and pt will allow us to recover more high bits of pt.

As a note, if pt was longer than 127 bytes we'd have to first blind the value to be shorter. However, we don't need to, so I won't cover that.

### Attack

After formulating the above attack I went about implementing it. First, searching for the largest value A that can be multiplied by the plaintext before resulting in a 128 byte decryption. Secondly, finding a value B that can be multiplied by the plaintext and gets the smallest value of B that results in a value larger than N. After getting these values and learning some bits of the plaintext, the plaintext is rolled around to a new value. This is all done using binary searches to minimize the number of oracle queries.

I eventually tweaked the value of B to allow for any result in a value between `N` and `N + 2^127` if such a value exists with an early exit. This reduced the number of oracle queries by around 20% and the math still worked.

Additionally, I implemented the flag recovery code. Making use of the fact that all the numbers found correspond to integer division, I simply reversed the process and walked through all the resulting plaintexts and their division to recover the flag.

Furthermore, I originally implemented a division operation that would search for common factors in the plaintext and use these to shrink the length of the plaintext. This resulted in significant query overhead so was removed.

```python
from pwn import *
import time

def int_to_bytes(val):
    plaintext = hex(val)[2:]
    if len(plaintext)%2 == 1:
        plaintext = "0"+plaintext
    return bytes.fromhex(plaintext)
    
        

#p = process(["python3", "chall.py"])
p = remote("209.97.132.64", 32419)

started = p.recvuntil(">")
p.sendline("1")
p.recvuntil("(n,e): (")
nums = p.recvline().decode("utf-8").replace(")","").replace(" ","").replace("'","")
n, e = nums.split(",")
n = int(n, 16)
e = int(e, 16)
#p.interactive()
p.recvuntil(">")
p.sendline("2")
p.recvuntil("Encrypted text:")
text = p.recvline()
text = text.decode("utf-8").strip()
ct = int(text, 16)
start = time.time()

cached = dict()
queries = 0

#This tests a number and gets the value for its decrypted length
def test_num(x):
    global cached
    global queries
    if x in cached:
        print("CACHED!")
        return cached[x]
    p.sendline("3")
    to_send = x
        
    p.sendline(int_to_bytes(x).hex())
    p.recvuntil("Length:")
    length = int(p.recvline().decode("utf-8").strip())
    cached[x] = length
    queries += 1
    return length
    
#This searches for a small value that just barely rolls over N
#Note, sometimes it isn't actually the smallest value, for some reason it does less queries this way/
def base_divide(x):
    byte_size = test_num(x)
    maximum = 0
    print("Queries start of base divide", queries)
    for i in range(int((127-byte_size)*8), 10000):
        test =(pow(int(2**i), e, n) * x) % n
        #print(test, i, 2**i)
        #print()
        maximum = 2 ** i
        if test_num(test) == 128:
            break
    print(maximum)
    bottom = maximum//2
    top = maximum
    print("Queries end of find offset", queries)
    print(bottom, top)
    while top > bottom + 1:
        mid = (top + bottom) // 2
        #print(bottom, top, mid)
        test = (pow(mid, e, n) * x) % n
        if test_num(test) == 128:
            top = mid - 1
        else:
            bottom = mid + 1
    print(bottom, top, mid)
    answer = 0
    print("Queries  mid find N range", queries)
    for i in range(top, bottom-2, -1):
        test = (pow(i, e, n) * x) % n
        print(test_num(test), byte_size)
        if test_num(test) == 127:
            answer = i
            break
    print("Queries  end find N range", queries)
    print(i)
    lowest = (256**127) // (answer+1)
    highest = ((256**127) // answer) + 1
    print(hex(lowest))
    print(hex(highest))
    ndiv_low = n // highest
    ndiv_hi = n // lowest + 1
    
    bottom = ndiv_low
    top = ndiv_hi
    print("N RANGED!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print(bottom, top)
    while top > bottom + 1:
        mid = (top + bottom) // 2
        test = (pow(mid, e, n) * x) % n
        print(bottom, top, mid, byte_size, test_num(test))
        if test_num(test) < 128:
            top = mid - 1
            if test_num(test)<127:
                print("early exit", queries)
                return mid, test
        else:
            bottom = mid + 1
    print(bottom, top)
    print("Queries  end find final", queries)
    answer = 0
    for i in range(bottom, top+3):
        test = (pow(i, e, n) * x) % n
        print(bottom, top, mid, byte_size, test_num(test))
        if test_num(test) <= byte_size:
            answer = i
            print("Queries  end divide", queries)
            return answer, test

print(n, e)
print(text)
pathed = []
multiples = []
for z in range(60):
    mul1, ct = (1, ct)
    pathed.append(ct)
    mul2, ct = base_divide(ct)
    pathed.append(ct)
    multiples.append((mul1, mul2))
    #This performs the reconstruction of the original plaintext after finding a small value to multiply by pt and the high bits of pt
    print("="*100, test_num(ct))
    if test_num(ct) < 64:
        break
    minimum = n//multiples[-1][1]
    maximum = n//(multiples[-1][1] - 1)
    minimum *= multiples[-1][0]
    maximum *=multiples[-1][0]  
    print("-"*100) 
    for a, b in reversed(multiples[:-1]):
        minimum = (n + minimum)// b
        maximum = (n + maximum)// b + 1
        minimum *= a
        maximum *= a 
    print(hex(minimum))
    print(hex(maximum))
    print(bytes.fromhex("0"+hex(minimum)[2:]))
    matched = 0
    for i in range(len(hex(minimum))):
        if hex(minimum)[i] == hex(maximum)[i]:
            matched += 1
        else:
            break
    print("-"*100, 1050*((time.time() - start)/queries), matched) 
    if minimum +2 > maximum:
        break
#print(trial_reduce(ct))
```
```

We now have the flag!

As a note, this script actually fails to correctly get the very last bit of the flag. I assume I have an off by one error somewhere, but I can't really be bothered to fix it at this time.
