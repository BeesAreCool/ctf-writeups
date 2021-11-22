# HackTheBox University Qualifiers - Crypto - Waiting List!

## Cheese an ECDSA solve or do big complex lattice stuff

Your mechanical arm needs to be replaced. Unfortunately, Steamshake Inc which is the top mechanical arm transplants has a long waiting list. You have found a SQL injection vulnerability and recovered two tables from their database. Could you take advantage of the information in there to speed things up? Don't forget, you have a date on Monday!

## A quick note

I cheesed this solve. There is a big proper solve that does fancy lattice equations to recover the hidden key based on converting everything into a close vector problem. However, after spending several hours trying to get that to work I found a way to avoid all that.

## Triage

The summary of the challenge is we are given 3 files, a signature generator/checker, a list of things that got signed, and the signatures with their corresponding values for the least significant bits of the nonce. We don't need any of that, we just care about the verification of signatures.

```python
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

def verify(self, pt, sig_r, sig_s):

		h = sha1(pt).digest()
		h = bytes_to_long(h)
		h = bin(h)[2:]
		h = int(h[:len(bin(self.n)[2:])], 2)
		sig_r = int(sig_r, 16)
		sig_s = int(sig_s, 16)
		
		c = inverse(sig_s, self.n)
		k = (c *(h +self.key*sig_r)) %self.n
		
		if sig_r== pow(self.g,k,self.n ):
			if pt ==b'william;yarmouth;22-11-2021;09:00':
				return 'Your appointment has been confirmed, congratulations!\n' +\
						'Here is your flag: ' + FLAG
			else:
				return 'Your appointment has been confirmed!\n'
		else: return 'Signature is not valid\n'
```

So, we just need to satisfy the equation `r = 5^((h+x*r)/s) mod n` where x is the secret key and h is a known constant based on what we are signing. 

### Attack

To solve `r = 5^((h+x*r)/s)` the simplest method is to make `((h+x*r)/s)` equate to 0. Since this equation is doing the division by using pycryptodomes inverse, I do some light fuzzing to see what it does when it is given a value that does not have an inverse.
```
>>> inverse(0,13)
0
```
Cool, when an inverse can't be found, it returns 0. That means `((h+x*r)/s)` will equal 0 if s does not have an inverse mod n.

Knowing that g (5) will always be raised to the power of 0 regardless of the private key, we know that we can set r to 1 to always match it. 

This means we can now sign anything with `r=1` and `s=0`.

Getting the solve from the server was pretty easy from here, just had to figure out the formatting with json to satisfy the server.

```
Welcome to the SteamShake transplant clinic where our mission is to deliver the most vintage and high tech arms worldwide.
Please use your signature to verify and confirm your appointment.
Estimated waiting for next appointment: 14 months
>{"pt":"william;yarmouth;22-11-2021;09:00", "r":"1", "s":"0"}
Your appointment has been confirmed, congratulations!
Here is your flag: HTB{t3ll_m3_y0ur_s3cr37_w17h0u7_t3ll1n9_m3_y0ur_s3cr37_15bf7w}
```

We now have the flag!

## Post-solve big ideas

Why do long solve when short solve work as good? DSA needs to have constrains on R and S values
