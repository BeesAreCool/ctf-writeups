# THCon21 - Cryptography - Kidsign

## Weak Elgamal signature generation due to poor generator choice, research heavy

My son Gamal just learnt how to sign!

    nc remote1.thcon.party 11002
    nc remote2.thcon.party 11002

Files :

    server.py

Creator : $in (Discord : $in#8929)


## Triage

Gamal is likely a reference to ElGamal, you can find this by googling `gamal cryptography`. ElGamal an encryption scheme that is based on modular exponentiation, so it is very similar to RSA and most RSA math will apply in this case. This is also ElGamal signing rather than encryption, which is very similar to DSA. However, it is notably not used very frequently. That is because it quite simply is harder to screw up and have insecure.

## Source Code Analysis

The following source code has been commented on by myself extensively to explain different parts.

```python
from Crypto.Util.number import  inverse, isPrime
from random import SystemRandom
from hashlib import sha256
from flag import FLAG
import os

rand = SystemRandom()

class ElGamal:
	def __init__(self):
        # q is a constant value and always the same
		self.q = 89666094075799358333912553751544914665545515386283824011992558231120286657213785559151513056027280869020616111209289142073255564770995469726364925295894316484503027288982119436576308594740674437582226015660087863550818792499346330713413631956572604302171842281106323020998625124370502577704273068156073608681
		assert(isPrime(self.q))
        # p is our main prime, basically everything is modulus p
		self.p = 2*self.q + 1
		assert(isPrime(self.p))
        # g is our generator point, in ElGamal signing it should NOT be 2. See the exploitation later!
		self.g = 2
        # Our hashing algorithm of choice
		self.H = sha256
        # X is the random number that forms our "private key"
		self.x = rand.randint(1,self.p-2)
        # Y is our "public key"
		self.y = pow(self.g,self.x,self.p)

    # Standard elgamal signature fluff
	def sign(self,m):
		k = rand.randint(2,self.p-2)
		while GCD(k,self.p-1) != 1:
			k = rand.randint(2,self.p-2)
		r = pow(self.g,k,self.p)
		h = int(self.H(m).hexdigest(),16)
		s = ((h - self.x * r)* inverse(k,self.p-1)) % (self.p - 1)
		assert(s != 0)
		return (r,s)

    # Standard elgamal signature verification fluff
	def verify(self,m,r,s):
        # NOTE, it checks that R and S are within the bounds of P, this limits the kinds of attack we can do
		if r <= 0 or r >= (self.p):
			return False
		if s <= 0 or s >= (self.p-1):
			return False
		h = int(self.H(m).hexdigest(),16)
		return pow(self.g,h,self.p) == (pow(self.y,r,self.p) * pow(r,s,self.p)) % self.p



if __name__ == '__main__':
	S = ElGamal()
    # The information we get told
	print("Here are your parameters:\n - generator g: {:d}\n - prime p: {:d}\n - public key y: {:d}\n".format(S.g, S.p, S.y))
	# 16 random bytes we need to sign
	message = os.urandom(16)

	print("If you can sign this message : {:s}, I'll reward you with a flag!".format(message.hex()))
    # Our R, S pair
	r = int(input("r: "))
	s = int(input("s: "))
	if S.verify(message,r,s):
		print(FLAG)
	else:
		print("Nope.")
```

## Flaw hunting

So we have several kinds of possible vulnerabilities I researched. In order:

- The wikipedia page for ElGamal signature scheme. This noted a security problem posed when know hash algorithm is specified and when you can choose what is signed. This is not our case.
- Unusually weak q or p choice. I googled the numbers, no results. Also verified they were prime with factordb.
- `2*q + 1`, or rather p and q being similar bit lengths. I remembered how in DSA these numbers are very different size wise. Turns out this wasn't the problem.
- `g = 2`, initial attempts were searching for an algorithm to quickly compute the dlog problem with respect to base 2. However, these rabbit holes eventually lead to ElGamal specific vulnerabilities with weak generators! 

### So G = 2

Search for "elgamal signature scheme forgery" and go through a page or two. You'll likely find the Bleichenbacher '96 papers on "Generating ElGamal signatures without knowing the secret key". If you don't, [here's a link](https://crypto.ethz.ch/publications/files/Bleich96.pdf). 

Reading the paper section 3 is what interests us. What is most impotant is Corollary 2, paraphrased here since some variables are represented differently.

`If g is smooth and divides p - 1 then it is possible to generate a valid ElGamal signature on an arbitrary value h if p = 1 (mod 4) and one half of the value 0 <= h < p if p = 3 mod (4).`

As a quick reminder, smooth numbers are numbers whose largest prime divisor is below some given value. 2 is basically as smooth as it gets with its largest prime factor being 2, the smallest "true"  prime.

Additionally, since `p = 2 * q - 1` we know `p - 1 = q * 1`. So we know our generator g is both smooth and divides p-1. That means this is almost certainly the correct set of formulas! However, I was not able to fully understand this paper, it was a bit too technical for me so I went looking elsewhere for this kind of attack.

I proceeded to go through more results as I search for `elgamal signature scheme generator of 2` which  led me to [this stackoverflow question](https://stackoverflow.com/questions/4506618/finding-a-generator-for-elgamal) on choosing a generator. One of the answers mentioned that the Handbook on Applied Cryptography mentions this exact vulnerability! I've previously referenced the HAC, and it is honestly one of the better textbooks to reference for CTF crypto. It is also available free online as PDFs. This chapter in particular is located [here](http://cacr.uwaterloo.ca/hac/about/chap11.pdf). Section 11.67 talks about the same kind of forgery as the Bleich96 paper, but it is explained easier with 4 simple steps to forge a signature! We'll be using those in the exploit

#### Side not about p mod 4

P is meant to be equal to 3 mod 4 in the HAC textbook. It is actually 3 mod 4 in this case. Don't worry about that, its inconvenient and theoretically makes this more unreliable but the solve still works.

## The exploit

I should now be able to follow the steps from the handbook in sagemath. So, I went ahead and netcatted in to the server instance.

```
Here are your parameters:
 - generator g: 2
 - prime p: 179332188151598716667825107503089829331091030772567648023985116462240573314427571118303026112054561738041232222418578284146511129541990939452729850591788632969006054577964238873152617189481348875164452031320175727101637584998692661426827263913145208604343684562212646041997250248741005155408546136312147217363
 - public key y: 34081586000739939996115771539774994345931035078520605361422412405251037539381460825503457004925484740745755926009396227236691079428299165482232451609521554262734199516793148504136719001952496591827324596200760455234870561112565074197603718594999473783000828249007202996802120629462265822461301643280581662024

If you can sign this message : c91a0b0012b89100a4ef684a76ff80d2, I'll reward you with a flag!
r: 
```

I went ahead and converted this into a relevant python snippet to prime all the variables I need. Remember what q is equal to from earlier.


```python
from hashlib import sha256

g = 2
p = 179332188151598716667825107503089829331091030772567648023985116462240573314427571118303026112054561738041232222418578284146511129541990939452729850591788632969006054577964238873152617189481348875164452031320175727101637584998692661426827263913145208604343684562212646041997250248741005155408546136312147217363
q = (p-1) // 2
y = 34081586000739939996115771539774994345931035078520605361422412405251037539381460825503457004925484740745755926009396227236691079428299165482232451609521554262734199516793148504136719001952496591827324596200760455234870561112565074197603718594999473783000828249007202996802120629462265822461301643280581662024
m = bytes.fromhex("c91a0b0012b89100a4ef684a76ff80d2")
h = int(sha256(m).hexdigest(),16)
```

- (a)  Compute `t=(p−3)/2` and set `r=q`.

This is easy math, we just go ahead and solve for t with

```python
t = (p-3)//2
r = q

```

- (b)  Determine `z` such that `a^(qz)=y^q(mod p)` where `y` is A’s public key. (This is possible since `q` and `y^q` are elements of `S` and `q` is a generator of `S`.)


To get z I used sagemaths log function over a modular field. However, it is important to note that is likely either 0 or 1. This is very useful for faster computation. I used log here only for demonstrative purposes. Also, remember that `a` in this case represents the generator, and our generator is represented as `g` in the code. I *believe* that z needs to be 1 for this to be solveable, but I may be wrong. If z wasn't equal to 1, I simply reconnected to the server and got a new `y` value.

```python
P = Zmod(p)
g_q = pow(g, q, p)
y_q = pow(y, q, p)
Y_Q = P(y_q)
z = Y_Q.log(g_q)
```

- (c)  Compute `s=t*(h(m)−qz) mod (p−1)`.

Relatively straightforward math go ahead and plug the math in to get your answer. 

```python
s = (t*(h-q*z)) % (p-1)
```

- (d) (`r`, `s`)is a signature on `m` which will be accepted by step 2 of Algorithm 11.64.

In this sample case, we now have an r value of `89666094075799358333912553751544914665545515386283824011992558231120286657213785559151513056027280869020616111209289142073255564770995469726364925295894316484503027288982119436576308594740674437582226015660087863550818792499346330713413631956572604302171842281106323020998625124370502577704273068156073608681` and an s value of `89666094075799358333912553751544914665545515386283824011992558231120286657213785559151513056027280869020616111209289142073255564770995469726364925295894316484503027288982119436576308594740674437582226015660087863550818792499346330683091718379006509656355738565844215748290441574045797060298979707077071173892`. I can enter these in to the netcat server which succesfully solves the mssage and outputs the flag.

```python
If you can sign this message : c91a0b0012b89100a4ef684a76ff80d2, I'll reward you with a flag!
r: 89666094075799358333912553751544914665545515386283824011992558231120286657213785559151513056027280869020616111209289142073255564770995469726364925295894316484503027288982119436576308594740674437582226015660087863550818792499346330713413631956572604302171842281106323020998625124370502577704273068156073608681
s: 89666094075799358333912553751544914665545515386283824011992558231120286657213785559151513056027280869020616111209289142073255564770995469726364925295894316484503027288982119436576308594740674437582226015660087863550818792499346330683091718379006509656355738565844215748290441574045797060298979707077071173892
b'THCon21{The_re4l_3l_Gam4l_blacksm1th}'
```

_This does not work every time_! You may need to do the math multiple times. This is because only around half of the messages are forgeable with this method and not all public keys work well. You should have a success in around 5 attempts.
