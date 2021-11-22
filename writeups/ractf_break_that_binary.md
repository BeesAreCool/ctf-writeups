# Really Awesome CTF - Reversing/Pwn - Break that Binary!

## SSH in to trick a SUID binary to read the flag and leak it.

We found this weird server open on the web running this program. We think we can break it somehow; can you take a look?

## A note on this writeup.

Pretty sure I solved this in an unintended way.

## Triage


After SSHing we can have a quick look at the files present on the server.
```
drwxr-xr-x 2 ractf 1000     52 2021-08-13 16:55 .
drwxr-xr-x 3 root  0        19 2021-08-13 16:55 ..
-rwx------ 1 root  0        34 2021-08-13 16:53 flag.txt
-rwx------ 1 root  0        16 2021-08-13 16:55 keyfile
-rwsr-xr-x 1 root  0    255840 2021-08-13 16:55 program
```

As you can see, the program will have access to both flag.txt and the keyfile. Additionaly, when running the program we receive what is some kind of encrypted output.

```
$ ./program
c0fbd3cc56273250d4b93d74e86d3598e1f970d129b2ce0a1806cb62c1a63782b6344c5c8360f3d4465f2b2370f72da1
$ 
```

Here is a commented decompilation of the program source code.

```
undefined8 main(void) //main does not use any arguments, meaning it is ignoring the command line

{


    int iVar1;
    FILE *file_help;
    size_t flag_length;
    char *big_buffer;
    long q;
    long i;
    ulong j;
    byte *pbVar2;
    byte *pbVar3;
    ulong padded_length;
    long in_FS_OFFSET;
    byte bVar4;
    timeval time_rand;
    undefined ctx [192];
    byte secret_key [16];
    byte key [16];
    undefined iv [16];
    byte flag [64];
    long local_40;
    char *end_of_flag;
    
    bVar4 = 0;
    local_40 = *(long *)(in_FS_OFFSET + 0x28);
    file_help = fopen("flag.txt","r");
    fgets((char *)flag,0x40,file_help);
    fclose(file_help);
    file_help = fopen("keyfile","r");
    fread(secret_key,0x10,1,file_help);
    fclose(file_help);

    //we've now loaded both flag.txt and the keyfile into their corresponding buffers

    flag_length = strlen((char *)flag);
    big_buffer = (char *)default_malloc(0x100000);

    //we malloc a really big buffer to hold the flag. I believe this to be the source of the intended solve.

    padded_length = (flag_length - 1 | 0xf) + 1;

    //Just computes the length of the flag when padded to 16 byte alignment for AES

    if (big_buffer != NULL) {
        strcpy(big_buffer,(char *)flag);
        gettimeofday(&time_rand,NULL);
        srand((int)time_rand.tv_sec * 1000000 + (int)time_rand.tv_usec);

        //Seed our random number generator with MICROSECONDS
        //There are 1 million microseconds per second. This can be brute forced.


        //Watch the variables, we are going to use the key from keyfile XORed with random bytes as the AES key as well as a random byte string as the IV.

        q = 0;
        do {
            iVar1 = rand();
            i = q + 1;
            key[q] = (byte)(iVar1 % 0x100) ^ secret_key[q];
            q = i;

            //This simply generates 16 random bytes and XORs them with each byte in the key from the keyfile for our AES key.

        } while (i != 0x10);
        q = 0;
        do {
            iVar1 = rand();
            iv[q] = (char)(iVar1 % 0x100);
            q += 1;
    
            //This generates our random IV

        } while (q != 0x10);
        flag_length = strlen((char *)flag);
        q = padded_length - flag_length;
        if (padded_length < flag_length) {
            q = 0;
        }
        end_of_flag = big_buffer + flag_length;
        for (; q != 0; q += -1) {
            *end_of_flag = '\0';
            end_of_flag = end_of_flag + (ulong)bVar4 * -2 + 1;
        }

        //This just pads our flag

        AES_init_ctx_iv(ctx,key,iv);
        AES_CBC_encrypt_buffer(ctx,big_buffer,padded_length);

        //The actual encryption

        if ((((flag < big_buffer) && (big_buffer < flag + padded_length)) ||
            ((big_buffer < flag && (flag < big_buffer + padded_length)))) ||
           (j = padded_length, pbVar2 = (byte *)big_buffer, pbVar3 = flag,
           0x40 < padded_length)) {
            do {
                invalidInstructionException();
            } while( true );
        }
        for (; j != 0; j = j - 1) {
            *pbVar3 = *pbVar2;
            pbVar2 = pbVar2 + (ulong)bVar4 * -2 + 1;
            pbVar3 = pbVar3 + (ulong)bVar4 * -2 + 1;
        }

        //This is all an abomination that verifies the encryption succeeded as far as I can tell.
        
    }
    free(big_buffer);

    for (j = 0; j < padded_length; j += 1) {
        printf("%02x",(ulong)flag[j]);

        //Prints out the resulting encrypted stream

    }
    putchar(10);
    if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
        return 0;
    }
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
}
```

### Attack

So, we can trivially brute force the microseconds used to generate the random numbers. However, unless we know the contents of keyfile that is useless. Luckily, its also trivial to determine the contents of keyfile. This is because we can move the keyfile to a different location and *create our own keyfile with contents we choose*.

```
$ mv keyfile keyfile_old
$ echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > keyfile
$ ls -la
total 264
drwxr-xr-x 1 ractf 1000     40 2021-08-16 17:43 .
drwxr-xr-x 1 root  0        19 2021-08-13 16:55 ..
-rwx------ 1 root  0        34 2021-08-13 16:53 flag.txt
-rw-r--r-- 1 ractf 1000     30 2021-08-16 17:43 keyfile
-rwx------ 1 root  0        16 2021-08-13 16:55 keyfile_old
-rwsr-xr-x 1 root  0    255840 2021-08-13 16:55 program
```

We now know the contents of keyfile, and can run the program binary to generate an encrypted keystream with our keyfile. However, we also want to be able to easily brute force the random seed. We can speed this up by determing a lower and upper bound for the team. This is done by running the command `date +%s%6N` to print the time in microseconds before and after we run the program.

```
$ date +%s%6N; ./program; date +%s%6N
1629135961503759
0dad76c19a51427bf53a160ec6dc7a9a75cdfcba651cb94d0b5cb6b89cf8b23487739216f37da8a93b5b8b5fb9c3e5f3
1629135961505135
```

We now have everything we need to crack the flag!

## The script

Because I wanted the random numbers and the encryption to be as close to the target as possible, I copied as much as possible from Ghidra into a C++ program. Additionally, I used TinyAES for the AES encryption since the target program did as well.

```
#include <stdio.h>
#include <string.h>
#include <stdint.h>
//#include <stdlib.h>
#include <iostream>
#define CBC 1

#include "aes.h"

static void test_encrypt_cbc(void);

using namespace std;
unsigned long seed =0;
int rand(void)

{
    seed = seed * 0x5851f42d4c957f2d + 1;
    //cout << seed << endl;
    return (int)(seed >> 0x21);
}
void srand(uint s)

{
    seed = (ulong)(s - 1);
    //cout << seed << endl;
    return;
}
bool test_decrypt(unsigned long seed){

    //Ciphertext value based on the program output
    unsigned char ciphertext[] = "\x0d\xad\x76\xc1\x9a\x51\x42\x7b\xf5\x3a\x16\x0e\xc6\xdc\x7a\x9a\x75\xcd\xfc\xba\x65\x1c\xb9\x4d\x0b\x5c\xb6\xb8\x9c\xf8\xb2\x34\x87\x73\x92\x16\xf3\x7d\xa8\xa9\x3b\x5b\x8b\x5f\xb9\xc3\xe5\xf3";
    int ciphertext_length = 48;
    unsigned char key[] = "AAAAAAAAAAAAAAAA";
    unsigned char iv[16];
    srand(seed);
    for(int q=0; q<0x10; q++){
        int iVar1 = rand();
        key[q] = (char)(iVar1 % 0x100) ^ key[q];
        //cout << hex << iVar1 << dec << endl;
    }
    for(int q=0; q<0x10; q++){
        int iVar1 = rand();
        iv[q] = (char)(iVar1 % 0x100);
    }
    int flag_length = ciphertext_length;
    struct AES_ctx ctx;
    for(int q=0; q<0x10; q++){
        cout << hex << (int) key[q];
    }
    cout << endl;
    for(int q=0; q<0x10; q++){
        cout << hex << (int) iv[q];
    }
    cout << endl;
    cout << key << endl;
    AES_init_ctx_iv(&ctx,key,iv);
    AES_CBC_decrypt_buffer(&ctx,ciphertext,flag_length);
    for(int i=0; i<ciphertext_length-4; i++){
        char * flag = (char *) ciphertext;
        if (flag[i+0] == 'c' && flag[i+1] == 't' && flag[i+2] == 'f'){
            cout << flag << endl;
        }
    }
    //cout << ciphertext << endl;
    return true;
}
int main(void)
{
    int exit=0;

    //Start and end based on the date calls in bash
    unsigned long start = 1629135961503759;
    unsigned long end =   1629135961505135;
    for(unsigned long time = start; time < end; time++){
        test_decrypt(time);
    }
    return exit;
}
```

When running this, it will output every possible combination decrypted. This generates a *lot* of noise. Roughly 1000+ lines of garbage. As an example,

```20bbd96cc9bad55c78250181a4e31c
1014d3186f5bdc7788a1173168fcc
 <BB><D9>lɺ<D5>\^G<82>P^X^A<A4><E3>^\
39a15de341237ccea3fc38f78669d
e122d13c34d1ad427fd558a31b9468e
9
^U<DE>4^R7^LΣ<FC>8<F7><86>i
cfdd4e5023ea183d964328d86debef7b
b13046240a628ccd773814ef5cfc50
<CF><DD>NP#<EA>^X=<96>C(<D8>m<EB><EF>{
e4ac8ac2e427aed5e6054fbe3cc7569
823e7f363dfe37c487e8bb9dadfeb312
䬊<C2>^NBz<ED>^`T<FB><E3><CC>ui
fd7fc7b47d1a5c9a291809b5931fb56
534cb8477a5746bc375d6f276ba16ad4
<FD>^?Ǵ}^Z\<9A>)^A<80><9B>Y1<FB>V
93ce3276bf2414af1212cbbcf12144
235af259b7af54b3e7d322b029432096
<93><CE>^C'k<F2>AJ<F1>!,<BB><CF>^R^AD
a8a1bc99564aa37ab93e585b457487b2
f4672b6bf3863ab9748d53ae7e6d758
<A8><A1><BC><99>VJ<A3>z<B9>>X[Et<87><B2>
```

However, we can make use of grep to narrow in on the output containing "ractf".

```
bee@blackandyellow:~/hackinghobby/ractf$ ./break_that | grep ractf -n10
2125-16bc682d98abec1a6b553fc887f4de5
2126-7b93275444276215a72621b92d24aca
2128-2cfa49f873d1316e52ff9c7e60d3d2
2129-4ba13b87819b8519ae715a5507518c
2131-c5dee111f2db33de39722bbcf44559c0
2132-1caf7598bef39311ba5dc92ee17b74e
2134:ractf{Curb_Y0ur_M3mOry_Alloc4t10n}
2135-dab11d80e0b3158e8113575c6aa6df2e
2136-edbdaeaafb4ca296ad27cb8ccba6e10
grep: (standard input): binary file matches
```

_Memory allocation? What could that be for, this is a crypto and SSH chall not heap pwn!_























#### After credits scene

```
Guy who can't do heap pwn:
    Was it intended that you could replace the keyfile file?
```

```
RACTF staff desperately trying to get people to do heap pwn:
    Huh. No…
    But how does that help
    It gets XORed with random anyway
```

#### Intended solve?

Huge shoutout to "Babaisflag" for telling me this.

You could use ulimit to shrink the maximim allocated memory. By doing this, the malloc call would return 0. This means the encryption is bypassed entirely and the encrypted flag is simply printed with hex encoding. 

```
$ ulimit -Sv 1000000 && ./program
72616374667b437572625f593075725f4d336d4f72795f416c6c6f63347431306e7d0000000000000000000000000000
```
