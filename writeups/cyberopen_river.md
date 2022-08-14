# CyberOpen Season II - River - Reverse Engineering Writeup

As an initial inspection we can run the `file` linux utility on the downloaded binary. That shows us this is a stand linux ELF executable, for the x86_64 architecture.

```
river: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=c252344a81d465fbde8abb015e518cf94a6ae003, not stripped
```

With this, we know the best tool for the job is a decompiler that can tackle linux binaries. Ghidra is currently the industry standard free decompiler, so we'll be using this to understand the inner workings of river.


## Decompiling

This binary was not stripped of debug symbols, so we can quickly identify the main function as well as internal function. Looking at the start of river we see the following initially.

```c
    local_10 = *(long *)(in_FS_OFFSET + 0x28);
    if (1 < param_1) {
        sVar3 = strlen(*(char **)(param_2 + 8));
        if (sVar3 == 0x27) {
            pipe(&local_88);
            pipe(&local_80);
            pipe(&local_78);
            pipe(&local_70);
            local_e4 = fork();
```

This initial snippet of code does several things. Firstly, the `local_10 = *(long *)(in_FS_OFFSET + 0x28)` segment is a common stack canary paradigm. The location of local\_10, 0x10 bytes from the top of the stack, means that a stack based buffer overflow almost anywhere would overwrite the canary. Additionally, the location of `*(long *)(in_FS_OFFSET + 0x28)` contains a pseudo random value that is hard to guess, and is hard to overwrite or alter. Since this is not a binary exploitation challenge, the canary is largely irrelevant and can be ignored.

Following, `param_1` is compared to 1. The first paramater of the main function in standard libc compiled binaries should always be argc, or the number of command line arguments, so we're checking if 2 or more arguments were passed *including the name of the binary*. So an example valid call would be `./river password`. Additionally, strlen is then called on `param_2+8`. 

Furthermore, the pipe function sets up "pipes" that can be used for interprocess communication. Each call creates an input and an output pipe, that can be read from and written to respectively. This will allow the program to pass data around after forking. Additionally, the variables pipe is called on appear to be in a sequence, storing them in an array would likely simplify the representation.

Finally, fork is called. Fork will essentially copy the process, meaning the process will be running twice. The returned value of fork will allow the process to know if it is the original process or the "forked" version. It is likely the forked process will attempt to communicate with the original "parent" process through the shared pipes.

We can make this more clear by adding a struct to represent the pipe file descriptor as well as by adding names to relevant variables.

```c
    canary_ = *(long *)(in_FS_OFFSET + 0x28);
    if (1 < argc) {
        length = strlen(argv[1]);
        if (length == 0x27) {
            pipe(&pipes[0].in);
            pipe(&pipes[1].in);
            pipe(&pipes[2].in);
            pipe(&pipes[3].in);
            fork_id_1 = fork();
```

We then have the following code. This is a part of 5 unordered segments that move into their correct order through multiprocess metholodology. I cover them in the order they appear in the code, and then roughly reconstruct the correct order based on the pipes.

```c
            if (fork_id_1 == 0) {
                close(pipes[0].out);
                close(pipes[1].in);
                close(pipes[1].out);
                close(pipes[2].in);
                close(pipes[2].out);
                close(pipes[3].in);
                last_byte = 0;
                while( true ) {
                    read_in_1 = read(pipes[0].in,needed,0x27);
     /* This xors each byte by the byte seen before */
                    if ((long)read_in_1 < 1) break;
                    for (i = 0; i < (long)read_in_1; i += 1) {
                        needed[i] = needed[i] ^ last_byte;
                        last_byte = needed[i];
                    }
                    write(pipes[3].out,needed,read_in_1);
                }
                close(pipes[3].out);
     /* WARNING: Subroutine does not return */
                exit(0);
            }
```

Firstly, the result of fork is checked. Fork will return 0 if  the program appears to close unnecesary pipes that it won't use in this forked version. It then reads in from pipe #0, processes the data, and writes it to pipe #3. The actual processing appears to be a fairly straightforward rolling XOR cipher, where each byte is XORed by the previous byte. After editing the data and passing it through the pipes the process exits.

```c
            fork_id_2 = fork();
            if (fork_id_2 == 0) {
                close(pipes[0].in);
                close(pipes[0].out);
                close(pipes[1].in);
                close(pipes[1].out);
                close(pipes[2].out);
                close(pipes[3].in);
                close(pipes[3].out);
                needed[0] = 0x99;
                needed[1] = 0x69;
                needed[2] = 0x3b;
//many lines cut out
                needed[37] = 0x61;
                needed[38] = 0x9a;
                to_read = 0x27;
                result_ptr = result;
                while( true ) {
                    read_bytes = read(pipes[2].in,result_ptr,to_read);
                    if (read_bytes < 1) break;
                    to_read -= read_bytes;
                    result_ptr = result_ptr + read_bytes;
                }
                flag_correct = memcmp(result,needed,0x27);
                if (flag_correct == 0) {
                    puts("Correct!!");
                }
                else {
                    puts("Wrong!!");
                }
     /* WARNING: Subroutine does not return */
                exit(0);
            }
```

The next segment reads in from pipe #2 and then places what is read into a buffer located at the variable `result`. This buffer is then compared to a long stack string of bytes using memcmp. Memcmp will check the first 0x27 bytes and if they match set the flag_correct variable accordingly. So essentially, the contents of pipe #2 must match these known "end" bytes.

```c
            forked_id_3 = fork();
            if (forked_id_3 == 0) {
                close(pipes[0].in);
                close(pipes[1].out);
                close(pipes[2].in);
                close(pipes[2].out);
                close(pipes[3].in);
                close(pipes[3].out);
                while( true ) {
                    read_in = read(pipes[1].in,needed,0x27);
                    if ((long)read_in < 1) break;
                    for (q = 0; q < (long)read_in; q += 1) {
                        needed[q] = needed[q] ^ 0x56;
                    }
                    write(pipes[0].out,needed,read_in);
                }
                close(pipes[0].out);
     /* WARNING: Subroutine does not return */
                exit(0);
            }
```

We have another repeat of the forking methodology again. This time, it appears to read from pipe #1 and write to pipe #0. This time it appears to be a simple constant XOR operation applied to every byte.

```c         
            forked_id_4 = fork();
            if (forked_id_4 == 0) {
                close(pipes[0].in);
                close(pipes[0].out);
                close(pipes[1].in);
                close(pipes[2].in);
                close(pipes[2].out);
                close(pipes[3].in);
                close(pipes[3].out);
                length = strlen(argv[1]);
                write(pipes[1].out,argv[1],length);
                close(pipes[1].out);
     /* WARNING: Subroutine does not return */
                exit(0);
            }
```

This segment simply takes the command line argument passed in and simply writes it to pipe #1 without alteration. It appears that the data enters in through pipe #1.

```c
            forked_id_5 = fork();
            if (forked_id_5 == 0) {
                close(pipes[0].in);
                close(pipes[0].out);
                close(pipes[1].in);
                close(pipes[1].out);
                close(pipes[2].in);
                close(pipes[3].out);
                needed[0] = 0xbb;
                needed[1] = 0x55;
                needed[2] = 0x62;
                needed[3] = 0xac;
             /* many more array elements */
                needed[36] = 0xfa;
                needed[37] = 0x75;
                needed[38] = 0xba;
                byte_counter = 0;
                while( true ) {
                    read_count = read(pipes[3].in,result,0x27);
                    if ((long)read_count < 1) break;
                    for (j = 0; j < (long)read_count; j += 1) {
                        counter_helper = byte_counter + 1;
                        result[j] = needed[byte_counter] ^ result[j];
                        byte_counter = counter_helper;
                        if (counter_helper == 0x27) {
                            byte_counter = 0;
                        }
                    }
                    write(pipes[2].out,result,read_count);
                }
                close(pipes[2].out);
     /* WARNING: Subroutine does not return */
                exit(0);
         }
```

This fifth and final segment is a traditional XOR of a "key" byte array by a "plaintext" array. The first byte of the key array is xored by the first byte of the plaintext array, then the second byte of the key array is xored by the second byte of the plaintext array. If the plaintext is longer than the key, the key will loop around when it exhausts its bytes. However, the key appears to be the same length as the plaintext so we shouldn't have an issue. This appears to take its data from pipe #3 and write to pipe #2. 

## Putting it all together

We know the program goes through the pipes in the following order, #1 -> #0 - > #3 -> #2 -> end. With this information we can reassemble the code in river into the following pseudocode.

```c
read_input(input)
constant_xor(input, 0x56)
rolling_xor(input)
key_based_xor(input, key)
check_input(input, goal)
```

Luckily, most of these functions can be easily inversed. Most of these functions can simply be ran again in order to inverse their contents. The only function that needs to be modified is the rolling xor, which needs to be slightly rearrange.

To solve, I implemented the inverse of these functions in python that implements the "inverse" functions and essentially runs the programs flow in reverse.

```python
def get_goal():
    needed = [0]*0x27
    needed[0] = 0x99;
    needed[1] = 0x69;
    needed[2] = 0x3b;
    needed[3] = 0xfc;
    needed[4] = 0x9d;
    needed[5] = 0x1a;
    needed[6] = 0xa0;
    needed[7] = 0x19;
    needed[8] = 0xd3;
    needed[9] = 0xa9;
    needed[10] = 0x87;
    needed[11] = 0xdd;
    needed[12] = 0x82;
    needed[13] = 0xca;
    needed[14] = 0x61;
    needed[15] = 0x38;
    needed[16] = 0xff;
    needed[17] = 0x55;
    needed[18] = 0x5e;
    needed[19] = 0xce;
    needed[20] = 0xaf;
    needed[21] = 0x9c;
    needed[22] = 0xa6;
    needed[23] = 0xd;
    needed[24] = 0xd3;
    needed[25] = 100;
    needed[26] = 0x9a;
    needed[27] = 0xea;
    needed[28] = 0x27;
    needed[29] = 0x86;
    needed[30] = 0x6f;
    needed[31] = 0x7f;
    needed[32] = 1;
    needed[33] = 0xe0;
    needed[34] = 0xad;
    needed[35] = 0x48;
    needed[36] = 0xdd;
    needed[37] = 0x61;
    needed[38] = 0x9a;
    return needed
    
def get_key():
    needed = [0]*0x27
    needed[0] = 0xbb;
    needed[1] = 0x55;
    needed[2] = 0x62;
    needed[3] = 0xac;
    needed[4] = 0xfc;
    needed[5] = 0x5f;
    needed[6] = 0x80;
    needed[7] = 0x5b;
    needed[8] = 0xb3;
    needed[9] = 0xc0;
    needed[10] = 0xea;
    needed[11] = 0xd7;
    needed[12] = 0xa8;
    needed[13] = 0x85;
    needed[14] = 10;
    needed[15] = 0x5a;
    needed[16] = 0xf8;
    needed[17] = 0x66;
    needed[18] = 0x59;
    needed[19] = 0xaa;
    needed[20] = 0xc2;
    needed[21] = 0x93;
    needed[22] = 0x91;
    needed[23] = 0x28;
    needed[24] = 0xff;
    needed[25] = 0x78;
    needed[26] = 0x9c;
    needed[27] = 0x8a;
    needed[28] = 0x66;
    needed[29] = 0xa4;
    needed[30] = 0x44;
    needed[31] = 0x3a;
    needed[32] = 0x73;
    needed[33] = 0xf7;
    needed[34] = 0x8f;
    needed[35] = 8;
    needed[36] = 0xfa;
    needed[37] = 0x75;
    needed[38] = 0xba;
    return needed

def rolling_xor_inverse(input_arr):
    last = 0
    for i in range(len(input_arr)):
        before = input_arr[i]
        last = last ^ input_arr[i]
        input_arr[i] = last
        last = before
    
def key_based_xor(input_arr, key_arr):
    for i in range(len(input_arr)):
        input_arr[i] ^= key_arr[i % len(key_arr)]
        
def constant_xor(input_arr, constant):
    for i in range(len(input_arr)):
        input_arr[i] ^= constant
    
current = get_goal()
key_based_xor(current, get_key())
rolling_xor_inverse(current)
constant_xor(current, 0x56)
print(bytes(current))
```

Running, we get the flag `tH3_gr34t_R1v3r_3bb5_4nD_fL0w5_8a3c41eb`.
