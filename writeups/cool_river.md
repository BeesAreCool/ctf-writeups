For the linker injection.

```c
#include <string.h>
#include <stdio.h>

int memcmp(const void *s1, const void *s2, size_t n){
    int i=0;
    for(;i<n; i++){
        if(((char *)s1)[i] != ((char *)s2)[i]){
            printf("Match: %d\n", i);
            return 1;
        }
    }
    printf("Match: %d\n", n);
    return 0;
}
```

For the automatic testing.

```python
from pwn import *
import string

known = ""
for i in range(39):
    for x in string.printable:
        guess = known + x
        guess += (39-len(guess)) * " "
        p = process(["./river", guess], env={"LD_PRELOAD":"/tmp/override.so"})
        p.recvuntil(b"Match: ")
        correct = int(p.recvline().decode("utf-8").strip())
        print(correct)
        p.close()
        if correct > i:
            known += x
            break
        print(known)
print(known)
```
