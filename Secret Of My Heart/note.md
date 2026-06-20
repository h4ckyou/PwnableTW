## Secret Of My Heart

```
mark@rwx:~/Desktop/Labs/PwnableTW/secretofmyheart$ file secret_of_my_heart
secret_of_my_heart: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=123aede7094ecfa8f50b3b34f3b9c754835d4e25, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/secretofmyheart$ checksec secret_of_my_heart
[*] '/home/mark/Desktop/Labs/PwnableTW/secretofmyheart/secret_of_my_heart'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
mark@rwx:~/Desktop/Labs/PwnableTW/secretofmyheart
```

From the menu on executing the program we can tell it's likely a heap challenge

```
mark@rwx:~/Desktop/Labs/PwnableTW/secretofmyheart$ ./secret_of_my_heart
==================================
        Secret of my heart        
==================================
 1. Add a secret                  
 2. show a secret                 
 3. delete a secret               
 4. Exit                          
==================================
Your choice :4
mark@rwx:~/Desktop/Labs/PwnableTW/secretofmyheart$
```
