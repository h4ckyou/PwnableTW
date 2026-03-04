## Bookwriter

```
mark@rwx:~/Desktop/Labs/PwnableTW/bookwriter$ file bookwriter
bookwriter: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8c3e466870c649d07e84498bb143f1bb5916ae34, stripped
mark@rwx:~/Desktop/Labs/PwnableTW/bookwriter$ checksec bookwriter
[*] '/home/mark/Desktop/Labs/PwnableTW/bookwriter/bookwriter'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
```

No PIE enabled

This is a heap challenge as you can tell from the menu

```
mark@rwx:~/Desktop/Labs/PwnableTW/bookwriter$ ./bookwriter
Welcome to the BookWriter !
Author :asdf
----------------------
      BookWriter      
----------------------
 1. Add a page        
 2. View a page       
 3. Edit a page       
 4. Information       
 5. Exit              
----------------------
Your choice :
```

The global variables are defined as this:

```c
char author[64];
char *books[8];
uint32_t sizes[8];
```

The first vulnerabilitiy is at `add_page`

```c
int add_page()
{
  unsigned int i; // [rsp+Ch] [rbp-14h]
  char *ptr; // [rsp+10h] [rbp-10h]
  __int64 size; // [rsp+18h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 8 )
      return puts("You can't add new page anymore!");
    if ( !books[i] )
      break;
  }
  printf("Size of page :");
  size = read_int();
  ptr = (char *)malloc(size);
  if ( !ptr )
  {
    puts("Error !");
    exit(0);
  }
  printf("Content :");
  read_input(ptr, size);
  books[i] = ptr;
  sizes[i] = size;
  ++count;
  return puts("Done !");
}
```

It iterates through [0..9] meaning there's an off by 1, with this if `books[8]` which maps to `sizes[0]` is null then a heap allocation can be stored there.

And during `edit_page` when we use index 0 it would use `books[0] => sizes[0]` and this in turn leads to a heap overflow
