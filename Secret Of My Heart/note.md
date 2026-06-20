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

The program uses a structure that manages the list of secrets:

```c
struct secret_t {
size_t size;
char name[0x20];
char *secret;
}
```

Here's the `main` function

```c
void __fastcall __noreturn main(const char *a1, char **a2, char **a3)
{
  int v3; // eax

  setup();
  while ( 1 )
  {
    while ( 1 )
    {
      show_menu();
      v3 = read_int();
      if ( v3 != 3 )
        break;
      delete_secret();
    }
    if ( v3 > 3 )
    {
      if ( v3 == 4 )
        exit(0);
      if ( v3 == 4869 )
        fake_hack();
LABEL_15:
      puts("Invalid choice");
    }
    else if ( v3 == 1 )
    {
      add_secret();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_15;
      show_secret();
    }
  }
}

__int64 read_int()
{
  char nptr[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( (int)_read_chk(0LL, nptr, 15LL, 15LL) <= 0 )
  {
    puts("read error");
    exit(1);
  }
  return (unsigned int)atoi(nptr);
}
```

The `setup` allocates some region using `mmap`, although that memory region can still be predicted as it uses the current time as seed.

```c
__int64 setup()
{
  unsigned int v0; // eax
  __int64 result; // rax
  signed int v2; // [rsp+Ch] [rbp-4h]

  v2 = 0;
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v0 = time(0LL);
  srand(v0);
  while ( v2 <= 0x10000 )
    v2 = rand() & 0xFFFFF000;
  addr = mmap((void *)v2, 0x1000uLL, 3, 34, -1, 0LL);
  result = addr;
  if ( addr == -1LL )
  {
    puts("mmap error");
    exit(0);
  }
  return result;
}
```

I never ended up using this so I don't know the essence...

There are 3 functionalities.

`add_secret`:

```c
int add_secret()
{
  int i; // [rsp+4h] [rbp-Ch]
  size_t size; // [rsp+8h] [rbp-8h]

  for ( i = 0; ; ++i )
  {
    if ( i > 99 )
      return puts("Fulled !!");
    if ( !addr[0][i].secret )
      break;
  }
  printf("Size of heart : ");
  size = (int)read_int();
  if ( size > 0x100 )
    return puts("Too big !");
  read_metadata(&addr[0][i], size);
  return puts("Done !");
}

char *__fastcall read_metadata(secret_t *addr, size_t size)
{
  char *result; // rax

  addr->size = size;
  printf("Name of heart :");
  read_str(addr->name, 32u);
  addr->secret = (char *)malloc(size);
  if ( !addr->secret )
  {
    puts("Allocate Error !");
    exit(0);
  }
  printf("secret of my heart :");
  result = &addr->secret[(int)read_str(addr->secret, size)];
  *result = 0;
  return result;
}
```

`show_secret`:

```c
int show_secret()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h]

  printf("Index :");
  idx = read_int();
  if ( idx > 99 )
  {
    puts("Out of bound !");
    exit(-2);
  }
  if ( !addr[0][idx].secret )
    return puts("No such heap !");
  printf("Index : %d\n", idx);
  printf("Size : %lu\n", addr[0][idx].size);
  printf("Name : %s\n", addr[0][idx].name);
  return printf("Secret : %s\n", addr[0][idx].secret);
}
```

`delete_secret`:

```c
int delete_secret()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  printf("Index :");
  v1 = read_int();
  if ( v1 > 99 )
  {
    puts("Out of bound !");
    exit(-2);
  }
  if ( !addr[0][v1].secret )
    return puts("No such heap !");
  free_metadata(&addr[0][v1]);
  return puts("Done !");
}

void *__fastcall free_metadata(secret_t *addr)
{
  void *result; // rax

  addr->size = 0LL;
  memset(addr->name, 0, sizeof(addr->name));
  free(addr->secret);
  result = addr;
  addr->secret = 0LL;
  return result;
}
```

The vulnerability is an off-by-null bug.

We are on `glibc 2.23`

```
mark@rwx:~/Desktop/Labs/PwnableTW/secretofmyheart$ ./ld-2.23.so ./libc.so.6 
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu5) stable release version 2.23, by Roland McGrath et al.
Copyright (C) 2016 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.
There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.
Compiled by GNU CC version 5.4.0 20160609.
Available extensions:
	crypt add-on version 2.1 by Michael Glad and others
	GNU Libidn by Simon Josefsson
	Native POSIX Threads Library by Ulrich Drepper et al
	BIND-8.2.3-T5B
libc ABIs: UNIQUE IFUNC
For bug reporting instructions, please see:
<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.
mark@rwx:~/Desktop/Labs/PwnableTW/secretofmyheart$
```

My plan was to first get a heap leak, we can easily achieve that by setting `secret.name` to `32` then we print the details out, as it doesn't null terminate we end up getting the adjacent data in memory which is a pointer to a heap region.

Next step was to get libc leak.

After looking at various people solve scripts on solving it, i realized that i overcomplicated my solution.

Anyways, I used the off by null to corrupt the `prev_inuse` bit flag of a chunk then consolidated the chunk with an inuse chunk.

That itself made the chunk seem like an unsorted bin chunk (the fd/bk pointed to some libc region) while still in use.

In order to pass this check in the glibc src for backward consolidation:

```c
#define unlink(AV, P, BK, FD) {                                            \
    FD = P->fd;								      \
    BK = P->bk;								      \
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      \
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
```

I had my chunks arranged this way:

```
gef> vis -n
0x5fb0f8131000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000041 | ........A....... |                                                                                                 
0x5fb0f8131010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000031 | ........1....... |
0x5fb0f8131020|+0x00020|+0x00020: 0x00005fb0f8131018 0x00005fb0f8131020 | ....._.. ...._.. |
0x5fb0f8131030|+0x00030|+0x00030: 0x00005fb0f8131010 0x4141414141414141 | ....._..AAAAAAAA |
0x5fb0f8131040|+0x00000|+0x00040: 0x0000000000000030 0x0000000000000100 | 0............... |
0x5fb0f8131050|+0x00010|+0x00050: 0x4242424242424242 0x0000000000000000 | BBBBBBBB........ |
0x5fb0f8131060|+0x00020|+0x00060: 0x0000000000000000 0x0000000000000000 | ................ |
* 13 lines, 0xd0 bytes
0x5fb0f8131140|+0x00000|+0x00140: 0x0000000000000000 0x0000000000000071 | ........q....... |
0x5fb0f8131150|+0x00010|+0x00150: 0x4141414141414141 0x4141414141414141 | AAAAAAAAAAAAAAAA |
0x5fb0f8131160|+0x00020|+0x00160: 0x4141414141414141 0x0000000000000000 | AAAAAAAA........ |
0x5fb0f8131170|+0x00030|+0x00170: 0x0000000000000000 0x0000000000000000 | ................ |
0x5fb0f8131180|+0x00040|+0x00180: 0x0000000000000000 0x0000000000000000 | ................ |
0x5fb0f8131190|+0x00050|+0x00190: 0x0000000000000000 0x0000000000000000 | ................ |
0x5fb0f81311a0|+0x00060|+0x001a0: 0x0000000000000000 0x0000000000000000 | ................ |
0x5fb0f81311b0|+0x00000|+0x001b0: 0x0000000000000000 0x0000000000020e51 | ........Q....... |  <-  top
0x5fb0f81311c0|+0x00010|+0x001c0: 0x0000000000000000 0x0000000000000000 | ................ |
* 8419 lines, 0x20e30 bytes
gef> 
```

With this, even after free we can't actually get the leak directly (?)

```
gef> vis -n
0x610dadf1a000|+0x00000|+0x00000: 0x0000000000000000 0x0000000000000041 | ........A....... |                                                                                                 
0x610dadf1a010|+0x00010|+0x00010: 0x0000000000000000 0x0000000000000131 | ........1....... |  <-  unsortedbins[1/1]
0x610dadf1a020|+0x00020|+0x00020: 0x00007c7360dc3b78 0x00007c7360dc3b78 | x;.`s|..x;.`s|.. |
0x610dadf1a030|+0x00030|+0x00030: 0x0000610dadf1a018 0x4141414141414141 | .....a..AAAAAAAA |
0x610dadf1a040|+0x00000|+0x00040: 0x0000000000000030 0x0000000000000100 | 0............... |
0x610dadf1a050|+0x00010|+0x00050: 0x4242424242424242 0x0000000000000000 | BBBBBBBB........ |
0x610dadf1a060|+0x00020|+0x00060: 0x0000000000000000 0x0000000000000000 | ................ |
* 13 lines, 0xd0 bytes
0x610dadf1a140|+0x00000|+0x00140: 0x0000000000000130 0x0000000000000070 | 0.......p....... |
0x610dadf1a150|+0x00010|+0x00150: 0x4141414141414141 0x4141414141414141 | AAAAAAAAAAAAAAAA |
0x610dadf1a160|+0x00020|+0x00160: 0x4141414141414141 0x0000000000000000 | AAAAAAAA........ |
0x610dadf1a170|+0x00030|+0x00170: 0x0000000000000000 0x0000000000000000 | ................ |
0x610dadf1a180|+0x00040|+0x00180: 0x0000000000000000 0x0000000000000000 | ................ |
0x610dadf1a190|+0x00050|+0x00190: 0x0000000000000000 0x0000000000000000 | ................ |
0x610dadf1a1a0|+0x00060|+0x001a0: 0x0000000000000000 0x0000000000000000 | ................ |
0x610dadf1a1b0|+0x00000|+0x001b0: 0x0000000000000000 0x0000000000020e51 | ........Q....... |  <-  top
0x610dadf1a1c0|+0x00010|+0x001c0: 0x0000000000000000 0x0000000000000000 | ................ |
* 8419 lines, 0x20e30 bytes
gef>
```

This is because `printf` stops at a null byte and before the libc pointer there are null bytes.

Another idea was to free that chunk and reallocate it back then pad with A's so that i would get the leak after printing. But this doesn't work because of the null termination it does lmao.

```c
  result = &addr->secret[(int)read_str(addr->secret, size)];
  *result = 0;
```

To go around this, I leveraged the remaindering property to get the leak + create a UAF primitive.

After exploiting fastbin dup, i got overlapping allocation to `_IO_list_all` and did `FSOP`.
