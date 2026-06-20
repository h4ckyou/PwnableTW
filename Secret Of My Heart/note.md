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

The program is really small, it uses a structure that manages the list of secrets:

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

