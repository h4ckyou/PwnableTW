## Applestore

```
mark@rwx:~/Desktop/Labs/PwnableTW/applestore$ file applestore
applestore: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=35f3890fc458c22154fbc1d65e9108a6c8738111, not stripped
mark@rwx:~/Desktop/Labs/PwnableTW/applestore$ checksec applestore
[*] '/home/mark/Desktop/Labs/PwnableTW/applestore/applestore'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Here's the structure made use of:

```c
00000000 struct phone_t // sizeof=0x10
00000000 {                                       // XREF: .bss:myCart/r
00000000     char *name;
00000004     int price __hex;
00000008     phone_t *next;                      // XREF: delete+18/r cart+61/r
0000000C     phone_t *prev;
00000010 };
```

The vulnerabilitiy is at `checkout`:

```c
unsigned int checkout()
{
  int sum; // [esp+10h] [ebp-28h]
  phone_t *mem; // [esp+18h] [ebp-20h] BYREF
  int v3; // [esp+1Ch] [ebp-1Ch]
  unsigned int v4; // [esp+2Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  sum = cart();
  if ( sum == 7174 )
  {
    puts("*: iPhone 8 - $1");
    asprintf(&mem, "%s", "iPhone 8");
    v3 = 1;
    insert(&mem);
    sum = 0x1C07;
  }
  printf("Total: $%d\n", sum);
  puts("Want to checkout? Maybe next time!");
  return __readgsdword(0x14u) ^ v4;
}

int cart()
{
  int idx; // eax
  int list_idx; // [esp+18h] [ebp-30h]
  int sum; // [esp+1Ch] [ebp-2Ch]
  phone_t *current; // [esp+20h] [ebp-28h]
  char buf[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  list_idx = 1;
  sum = 0;
  printf("Let me check your cart. ok? (y/n) > ");
  fflush(stdout);
  my_read(buf, 21u);
  if ( buf[0] == 'y' )
  {
    puts("==== Cart ====");
    for ( current = myCart.next; current; current = current->next )
    {
      idx = list_idx++;
      printf("%d: %s - $%d\n", idx, current->name, current->price);
      sum += current->price;
    }
  }
  return sum;
}
```

`mem` isn't initialized so it uses the previous stack frame values, and it happens that `next` holds a pointer to a user controllable buffer.

Also it happens to be that `current->name` is a pointer to some libc region, so libc leak gotten!

Using this we can insert the `current` address into the previous node's next pointer.

From there we can gain arb write via the `delete` function.

```c
unsigned int delete()
{
  int list_idx; // [esp+10h] [ebp-38h]
  phone_t *current; // [esp+14h] [ebp-34h]
  int user_idx; // [esp+18h] [ebp-30h]
  phone_t *next; // [esp+1Ch] [ebp-2Ch]
  phone_t *prev; // [esp+20h] [ebp-28h]
  char nptr[22]; // [esp+26h] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-Ch]

  v7 = __readgsdword(0x14u);
  list_idx = 1;
  current = myCart.next;
  printf("Item Number> ");
  fflush(stdout);
  my_read(nptr, 21u);
  user_idx = atoi(nptr);
  while ( current )
  {
    if ( list_idx == user_idx )
    {
      next = current->next;
      prev = current->prev;
      if ( prev )
        prev->next = next;
      if ( next )
        next->prev = prev;
      printf("Remove %d:%s from your shopping cart.\n", list_idx, current->name);
      return __readgsdword(0x14u) ^ v7;
    }
    ++list_idx;
    current = current->next;
  }
  return __readgsdword(0x14u) ^ v7;
}
```

My attack plan was to first leak stack, and i used the arb write primitive to store the address of `environ` to some global variable

Then I leaked the stack and calculated the ebp of the `main` function.

I overwrote the ebp from the saved ebp of `handler` stack frame to my ropchain.

After `leave, ret` was then executed the `esp` pointed to the ropchain - stack pivot!

