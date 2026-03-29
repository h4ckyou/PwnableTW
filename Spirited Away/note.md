## Spirited Away 

```
mark@rwx:~/Desktop/Labs/PwnableTW/spiritedaway$ file spirited_away_patched 
spirited_away_patched: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter ld-2.23.so, for GNU/Linux 2.6.24, BuildID[sha1]=9e6cd4dbfea6557127f3e9a8d90e2fe46b21f842, not stripped
mark@rwx:~/Desktop/Labs/PwnableTW/spiritedaway$ checksec spirited_away
[*] '/home/mark/Desktop/Labs/PwnableTW/spiritedaway/spirited_away'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
mark@rwx:~/Desktop/Labs/PwnableTW/spiritedaway$
```

Decompiled code:

```c
int survey()
{
  char v1[56]; // [esp+10h] [ebp-E8h] BYREF
  size_t nbytes; // [esp+48h] [ebp-B0h]
  size_t r_size; // [esp+4Ch] [ebp-ACh]
  char comment[80]; // [esp+50h] [ebp-A8h] BYREF
  int age; // [esp+A0h] [ebp-58h] BYREF
  void *heap_chunk; // [esp+A4h] [ebp-54h]
  char reason[80]; // [esp+A8h] [ebp-50h] BYREF

  nbytes = 60;
  r_size = 80;
LABEL_2:
  memset(comment, 0, sizeof(comment));
  heap_chunk = malloc(60u);
  printf("\nPlease enter your name: ");
  fflush(stdout);
  read(0, heap_chunk, nbytes);
  printf("Please enter your age: ");
  fflush(stdout);
  __isoc99_scanf("%d", &age);
  printf("Why did you came to see this movie? ");
  fflush(stdout);
  read(0, reason, r_size);
  fflush(stdout);
  printf("Please enter your comment: ");
  fflush(stdout);
  read(0, comment, nbytes);
  ++cnt;
  printf("Name: %s\n", (const char *)heap_chunk);
  printf("Age: %d\n", age);
  printf("Reason: %s\n", reason);
  printf("Comment: %s\n\n", comment);
  fflush(stdout);
  sprintf(v1, "%d comment so far. We will review them as soon as we can", cnt);
  puts(v1);
  puts(&s);
  fflush(stdout);
  if ( cnt > 199 )
  {
    puts("200 comments is enough!");
    fflush(stdout);
    exit(0);
  }
  while ( 1 )
  {
    printf("Would you like to leave another comment? <y/n>: ");
    fflush(stdout);
    read(0, &choice, 3u);
    if ( choice == 'Y' || choice == 'y' )
    {
      free(heap_chunk);
      goto LABEL_2;
    }
    if ( choice == 'N' || choice == 'n' )
      break;
    puts("Wrong choice.");
    fflush(stdout);
  }
  puts("Bye!");
  return fflush(stdout);
}
```

Bugs:
- Uninitialized memory read via printf caused from no null termination during read & scanf not checking return value
- Stack overflow caused from snprintf leading to adjacent variable overwrite (nbytes) then leveraging that to cause stack overflow to corrupt the pointer (heap_chunk)

Using the first bug for memory leaks + second bug for arb free, i performed house of spirit to get allocation to the stack then overwrote the return address
