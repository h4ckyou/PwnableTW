<h3> HackNote </h3>

This was an easy one with not so much constraints

The bug is simply a UAF and we can control the size of what is to be allocated

The program behaves as a note service app where we can:
- add a note
- delete a note
- print a note

The notes are managed using this struct:

```c
struct note_t  {
void (*show_note)();
char *note;
}
```

Since there's a function pointer which is triggered when you use the `print_note` function
![image](https://github.com/user-attachments/assets/60a29df6-a466-465d-aceb-133f674527fa)
![image](https://github.com/user-attachments/assets/743c3e60-c691-4359-a534-231907fe2658)

