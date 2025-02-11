<h3> Tcache Tear </h3>

![image](https://github.com/user-attachments/assets/ebaf39a1-fc08-4b28-bdbe-002351d5f767)

This was a nice challenge that showcases how you can bypass glibc mitigations on a chunk that's about to be freed

We are provided with a binary that shows a menu option when executed
![image](https://github.com/user-attachments/assets/3e8c1981-f15e-4680-90b1-8321b762aad0)

With the list of options shown we can make some guesses that this will be about heap exploitation

The binary uses glibc 2.27 and it has all protections aside `PIE` enabled 
![image](https://github.com/user-attachments/assets/001835f1-41c1-4223-b6db-e4021e2fa632)
![image](https://github.com/user-attachments/assets/c07bc682-c844-4361-88dc-ff4b6f336c78)

From reversing i got that:
- We have just only one place where our heap pointer is stored
- There's a heap overflow
- A UAF

Here in the `allocate` function, we can make any sized allocation as long as it's less than or equal to 256 and the address returned is stored in `ptr` then it will call the `read_input` function with size as `size - 16`
![image](https://github.com/user-attachments/assets/50e33f2d-4562-4788-8372-24a8c8e77ed2)
![image](https://github.com/user-attachments/assets/ef2304cd-9fb8-4168-9e97-9ddca82c2478)

But because `__read_chk` buflen is defined as `size_t` if the size we passed is negative it will wrap around thus giving us an overflow, so we just need to make size some value such that when it's subtracted by 16 it will give a negative value. Any number less than 16 is sufficient

Moving on we can see that after it free's our pointer it doesn't set it to null. Also we're limited to just 8 free's
![image](https://github.com/user-attachments/assets/69b33468-2288-401e-b31a-3c2115763885)

And the last important thing is that our name is stored in a global variable
![image](https://github.com/user-attachments/assets/c813106d-ca4a-4876-b84a-6dc6c6636e64)

That's all the binary does!

First we can leverage the UAF to get double free on the tcache as there's no check to see if the chunk we're about to free is already in the tcache bin

![image](https://github.com/user-attachments/assets/66df5bff-83d9-4a37-9a4a-51eae585c9e2)

And with that we can get arb write, but since the GOT is not writable we need to target the libc

But to do that we need a libc leak

At first i had issue with this because i wanted to fill up the tcache then any more free will be placed in maybe the unsorted bin which has pointers to libc as it's fd/bk value

The issue with that is that we can only make one allocation so even if we free the chunk when we allocate it, we'll end up with the same chunk and also there's no "view chunk" option that can let us read the content of our chunk so what a bummer

Now it occurred to me that we're given an option to provide a name? Why that, is it important?

That's actually useful because with that we can fake a chunk on the global name variable then make malloc return it and on free'ing the chunk it will be placed on the unsorted bin

I decided to use a chunk of size `0x500` because if you free that it will get placed to the unsorted bin 

There are some checks that are done on a chunk that's about to be consolidated for example if we don't pass that we get this error:
- double free or corruption (!prev)
- corrupted size vs. prev_size

The first check just validates that the next chunk prev inuse bit is set
![image](https://github.com/user-attachments/assets/b7509c42-312e-403d-80fd-2717dcc29b48)

While the second one occurs during the forward consolidation with the unlink macro where it validates that the chunk size equals the next chunk prev size
![image](https://github.com/user-attachments/assets/17bc4767-b285-4024-98ab-eac02e71ba4d)

But this can be easily bypassed because we have an overflow, so we can forge fake chunks that passes the check

And with that the chunk will be placed in the unsorted bin and we can use the info function to view it's content thus getting a libc leak

The rest is straight forward, since we have a libc leak we perform tcache dup again but this time we overwrite `__free_hook` to a one gadget

Pretty nice challenge!


























