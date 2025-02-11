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

But because `__read_chk` size is defined as `size_t` if the size we passed is negative it will wrap around thus giving us an overflow, so we just need to make size some value such that when it's subtracted by 16 it will give a negative value. Any number less than 16 is sufficient

