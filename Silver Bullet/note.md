<h3> Silver Bullet </h3>

![image](https://github.com/user-attachments/assets/7bec2ef5-da20-4a07-b185-f5e250e80ce9)

This challenge showcases a buffer overflow with some pretty nice way to trigger it

When we run it we get this
![image](https://github.com/user-attachments/assets/6fd73fb1-8e77-42a6-94f4-104c4b93f6da)
![image](https://github.com/user-attachments/assets/47fc2735-481c-485b-a6f5-1e7a77c2a941)

We have 4 options to choose from but the option 4 is useless as it just `exits`
![image](https://github.com/user-attachments/assets/d19f7c2e-e003-45c0-83a2-b17189b8756d)

We can create a silver bullet using option 1
![image](https://github.com/user-attachments/assets/74553ed6-9742-43e7-91df-c619238c3059)

What that does is reading some input to the buffer then updating it's size `s->bullet` and we can only use this once!

The power up function is this
![image](https://github.com/user-attachments/assets/4d2061c4-7f98-4bee-bd22-779c68afda21)

Basically it makes sure that the value of the bullet which represents the string length of the buffer isn't greater than 47, then it reads some sized number of bytes gotten from subtracting 48 with the bullet value

Then it uses `strncat` to append the content of `s` to `dest->description` and it then updates `dest->bullet` to the sum of the length of s with it's original size

And the final function is beat
![image](https://github.com/user-attachments/assets/52a73f6b-0a7b-46cd-94c9-9ab7e4e61669)
![image](https://github.com/user-attachments/assets/23e85a5b-0c5e-4a23-876c-bcd43602c20e)

This would only return True if our bullet size is greater than `0x7FFFFFFF`
![image](https://github.com/user-attachments/assets/97d10562-60f5-42e3-86a3-bbb1b9eb3f9d)

With this we need to overwrite the return address of the main function since that's where the `s` buffer is 
![image](https://github.com/user-attachments/assets/e80c1d9f-0b2a-4c0e-8ac5-5e574f682224)

And to do that we need the size to be greater than `0x7FFFFFFF`

To do that we'll leverage a buffer overflow to overwrite the size to something large

To trigger the overflow you need to know that `strncat` will append non-null bytes from a source array to a string, and null-terminate the result, you can check the man page for that it's how i figured it

So the trick is that if we set the size as 47 basically we give it 47 bytes as the bullet description when it does `48 - dest->bullet` that would give `1` and then after `strncat` is called it would overwrite the next byte on the stack to a null byte and that value represents the current size

Then when the new size is calculated it will actually be `1 + 0` because we read in just a byte to `s` and currently `dest->bullet` is `0`

```c
v3 = strlen(s) + dest->bullet;
dest->bullet = v3
```

With that when we use the power up function again we can now write out of bound the buffer since `strncat` appends bytes thus overwriting the return address

And it's a straight forward `ret2libc` once you have eip control!

Pretty neat challenge.



