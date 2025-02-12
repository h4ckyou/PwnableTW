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

