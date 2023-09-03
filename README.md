# escl

## Introduction
escl is a program for elevating privileges to root. As a regular Linux desktop
user and programmer, I have very little use for the intricate bloat of sudo,
and while doas is better, I felt it could still be more minimal. This program
only implements two things:
1. Choosing which users are allowed to use it, and which passwords they can
authenticate with
2. Giving those users root privileges when run

The point of escl is that it is utterly dependency-free (except for certain
POSIX standard functions and libcypt, which should be available on effectively
every Linux system ever). Its allowed users and passwords are stored separately
from all other programs, so you can easily drag-and-drop it in and out of any
system without being afraid of breaking something.

## Dependencies
Software / system dependencies are:
* A shell environment for execution

## Management
* To build the program, run `make`
* To install the program, run `make install`
* To uninstall all program files from the system, run `make uninstall`

## Usage
Immediately following installation:
1. Login as root
2. Give users permission to use escl with `escl -ua <user1> -ua <user2> ...`
3. Add a password for permitted users to authenticate with using `escl -pa`

When usage is actually needed:
1. Run the command you wish to execute, prefixed by `escl`. For example, a
non-root user may run `escl pacman -Syu` in a similar way to how they would run
`sudo pacman -Syu`
2. Enter one of the added passwords

Security / maintenance:
* To revoke users' abilities to use escl, run `escl -ur <user1> -ur <user2> ...`
* To remove a password, run `escl -pr` and enter the password you wish to revoke
* To regenerate the salt and hash used for storing a password, simply remove it
using `escl -pr` and readd it using `escl -pa`

## Contributing
I am not accepting pull requests, this program is entirely for my own usage.
Feel free to fork this project and make your own version.
