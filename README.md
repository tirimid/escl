# escl

## Introduction
escl is a program for elavating privileges to root. As a regular Linux desktop
user and programmer, I have very little use for the intricate bloat of sudo,
and while doas is better, I felt it could still be more minimal. This program
only implements two things:
1. Choosing which users are allowed to use it, and which passwords they can
authenticate with
2. Giving those users root privileges when run

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
3. Add passwords for permitted users to authenticate with using
`escl -pa <pass1> -pa <pass2> ...`

When usage is actually needed:
1. Run the command you with to execute, prefixed by `escl`. For example, a
non-root user may run `escl pacman -Syu` in a similar way to how they would run
`sudo pacman -Syu`
2. Enter one of the added passwords

## Contributing
I am not accepting pull requests, this program is entirely for my own usage.
Feel free to fork this project and make your own version.
