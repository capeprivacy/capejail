# Capejail

Enable a secure compute environment in a jail that blocks certain syscalls.

## Motivation

After experimentation, I've found that existing jail programs such
[nsjail](https://github.com/google/nsjail)
and [firejail](https://firejail.wordpress.com/) do not work inside of AWS nitro
enclaves. This jail implementation was built specifically for safeguarding Cape
from user code when running inside of an enclave.

The security is multilayer.
1. User code is run in a `chroot` so that it cannot access files outside of its
designated jail.
2. User code is run as a different user with locked down permissions.
3. User code is run with seccomp filters set to block harmful syscalls that can
be used to escape the jail.

The chroot environment can be customized to the level of security desired.
For example, by restricting access to `/proc` and certain devices in `/dev/`
AND running the jail as a non-root user, you can keep the jailed user from
seeing other processes and devices that it should not have access to. While
Linux Namespaces are commonly used to achieve this, it has been found that
we do not have access to configuring namespaces while in the Nitro Enclave.

## Usage
```
$ capejail -h
capejail: enable a secure compute environment in a jail that blocks certain syscalls
usage:
	capejail [OPTION] -- PROGRAM [ARGS]

	-d	directory to start in within jail

	-r	path to chroot directory to use in jail

	-u	user to run as within the jail

	-I	insecure mode, launch with seccomp disabled

NOTE: should be run as root or with sudo to allow chroot
```

## Example
```bash
(py310) [kyle@fedora capejail]$ sudo capejail -r ~/chroot -u jailuser -- bash
[jail]$ echo $USER
jailuser
[jail]$ pwd
/
[jail]$ ls -l
total 8
drwxr-xr-x 1 root root  730 Jun  2 20:15 bin
drwxr-xr-x 1 root root   14 Jun  2 18:52 dev
drwxr-xr-x 1 root root 1274 Jun  2 20:15 etc
drwxr-xr-x 1 root root   84 Jun  2 20:15 lib
drwxr-xr-x 1 root root   40 May 24 20:28 lib64
drwxr-xr-x 1 root root 1008 Jun  2 20:15 sbin
drwxr-xr-x 1 root root    0 Jun  2 19:58 tmp
drwxr-xr-x 1 root root   84 May 24 20:28 usr
drwxr-xr-x 1 root root   90 Jun  2 14:27 var
[jail]$ chroot /tmp # for security, this is supposed to fail
Bad system call (core dumped)
[jail]$ exit
exit
(py310) [kyle@fedora capejail]$
```
