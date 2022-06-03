# Capejail

Enable a secure compute environment in a jail that blocks certain syscalls

## Usage
```
$ capejail -h
capejail: enable a secure compute environment in a jail that blocks certain syscalls
usage:
	capejail -u USER -r CHROOT [-d DIRECTORY] PROGRAM [ARGS]

	-d	directory to start in within jail

	-r	path to chroot directory to use in jail

	-u	user to run as within the jail

NOTE: should be run as root or with sudo to allow chroot
```

# Example
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
