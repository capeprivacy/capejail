# Capejail

Enable a secure compute environment in a jail that blocks certain syscalls.

## Contents
- [Build](#build)
- [Motivation](#motivation)
- [Usage](#usage)
- [Example](#example)

## Build

Because of the dependence on
[seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html), this project is
Linux specific, and it will not build on other operating systems (not even other
UNIX like systems).

First, ensure that you have the following dependencies installed:

Ubuntu/Debian
```
sudo apt install libseccomp-dev
```

Fedora/CentOS/Red hat
```
sudo dnf install libseccomp-devel
```

To compile `capejail`, type the following into a terminal:

```
make
```

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
4. User code is run in a separate PID namespace, so it is not able to see or
interact with any other processes on the system, other than its own child
processes.
5. Optionally, the jail can unshare the networking namespace, which removes the
jailed process's ability to perform any networking.

The chroot environment can be customized to the level of security desired.
For example, by restricting access to `/proc` and certain devices in `/dev/`
AND running the jail as a non-root user, you can keep the jailed user from
tampering with other processes and devices.

For a comprehensive list of why certain syscalls are blocked, please see
[SYSCALLS.md](https://github.com/capeprivacy/capejail/blob/main/SYSCALLS.md).

## Usage
```
$ capejail -h
capejail: enable a secure compute environment in a jail that blocks certain syscalls

usage:
	capejail [OPTION] -- PROGRAM [ARGS]

	-h	display this help message

	-n	disable networking for the jailed process

	-d	directory to start in within jail

	-r	path to chroot directory to use in jail

	-u	user to run as within the jail

	-I	insecure mode, launch with seccomp disabled

NOTE: should be run as root or with sudo to allow chroot
```

## Example

First, create a chroot directory. One way to do this is to run a docker
container, and mount a volume to it where you will install the system to.

```
docker run --rm -it -v ~/chroot:/chroot debian
```

Next, within the docker container, copy the necessary directories into the
chroot:

```
mkdir /chroot
cp -r /bin /chroot/
cp -r /sbin /chroot/
cp -r /usr /chroot/
cp -r /etc /chroot/
rm -f /chroot/etc/bash.bashrc
cp -r /lib /chroot/
cp -r /lib64 /chroot/
mkdir /chroot/dev
mknod -m 666 /chroot/dev/null c 1 3
mknod -m 666 /chroot/dev/zero c 1 5
mknod -m 666 /chroot/dev/random c 1 8
mknod -m 666 /chroot/dev/urandom c 1 9
```

Create a new user for running as within the jail.

```
adduser jailuser
```

And now you'll have a chroot environment setup at `~/chroot`. At this point,
you're ready to run `capejail`.

```bash
(py310) [kyle@fedora ~]$ grep PRETTY_NAME /etc/os-release
PRETTY_NAME="Fedora Linux 36 (Workstation Edition)"
(py310) [kyle@fedora ~]$ sudo capejail -r ~/chroot -u jailuser -- bash
[jail]$ grep PRETTY_NAME /etc/os-release
PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
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
(py310) [kyle@fedora ~]$
(py310) [kyle@fedora ~]$ # Note, the '-I' flag is used here because ping will
(py310) [kyle@fedora ~]$ # be killed by an illegal syscall before it has a
(py310) [kyle@fedora ~]$ # chance to be blocked by unsharing the network namespace.
(py310) [kyle@fedora ~]$ # DON'T USE '-I' IN PRODUCTION!
(py310) [kyle@fedora ~]$ sudo capejail -u jailuser -I -n -r /home/kyle/chroot-ping/ -- bash
[jail]$ ping google.com # with the '-n' flag, network calls are not allowed
ping: socket: Operation not permitted
```
