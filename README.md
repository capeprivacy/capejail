# Capejail

Enable a secure compute environment in a jail that blocks certain syscalls.

## Contents
- [Build](#build)
- [Motivation](#motivation)
- [Usage](#usage)
- [Example](#example)
- [Allowing Syscalls](#allowing-syscalls)

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

After exiting the docker container, create a new user on the host system for
running as within the jail.

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

## Allowing Syscalls

First step for allowing a new syscall, is discovering which syscall you need.

Let's look at an example that uses `ping`. We see in this example that we get
the message `Bad system call (core dumped)` when using the ping program.
```
(py310) [kyle@fedora capejail]$ sudo capejail -- bash
[jail]# ping google.com
Bad system call (core dumped)
```

We can use `strace` to monitor which systemcalls are being used by this program.
The `-f` flag will follow forks, which is necessary because capejail forks the
user program into a new process. `-c` will show a summary of all of the syscalls
made.

```
(py310) [kyle@fedora capejail]$ strace -f -c ping -c 1 google.com
PING google.com (172.217.4.78) 56(84) bytes of data.
64 bytes from lga15s47-in-f78.1e100.net (172.217.4.78): icmp_seq=1 ttl=119 time=12.4 ms

--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 12.443/12.443/12.443/0.000 ms
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 16.08    0.000770          15        49           mmap
 12.49    0.000598         598         1           execve
 11.34    0.000543          19        28         7 openat
  7.64    0.000366          12        29           newfstatat
  6.10    0.000292           9        31           close
  5.97    0.000286          17        16           recvmsg
  5.68    0.000272          27        10           socket
  4.28    0.000205           9        21           read
  3.95    0.000189          12        15           mprotect
  3.74    0.000179          29         6           sendto
  2.53    0.000121           8        14           setsockopt
  2.21    0.000106          17         6           write
  2.09    0.000100          10        10           pread64
  1.75    0.000084          16         5         1 connect
  1.36    0.000065          10         6           ppoll
  1.25    0.000060           7         8         4 prctl
  1.11    0.000053           7         7           capget
  1.00    0.000048           9         5           getsockopt
  0.88    0.000042           8         5           getsockname
  0.86    0.000041          10         4           brk
  0.84    0.000040           4         9           rt_sigprocmask
  0.75    0.000036           7         5           munmap
  0.67    0.000032          10         3           bind
  0.58    0.000028           9         3           rt_sigaction
  0.52    0.000025           6         4         2 recvfrom
  0.48    0.000023          11         2           lseek
  0.46    0.000022           5         4           futex
  0.42    0.000020          10         2           ioctl
  0.42    0.000020          20         1         1 access
  0.42    0.000020          10         2           getrandom
  0.31    0.000015           7         2         1 arch_prctl
  0.29    0.000014           7         2           getuid
  0.27    0.000013          13         1           capset
  0.27    0.000013          13         1           rseq
  0.21    0.000010          10         1           setuid
  0.19    0.000009           9         1           setitimer
  0.17    0.000008           8         1           set_tid_address
  0.15    0.000007           7         1           getpid
  0.15    0.000007           7         1           set_robust_list
  0.15    0.000007           7         1           prlimit64
  0.00    0.000000           0         1           uname
------ ----------- ----------- --------- --------- ----------------
100.00    0.004789          14       324        16 total
```

I put together a small bash function that will search the list of syscalls and
find which ones are missing from the allow list from capejail.

```
function search_syscalls()
{
    for item in $(cat /tmp/syscalls);
	do
    	grep $item seccomp.c > /dev/null;
    	if [[ $? != 0 ]]; then
    	    echo $item
    	fi
    done
}
```

To use this function, place each of the syscalls that strace detected into the
text file `/tmp/syscalls` like so. Please note that each line only contains the
exact name of the syscall as output by `strace`.

```
(py310) [kyle@fedora capejail]$ cat /tmp/syscalls
mmap
openat
execve
newfstatat
close
mprotect
read
socket
recvmsg
setsockopt
sendto
connect
munmap
write
pread64
rt_sigprocmask
prctl
ppoll
capget
getsockopt
access
brk
getsockname
rt_sigaction
bind
setitimer
recvfrom
ioctl
getrandom
lseek
futex
getuid
arch_prctl
capset
setuid
getpid
uname
prlimit64
rseq
set_tid_address
set_robust_list
```

Now we can call our `search_syscalls` function to search which syscalls we are
missing. We can see below that we are missing 3 syscalls.

```
(py310) [kyle@fedora capejail]$ search_syscalls
setsockopt
capset
setuid
```

If we want to allow these syscalls (which in actuality, we do not as these can
be used to exploit the system) then we can add them to the allow list found in
`seccomp.c`.

By using the `SCMP_SYS` macro, we can then add these syscalls to the allow list
as follows:

```diff
diff --git a/seccomp.c b/seccomp.c
index 6a62dc4..8051406 100644
--- a/seccomp.c
+++ b/seccomp.c
@@ -6,6 +6,9 @@
 #include "seccomp.h"

 static const int ALLOWED_SYSCALLS[] = {
+    SCMP_SYS(setsockopt),
+    SCMP_SYS(capset),
+    SCMP_SYS(setuid),
     /*
      * Check user's permissions for a file.
      */
```

We will now recompile:

```
make
```

Finally, we will run capejail again, and see that ping is no longer being killed
by a bad syscall:

```
(py310) [kyle@fedora capejail]$ sudo ./capejail -- ping -c 3 google.com
PING google.com (172.217.4.78) 56(84) bytes of data.
64 bytes from lga15s47-in-f78.1e100.net (172.217.4.78): icmp_seq=1 ttl=119 time=12.9 ms
64 bytes from ord37s18-in-f14.1e100.net (172.217.4.78): icmp_seq=2 ttl=119 time=11.8 ms
64 bytes from ord37s18-in-f14.1e100.net (172.217.4.78): icmp_seq=3 ttl=119 time=11.6 ms

--- google.com ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2004ms
rtt min/avg/max/mdev = 11.600/12.080/12.854/0.552 ms
./capejail: 'ping' exited with status 0
./capejail: shutting down
```
