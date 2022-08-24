# Capejail

Enable a secure compute environment in a jail that blocks certain syscalls.

## Contents
- [Motivation](#motivation)
- [Usage](#usage)
- [Example](#example)

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
tampering with other processes and devices. While Linux Namespaces are commonly
used to achieve this, it has been found that we do not have access to
configuring namespaces while in the Nitro Enclave.

For a comprehensive list of why certain syscalls are blocked, please see
[SYSCALLS.md](https://github.com/capeprivacy/capejail/SYSCALLS.md).

> Why not just use namespaces, cgroups, and/or unshare?

For sandboxing, those are absolutely the tools that one should reach for first
on Linux! Unfortunately for us, within the enclave, we don't have the
capabilities to use any of these tools. For example, when attempting to make a
call to `unshare(CLONE_NEWNET)` in order to disable networking for the jailed
process, we get the following error:

```
unshare: Operation not permitted
```

This is happening because `CLONE_NEWNET` requires the capability
`CAP_SYS_ADMIN`, however, the Nitro Enclave does not have this capability
enabled. We can see this happening within Docker as well. We can list the
current process's capabilities by using the `getpcaps` command bellow:

```
root@6d1a0e8b7db6:/# getpcaps 0
0: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```

Given the lack of capabilities to unshare `CLONE_NEWNS`, `CLONE_NEWCGROUP`, or
`CLONE_NEWNET`, we therefore cannot use these Linux features in our sandboxing
implementation.

Hence, we need to work around these limitations with our own implementation
utilizing chroot, seccomp, and UNIX user permissions.

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
