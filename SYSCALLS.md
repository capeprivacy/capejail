# SYSCALLS

This is a list of blocked syscalls.

We are more prone to blocking syscalls rather than allowing them. If a syscall
does not seem to be useful to our users, then we block it out of an abundance
of caution. Many of the blocked syscalls may indeed be safe, but we think that
defaulting to blocking them will be the safer option. If a blocked syscall is
both safe and useful, then we will be open to discussion of adding it to the
allow list.

We will only allow syscalls that are unlikely to lead to exploits.

Particularly dangerous syscalls will be marked with ⚠️.

## Blocked

### accept

Not needed by demo programs, and is helpful for restricting networking.

### accept4

See [accept](#accept).

### acct

Requires CAP_SYS_PACCT privileges, and does not seem to be useful for user
processes.

### add_key

It is unlikely that a user program would have a need to add a key to the
kernel's keyring, so best to block it out of caution.

### adjtime

Needs CAP_SYS_TIME privileges. Tunes the kernels clock, could be used
nefariously.

### afs_syscall

Unimplemented system call. This system call is not implemented in the Linux
kernel, and always returns -1.

### bpf

Berkeley Packet Filter. Used for network packet filtering and for seccomp.
Neither of which operations should be necessary for user programs to do.

### capset

Set capabilities of calling thread. This syscall can grant the thread privileges
to make additional syscalls, for example CAP_SYS_CHROOT. Could be used
maliciously.

### chroot ⚠️

Change root directory. This is the big one to block, since it can be used to
escape the jail.

### clock_adjtime

See [adjtime](#adjtime).

### clock_settime

See [adjtime](#adjtime).

### __clone2

Not intentionally blocked, but because libseccomp does not provide a SCMP_SYS
macro for `__clone2`, we are not able to allow it.

```
enableseccomp.c:23:5: error: ‘__SNR___clone2’ undeclared here (not in a function)
   23 |     SCMP_SYS(__clone2),
      |     ^~~~~~~~
```

### create_module

Create a loadable kernel module. This was removed in Linux 2.6, so no reason to
use it.

### delete_module

Probably no good reason for user code to unload kernel modules.

### epoll_pwait2

Not intentionally blocked, but this is a new syscall that currently doesn't
compile with the version of libseccomp used in the container. The plan is to
allow this once libseccomp supports it.

See [epoll_create](#epoll_create).

### finit_module ⚠️

User code probably shouldn't be loading kernel modules.

### fsconfig

Literally no man pages for this syscall. Syscall number 431 in asm/unistd_64.h
on AMD64 Linux.

### fsmount

Literally no man pages for this syscall.

### fsopen

Literally no man pages for this syscall.

### fspick

Literally no man pages for this syscall.

### futimesat

Obsolete system call.

### futex_waitv

Not intentionally blocked, but this is a new syscall that currently doesn't
compile with the version of libseccomp used in the container. The plan is to
allow this once libseccomp supports it.

See [futex](#futex)

### get_kernel_syms

Retrieve exported kernel and module symbols. Users probably don't need to do
anything with kernel modules.

### getpmsg

Unimplemented system call. This system call is not implemented in the Linux
kernel, and always returns -1.

### init_module

Initialize a kernel module. A user function shouldn't need to do this.

### ioperm

Set port IO permissions. Turning on requires CAP_SYS_RAWIO permissions.

### io_pgetevents

No man pages for this syscall.

### iopl

Similar to [ioperm](#ioperm), but this one is deprecated due to it being a lot
slower than ioprem.

### kcmp

Compare if two processes share kernel resources such as virtual memory,
file descriptors, etc. Requires the same privileges as ptrace.

### kexec_file_load ️⚠️

Load a new kernel that will run on reboot.

### kexec_load ⚠️

See [kexec_file_load](#kexec_file_load)

### keyctl

Manage kernel keyring.

### landlock_add_rule

No man page entries, so defaulting to blocking.

### landlock_create_ruleset

No man page entries, so defaulting to blocking.

### landlock_restrict_self

No man page entries, so defaulting to blocking.

### link

Hard links that lead outside of the chroot are a way of escaping a chroot jail.
Since the process is already jailed, I'm not aware of a way for this to be
exploited, I also don't think that it will have any value to user functions, so
I will block it out of an abundance of caution.

### linkat

See [link](#link)

### listen

Listen for a connection on a socket. Could be used to run a webserver from
within the enclave, possibly spoofing sentinel.

### mbind

Set the NUMA policy, requires CAP_SYS_NICE for certain flags.

### migrate_pages

Move all pages in another process to another set of nodes. I'm suspicious of
something that can affect memory of other processes, so for now we're blocking
this one.

### mknod ⚠️

Create special files, e.g., the files that can be found within `/dev`. One of
the goals of `capejail` is to block access to certain special files such as
`/dev/nsm`. We want to be sure that a malicious process will not be able to
create these files itself.

### mknodat ⚠️

See [mknod](#mknod)

### mount

Attach a filesystem to a target path. User's probably won't need to mount any
filesystems.

### mount_setattr

See [mount](#mount)

### move_mount

No manpage entries.

### move_pages

See [migrate_pages](#migrate_pages)

### nfsservctl

Interface with NFS daemon. This system call no longer exists in Linux since
version 3.1.

### open_tree

No man pages.

### perf_event_open

Performance monitoring. Can be used to spy on other processes.

### pidfd_getfd

Gets a duplicate file descriptor of another processes file descriptor. Requres
ptrace.

See [here](https://www.phoronix.com/news/Linux-5.6-pidfd-getgd)

### pidfd_open

See [pidfd_getfd](#pidfd_getfd)

### pivot_root

Change the root mount.

### process_mrelease

Fairly new system call that is not yet available in the libseccomp version
used in the container. Should be safe to allow when we upgrade the container.

### process_vm_readv

Transfer data between address spaces.

### process_vm_writev

Transfer data between address spaces.

### ptrace ⚠️

Allows caller to observe the target process. Can be used to extract memory
from any other process.

### putpmsg

This syscall is not implemented.

### query_module

User code probably shouldn't need to worry about kernel module.

### quotactl

Manipulate disk quotas

### quotactl_fd

See [quotactl](#quotactl)

### reboot

Reboot the system.

### request_key

Request a key from the kernel's key management facility.

### sched_getaffinity

It is unlikely that user code will need to do anything with scheduling

### sched_getattr

See [sched_getaffinity](#sched_getaffinity)

### sched_getparam

See [sched_getaffinity](#sched_getaffinity)

### sched_get_priority_max

See [sched_getaffinity](#sched_getaffinity)

### sched_get_priority_min

See [sched_getaffinity](#sched_getaffinity)

### sched_getscheduler

See [sched_getaffinity](#sched_getaffinity)

### sched_rr_get_interval

See [sched_getaffinity](#sched_getaffinity)

### sched_setaffinity

See [sched_getaffinity](#sched_getaffinity)

### sched_setattr

See [sched_getaffinity](#sched_getaffinity)

### sched_setparam

See [sched_getaffinity](#sched_getaffinity)

See [sched_getaffinity](#sched_getaffinity)


### sched_setscheduler

See [sched_getaffinity](#sched_getaffinity)

### sched_yield

See [sched_getaffinity](#sched_getaffinity)

### seccomp

We are already using seccomp to restrict syscalls that the user code can make.
We want to avoid user code being able to potentially exploit subsequent calls
to seccomp to re-enable previously disabled syscalls. While I am not aware of
such an exploit, I don't want to rule it out.

### security

Unimplemented syscall.

### setfsgid

User code probably won't need to set the filesystem group ID.

### setfsuid

User code probably won't need to set the filesystem user ID.

### setgid

Let's avoid a possible exploit of user code trying to change its group ID to
another user on the system.

### setgroups

Let's avoid a possible exploit of user code trying to change its group
membership.

### sethostname

User code should not need to change the hostname.

### setns

Move the calling thread into a different namespace. We certainly don't want
user code to be able to escape its namespace.

### setpgid

User code probably won't need to be changing its process group ID.

### setpriority

Requires CAP_SYS_NICE to be able to get a more favorable priority.

### setregid

User code should not be changing its group ID.

### setresgid

User code should not be changing its group ID.

### setresuid

User code should not be changing its user ID.

### setreuid

User code should not be changing its user ID.

### setrlimit

User code should not be adjusting its resource limits.

### setsockopt

Let's block this to avoid the user running a web server within the enclave.

### settimeofday

Set system time of day. User code should not need to do this.

### setuid

Users should not be able to change their UID. Users code should be restricted
to the capejail user.

### shutdown

User code should not be able to shutdown the virtual machine.

### swapoff

Disable swap area. Users shouldn't need to configure swap.

### swapon

Enable swap area. Users shouldn't need to configure swap.

### symlink

I'm hesitant to allow links in case if there is an exploit to set and follow
links to escape the chroot jail.

### symlinkat

See [symlink](#symlink)

### sync

Commit file to disk. Shouldn't be necessary.

### sync_file_range

See [sync](#sync)

### syncfs

See [sync](#sync)

### \_sysctl

No longer exists in current kernels, removed with Linux version 5.5.

### syslog

Read from kernel message ring buffer. Users shouldn't need this.

### tuxcall

Unimplemented syscall.

### umount

Unmount a volume. Users should not be umounting volumes from the filesystem.

### umount2

See [umount](#umount)

### vserver

Unimplemented syscall.
