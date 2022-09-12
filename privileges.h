#ifndef PRIVILEGES_H
#define PRIVILEGES_H

/*
 * - Set the UID of the current process to `uid`.
 * - Drop group memberships to only the current user group.
 * - Create a new process namespace for child processes.
 * - Optionally unshare the networking namespace.
 */
int cape_drop_privileges(uid_t uid, bool with_networking);

#endif /* PRIVILEGES_H */
