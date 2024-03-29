#ifndef BANNED_H
#define BANNED_H

/*
 * This header lists functions that have been banned from our code base,
 * because they're too easy to misuse (and even if used correctly,
 * complicate audits). Including this header turns them into compile-time
 * errors.
 */

#define BANNED(func) sorry_##func##_is_a_banned_function

/*
 * Original linux list of banned functions
 * https://github.com/git/git/blob/master/banned.h
 */
#undef strcpy
#define strcpy(x, y) BANNED(strcpy)
#undef strcat
#define strcat(x, y) BANNED(strcat)
#undef strncpy
#define strncpy(x, y, n) BANNED(strncpy)
#undef strncat
#define strncat(x, y, n) BANNED(strncat)

#undef sprintf
#undef vsprintf
#define sprintf(...) BANNED(sprintf)
#define vsprintf(...) BANNED(vsprintf)

#undef gmtime
#define gmtime(t) BANNED(gmtime)
#undef localtime
#define localtime(t) BANNED(localtime)
#undef ctime
#define ctime(t) BANNED(ctime)
#undef ctime_r
#define ctime_r(t, buf) BANNED(ctime_r)
#undef asctime
#define asctime(t) BANNED(asctime)
#undef asctime_r
#define asctime_r(t, buf) BANNED(asctime_r)

/*
 * Additional banned functions that are not banned in Linux
 */

/* alloca commonly allocates on the stack */
#undef alloca
#define alloca(x) BANNED(alloca)

#endif /* BANNED_H */
