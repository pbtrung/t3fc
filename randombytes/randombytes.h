#ifndef sss_RANDOMBYTES_H
#define sss_RANDOMBYTES_H

#ifdef _WIN32
/* Load size_t on windows */
#include <CRTDEFS.H>
#else
#include <unistd.h>
#endif /* _WIN32 */

#if defined(__cplusplus)
extern "C" {
#endif

/*
 * Write `n` bytes of high quality random bytes to `buf`
 */
int randombytes(void *buf, size_t n);

#if defined(__cplusplus)
}
#endif

#endif /* sss_RANDOMBYTES_H */