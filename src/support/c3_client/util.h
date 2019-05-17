#ifndef __UTIL_H
#define __UTIL_H
 #include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined __GNUC__ || defined __llvm__
#define nn_fast(x) __builtin_expect ((x), 1)
#define nn_slow(x) __builtin_expect ((x), 0)
#else
#define nn_fast(x) (x)
#define nn_slow(x) (x)
#endif


void nn_backtrace_print (void);

#define nn_assert(x) \
    do {\
        if (nn_slow (!(x))) {\
            nn_backtrace_print (); \
            fprintf (stderr, "Assertion failed: %s (%s:%d)\n", #x, \
                __FILE__, __LINE__);\
            fflush (stderr);\
            abort ();\
        }\
    } while (0)

/*  Check the condition. If false prints out the errno. */
#define errno_assert(x) \
    do {\
        if (nn_slow (!(x))) {\
            nn_backtrace_print (); \
            fprintf (stderr, "%s [%d] (%s:%d)\n", nn_err_strerror (errno),\
                (int) errno, __FILE__, __LINE__);\
            fflush (stderr);\
            nn_err_abort ();\
        }\
    } while (0)


const char *nn_err_strerror (int errnum);


inline void nn_err_abort (void)
{
    abort ();
}


#ifdef __cplusplus
}
#endif

#endif


