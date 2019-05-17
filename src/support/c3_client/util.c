#include "util.h"
#include <errno.h>


const char *nn_err_strerror (int errnum)
{
    switch (errnum) {
#if defined NN_HAVE_WINDOWS
    case ENOTSUP:
        return "Not supported";
    case EPROTONOSUPPORT:
        return "Protocol not supported";
    case ENOBUFS:
        return "No buffer space available";
    case ENETDOWN:
        return "Network is down";
    case EADDRINUSE:
        return "Address in use";
    case EADDRNOTAVAIL:
        return "Address not available";
    case ECONNREFUSED:
        return "Connection refused";
    case EINPROGRESS:
        return "Operation in progress";
    case ENOTSOCK:
        return "Not a socket";
    case EAFNOSUPPORT:
        return "Address family not supported";
    case EPROTO:
        return "Protocol error";
    case EAGAIN:
        return "Resource unavailable, try again";
    case EBADF:
        return "Bad file descriptor";
    case EINVAL:
        return "Invalid argument";
    case EMFILE:
        return "Too many open files";
    case EFAULT:
        return "Bad address";
    case EACCES:
        return "Permission denied";
    case ENETRESET:
        return "Connection aborted by network";
    case ENETUNREACH:
        return "Network unreachable";
    case EHOSTUNREACH:
        return "Host is unreachable";
    case ENOTCONN:
        return "The socket is not connected";
    case EMSGSIZE:
        return "Message too large";
    case ETIMEDOUT:
        return "Timed out";
    case ECONNABORTED:
        return "Connection aborted";
    case ECONNRESET:
        return "Connection reset";
    case ENOPROTOOPT:
        return "Protocol not available";
    case EISCONN:
        return "Socket is connected";
#endif
    //case ETERM:
      //  return "Nanomsg library was terminated";
    //case EFSM:
      //  return "Operation cannot be performed in this state";
    default:
#if defined _MSC_VER
#pragma warning (push)
#pragma warning (disable:4996)
#endif
        return strerror (errnum);
#if defined _MSC_VER
#pragma warning (pop)
#endif
    }
}

