/*
	2014-02-24, Ver 0.1, created by LiJia(lijia@nismail.iie.ac.cn).

	Add system socket API timeout features, as if the socket was specified to be nonblocking.

	在系统标准SOCKET接口基础上, 增加超时机制, 对于任何类型描述符, 都类似非阻塞操作.
*/

#ifndef MESA_SOCKET_WRAP_H
#define MESA_SOCKET_WRAP_H

#include <sys/types.h> 
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum{
	MESA_SOCK_SUCCESS		=   0,
	MESA_SOCK_COMMON_ERR	= -1,
	MESA_SOCK_TIMEOUT		= -2,
	MESA_SOCK_WOULD_BLOCK	= -3,
	MESA_SOCK_PEER_CLOSE		= -4,
	MESA_SOCK_INVALID_ARG	= -5,
}MESA_sock_errno_t;

/* get current time in microseconds */
long MESA_sock_get_time_ms(void);

/*
	Check a sokcet fd status.

	return value:
		0	 : no error;
		other: fd has error.
*/
int MESA_sock_has_error(int sockfd);

/*
	Check a socket can be read or not.
	return value:
		1 		: some data can be read;
		negative 	: maybe timeout, maybe link error, see also "MESA_sock_errno_t".
*/
int MESA_sock_can_be_read(int sockfd, int timeout_ms);

/*
	Check a socket can be written or not.
	return value:
		1 		: data can be written;
		negative 	: maybe timeout, maybe link error, see also "MESA_sock_errno_t".
*/
int MESA_sock_can_be_write(int sockfd, int timeout_ms);

/*
	args:
		the first three args like the connect(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout, units:millisecond,
			    return until connection succeed, or timeout, or some error occur.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1: block infinite, until connection succeed, or some error occur.
	return value:
		0	 	: connection succeed;
		negative : see also "MESA_sock_errno_t".
*/
int MESA_sock_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen, int timeout_ms);

/*
	args:
		the first three args like the read(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond,
			    return until 'count' bytes has read, or timeout, or some error occur.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1: block infinite if no available data whether sockfd is block or non-block, 
 			    return until 'count' bytes has read, or some error occur.
	return value:
			0	: peer closed;
		positive : the number of bytes read, maybe smaller than 'count', 
				  because timeout but fewer bytes are actually available right now;
		negative 	: see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_greedy_read(int sockfd, void *buf, size_t count, int timeout_ms);



/*
	args:
		the first three args like the write(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond,
			    return until 'count' bytes has written, or timeout, or some error occur.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1:  block infinite if no available buf whether sockfd is block or non-block, 
 				return until 'count' bytes has written, or some error occur.
	return value:
		0	 	: do nothing;
		positive : the number of bytes written, maybe smaller than 'count', 
				  because timeout but no enough buf available right now;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_force_write(int sockfd, const void *buf, size_t count, int timeout_ms); 


/*
	args:
		the first four args like the recv(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1:  block infinite if no available data whether sockfd is block or non-block, 
 				return until any bytes has been recv, or some error occur.
	return value:
		0	 	: peer closed;
		positive : the number of bytes received;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_recv(int s, void *buf, size_t len, int flags, int timeout_ms);


/*
	args:
		the first six args like the recvfrom(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1:  block infinite if no available buf whether sockfd is block or non-block, 
 				return until any bytes has been received, or some error occur.
	return value:
		0	 	: peer closed;
		positive : the number of bytes received;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_recvfrom(int s, void *buf, size_t len, int flags,
                        			   struct sockaddr *from, socklen_t *fromlen, int timeout_ms);


/*
	args:
		the first four args like the send(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1: block infinite if no available buf whether sockfd is block or non-block, 
 				return until 'len' bytes has been sent, or timeout, some error occur.
	return value:
		positive : the number of characters sent;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_send(int s, const void *buf, size_t len, int flags, int timeout_ms);


/*
	args:
		the first six args like the sendto(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1: block infinite if no available buf whether sockfd is block or non-block, 
 				return until 'len' bytes has been sent, or timeout, some error occur.
	return value:
		positive : the number of characters sent;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_sendto(int s, const void *buf, size_t len, int flags, 
						const struct sockaddr *to, socklen_t tolen, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif

