/*
	2014-02-24, Ver 0.1, created by LiJia(lijia@nismail.iie.ac.cn).

	Add system socket API timeout features, as if the socket was specified to be nonblocking.

	在系统标准SOCKET接口基础上, 增加超时机制, 对于任何类型描述符, 都类似非阻塞操作.
*/

#include "../include/MESA_socket_wrap.h"
#include <sys/types.h> 
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/time.h>
#include <stdarg.h>
       
#ifdef __cplusplus
extern "C"
{
#endif

const char *MESA_sock_wrap_version_VERSION_20160309;


#define MESA_SOCK_DEBUG					(0)

#define MESA_SOCK_FD_MAX					(2048) /* 2.6.8内核以后, 此值不再使用 */

#define MESA_SOCK_INIT_FLAG				(0x20140224) /* this module create date */
#define MESA_SOCK_INT_MAX					(0x7FFFFFFF) /* 0x7FFFFFFF ms is almost 3 day. */

#define MESA_SOCK_OP_READ				(1)
#define MESA_SOCK_OP_WRITE				(2)

/* 此宏定义在man中有, 但在老版的系统中sys/epoll.h竟然没有定义, 需要手工添加 */
#ifndef EPOLLRDHUP
#define EPOLLRDHUP						(0x2000)
#endif


static volatile int __MESA_sock_init_flag__ = 0;
static int __MESA_sock_ep_fd__ = -1;

typedef struct{
	long into_fun_time_ms;
	long cur_time_ms;
	char *op_ptr;
	ssize_t op_len;
	int flag_block;	
	int timeout_ms;
	int original_sock_flags;
}MESA_epoll_arg_t;

typedef struct{
	MESA_sock_errno_t errno_bin;
	const char *errno_str;
}MESA_sock_errno_bin_string_t;


static MESA_sock_errno_bin_string_t G_MESA_SOCK_ERROR[] =
{
	{MESA_SOCK_SUCCESS,				"MESA_SOCK_SUCCESS"},
	{MESA_SOCK_COMMON_ERR,			"MESA_SOCK_COMMON_ERR"},
	{MESA_SOCK_TIMEOUT,				"MESA_SOCK_TIMEOUT"},
	{MESA_SOCK_WOULD_BLOCK,		"MESA_SOCK_WOULD_BLOCK"},
	{MESA_SOCK_PEER_CLOSE,			"MESA_SOCK_PEER_CLOSE"},
	{MESA_SOCK_INVALID_ARG,			"MESA_SOCK_INVALID_ARG"},
	{MESA_SOCK_EPOLL_CREATE_ERR,	"MESA_SOCK_EPOLL_CREATE_ERR"},
};


const char *MESA_sock_strerror(int err_num)
{
	int abs_errno;

	abs_errno = abs(err_num); /* 将负数转换为正整数 */

	if(abs_errno >= abs(__MESA_SOCK_ERRNO_MAX)){
		return "errno is invalid!";
	}

	return G_MESA_SOCK_ERROR[abs_errno].errno_str;
}


static void MESA_SOCK_LOG(char * format, ...)
{
#if MESA_SOCK_DEBUG
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
#endif

    return;
}

long MESA_sock_get_time_ms(void)
{
	struct timeval cur_time;
	long cur_sec, cur_usec;

	gettimeofday(&cur_time, NULL);
	cur_sec = cur_time.tv_sec;
	cur_usec = cur_time.tv_usec;
	
	return cur_sec * 1000 + cur_usec/1000;
}

static inline void MESA_sock_update_time(MESA_epoll_arg_t *mesa_arg)
{
	mesa_arg->cur_time_ms = MESA_sock_get_time_ms();
}


static inline int MESA_sock_is_block(int fd)
{
	int flags = 0;
	
	flags = fcntl(fd, F_GETFL, 0);
	if(flags < 0){
		return 0;
	}
	
	return ((O_NONBLOCK & flags) != 0)?0:1;
}

static inline int MESA_sock_init(void)
{
	if(MESA_SOCK_INIT_FLAG == __MESA_sock_init_flag__){
		return 0;
	}
	
	__MESA_sock_ep_fd__ = epoll_create(MESA_SOCK_FD_MAX);
	if(__MESA_sock_ep_fd__ < 0){
		return MESA_SOCK_EPOLL_CREATE_ERR;
	}

	__MESA_sock_init_flag__ = MESA_SOCK_INIT_FLAG;
	
	return MESA_SOCK_SUCCESS;
}

static inline int MESA_sock_preprocess(int sockfd, const void *buf, size_t count, int timeout_ms, MESA_epoll_arg_t *mesa_arg)
{
	memset(mesa_arg, 0, sizeof(MESA_epoll_arg_t));
	
	mesa_arg->into_fun_time_ms = MESA_sock_get_time_ms();
	mesa_arg->cur_time_ms = mesa_arg->into_fun_time_ms;

	mesa_arg->op_ptr = (char *)buf;
	mesa_arg->op_len = count;

	mesa_arg->flag_block = MESA_sock_is_block(sockfd);

	/* to non-block */
	if(mesa_arg->flag_block != 0){
		mesa_arg->original_sock_flags = fcntl(sockfd, F_GETFL, 0);
		fcntl(sockfd, F_SETFL, mesa_arg->original_sock_flags | O_NONBLOCK);
	}

	if(-1 == timeout_ms){
		mesa_arg->timeout_ms = MESA_SOCK_INT_MAX;
	}else{
		mesa_arg->timeout_ms = timeout_ms;
	}

	return 0;
}

static inline int MESA_sock_recovery(int sockfd, MESA_epoll_arg_t *mesa_arg)
{
	if(mesa_arg->flag_block){
		fcntl(sockfd, F_SETFL, mesa_arg->original_sock_flags);
	}

	return 0;
}

static inline int MESA_sock_timeout(MESA_epoll_arg_t *mesa_arg)
{
	return (mesa_arg->into_fun_time_ms + mesa_arg->timeout_ms < mesa_arg->cur_time_ms)?1:0;
}

static inline long MESA_sock_left_time(MESA_epoll_arg_t *mesa_arg)
{
	long left_time;

	mesa_arg->cur_time_ms = MESA_sock_get_time_ms();

	left_time = mesa_arg->timeout_ms - (mesa_arg->cur_time_ms - mesa_arg->into_fun_time_ms);
	if(left_time < 0){
		return 0;
	}
	
	return left_time;
}


/*
	return value:
		0		: peer closed;
		1		: sockfd is operable;
		negative	: error, see also "MESA_sock_errno_t".
*/
static int MESA_sock_is_operable(int sockfd, int op_type, int timeout_ms)
{
	int i, ret, fun_res = MESA_SOCK_COMMON_ERR;
	struct epoll_event interest_event;
	struct epoll_event monitor_event[MESA_SOCK_FD_MAX];	
	char err_buf[1024];
	int interested_flags, total_monitor_flags, hit_event_flag;
	long raw_timeout, into_fun_time, cur_time;

	ret =  MESA_sock_init();
	if(ret < 0){
		return ret;
	}

	raw_timeout = timeout_ms;
	into_fun_time = MESA_sock_get_time_ms();
	
	if(MESA_SOCK_OP_READ == op_type){
		interested_flags = EPOLLIN;
		total_monitor_flags = EPOLLIN | EPOLLERR | EPOLLRDHUP;
	}else{
		interested_flags = EPOLLOUT;
		total_monitor_flags = EPOLLOUT | EPOLLERR;
	}

	memset(&interest_event, 0, sizeof(struct epoll_event));
	interest_event.events = total_monitor_flags ; /* | EPOLLONESHOT*/
	interest_event.data.fd = sockfd;

	ret = epoll_ctl(__MESA_sock_ep_fd__, EPOLL_CTL_ADD, sockfd, &interest_event);
	if(ret < 0){
		strerror_r(errno, err_buf, 1024);
		MESA_SOCK_LOG("epoll_ctl: ADD fd:%d error:%d, %s\n", sockfd, errno, err_buf);
		switch(errno){
			case EEXIST:
			break;

			default:
				fun_res = MESA_SOCK_COMMON_ERR;
				goto err1;	
		}
	}

retry_wait:
	ret = epoll_wait(__MESA_sock_ep_fd__, monitor_event, MESA_SOCK_FD_MAX, timeout_ms);
	if(0 == ret){
		fun_res = MESA_SOCK_TIMEOUT;
		goto err2;
	}else if(ret < 0){
		switch(errno){
			case EINTR:
				goto retry_wait;
			break;

			default:
				fun_res = MESA_SOCK_COMMON_ERR;
				goto err2;
		}
	}
	
	hit_event_flag = 0;
	for(i = 0; i < ret; i++){
		if(monitor_event[i].data.fd == sockfd){
			/* 先检查错误事件 */
			if(monitor_event[i].events & EPOLLERR){
				fun_res = MESA_SOCK_COMMON_ERR;
				hit_event_flag = 1;
				break;
			}
			if((MESA_SOCK_OP_READ == op_type) && (monitor_event[i].events & EPOLLRDHUP)){
				fun_res = 0;
				hit_event_flag = 1;
				break;
			}
			if(monitor_event[i].events & interested_flags){
				fun_res = 1;
				hit_event_flag = 1;
				break;
			}
		}
	}

	if(0 == hit_event_flag){
		cur_time = MESA_sock_get_time_ms();
		if(cur_time - into_fun_time < raw_timeout){
			timeout_ms = raw_timeout - (cur_time - into_fun_time);
			goto retry_wait;
		}else{
			fun_res = MESA_SOCK_TIMEOUT;
		}
	}

err2:	
	ret = epoll_ctl(__MESA_sock_ep_fd__, EPOLL_CTL_DEL, sockfd, &interest_event);
	if(ret < 0){
		strerror_r(errno, err_buf, 1024);
		MESA_SOCK_LOG("epoll_ctl:DEL error:%d, %s\n", errno, err_buf);
	}

err1:
	return fun_res;
}




/*
	Check a socket can be read or not.
	return value:
		1 		: some data can be read;
		negative 	: maybe timeout, maybe link error, see also "MESA_sock_errno_t".
*/
int MESA_sock_can_be_read(int sockfd, int timeout_ms)
{
	return MESA_sock_is_operable(sockfd, MESA_SOCK_OP_READ, timeout_ms);
}

/*
	Check a socket can be written or not.
	return value:
		1 		: data can be written;
		negative 	: maybe timeout, maybe link error, see also "MESA_sock_errno_t".
*/
int MESA_sock_can_be_write(int sockfd, int timeout_ms)
{
	return MESA_sock_is_operable(sockfd, MESA_SOCK_OP_WRITE, timeout_ms);
}

/*
	Check a sokcet fd status.

	return value:
		0	 : no error;
		other: fd has error.
*/
int MESA_sock_has_error(int sockfd)
{
	int ret, error;
	socklen_t len;

	len = sizeof(error);

	ret = getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len);
	if(ret < 0){
		return ret;
	}

	if(error != 0){
		return error;
	}

	return 0;
}

/*
	args:
		the first three args like the connect(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout, units:millisecond,
			    return until connection succeed, or timeout, some error occur.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1: block infinite, until connection succeed, or some error occur.
	return value:
		0	 	: connection succeed;
		negative : see also "MESA_sock_errno_t".
*/
int MESA_sock_connect(int sockfd, const struct sockaddr  *saptr, socklen_t salen, int timeout_ms)
{
	int ret;
	MESA_epoll_arg_t mesa_epoll_arg;

	MESA_sock_preprocess(sockfd, NULL, 0, timeout_ms, &mesa_epoll_arg);

	if(0 == timeout_ms){
		ret = connect(sockfd, saptr, salen);
		goto recovery;
	}
	
re_connect:
       ret = connect(sockfd, saptr, salen);
       if(ret < 0){
       	switch(errno){
			case EINPROGRESS:
			case EALREADY:
				/* normal, would wait tcp-3-handshake */
			break;
			
			case EINTR:
				goto re_connect;
			break;

			case EISCONN:	
				ret = 0;
				goto recovery;
			break;
			
			default:
				ret = MESA_SOCK_COMMON_ERR;
				goto recovery;
			break;
       	}
	}else if(0 == ret){
		goto test_link_status;
	}

	//ret = MESA_sock_is_operable(sockfd, EPOLLOUT, &mesa_epoll_arg);
	ret = MESA_sock_can_be_write(sockfd, timeout_ms);
	if(1 == ret){
test_link_status:		
		if(MESA_sock_has_error(sockfd) != 0){
			ret = MESA_SOCK_COMMON_ERR;
		}else{
			ret = 0;
		}
	}

recovery:
	MESA_sock_recovery(sockfd, &mesa_epoll_arg);

	return ret;
}

/*
	args:
		the first three args like the read(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond,
			    return until 'count' bytes has been read, or timeout, some error occur.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1: block infinite if no available data whether sockfd is block or non-block, 
 			    return until 'count' bytes has been read, or some error occur.
	return value:
			0	: end of file, or peer closed;
		positive : the number of bytes read, maybe smaller than 'count', 
				  because timeout but fewer bytes are actually available right now;
		negative 	: see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_greedy_read(int sockfd, void *buf, size_t count, int timeout_ms)
{
	int ret = MESA_SOCK_COMMON_ERR;
	MESA_epoll_arg_t mesa_epoll_arg;

	MESA_sock_preprocess(sockfd, buf, count, timeout_ms, &mesa_epoll_arg);

	if(0 == timeout_ms){
		ret = read(sockfd, buf, count);
		goto recovery;
	}
	
	while((mesa_epoll_arg.op_len > 0) && (0 == MESA_sock_timeout(&mesa_epoll_arg))){
re_read:
		ret = read(sockfd, mesa_epoll_arg.op_ptr, mesa_epoll_arg.op_len);
		if(ret < 0){
			switch(errno){
				case EINTR:
					goto re_read;
				break;

				case EAGAIN:
				break;

				default:
					ret = MESA_SOCK_COMMON_ERR;
					goto recovery;
			}
			
			//ret = MESA_sock_is_operable(sockfd, EPOLLIN, &mesa_epoll_arg);
			ret = MESA_sock_is_operable(sockfd,  MESA_SOCK_OP_READ, MESA_sock_left_time(&mesa_epoll_arg));
			if(1 == ret){
				continue;
			}else{
				goto recovery;	
			}
		}else if(0 == ret){
			ret = 0;
			goto recovery;
		}

		mesa_epoll_arg.op_ptr += ret;
		mesa_epoll_arg.op_len -= ret;
		MESA_sock_update_time(&mesa_epoll_arg);
	}
	
recovery:
	MESA_sock_recovery(sockfd, &mesa_epoll_arg);

	if(count - mesa_epoll_arg.op_len > 0){ /* test if already read some data */
		return count - mesa_epoll_arg.op_len;
	}
	
	return ret;
}

/*
	args:
		the first three args like the write(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond,
			    return until 'count' bytes has been written, or timeout, some error occur.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1:  block infinite if no available buf whether sockfd is block or non-block, 
 				return until 'count' bytes has been written, or some error occur.
	return value:
		positive : the number of bytes written, maybe smaller than 'count', 
				  because timeout but no enough buf available right now;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_force_write(int sockfd, const void *buf, size_t count, int timeout_ms)
{
	int ret = MESA_SOCK_COMMON_ERR;
	MESA_epoll_arg_t mesa_epoll_arg;

	if(NULL == buf || 0 == count){
		return 0;
	}
	
	MESA_sock_preprocess(sockfd, buf, count, timeout_ms, &mesa_epoll_arg);

	if(0 == timeout_ms){
		ret = write(sockfd, buf, count);
		goto recovery;
	}
	
	while((mesa_epoll_arg.op_len > 0) && (0 == MESA_sock_timeout(&mesa_epoll_arg))){
re_send:
		ret = write(sockfd, mesa_epoll_arg.op_ptr, mesa_epoll_arg.op_len);
		if(ret < 0){
			switch(errno){
				case EINTR:
					goto re_send;
				break;

				case EAGAIN:
				break;

				case EPIPE:
					ret = MESA_SOCK_PEER_CLOSE;
					goto recovery;
				break;

				default:
					ret = MESA_SOCK_COMMON_ERR;
					goto recovery;
			}

			//ret = MESA_sock_is_operable(sockfd, EPOLLOUT, &mesa_epoll_arg);
			ret = MESA_sock_is_operable(sockfd, MESA_SOCK_OP_WRITE, MESA_sock_left_time(&mesa_epoll_arg));
			if(1 == ret){ 
				continue;
			}else if(0 == ret ){
				ret = MESA_SOCK_TIMEOUT;
				goto recovery;	
			}else{
				goto recovery;	
			}
		}

		mesa_epoll_arg.op_ptr += ret;
		mesa_epoll_arg.op_len -= ret;
		MESA_sock_update_time(&mesa_epoll_arg);
	}

recovery:
	MESA_sock_recovery(sockfd, &mesa_epoll_arg);

	if((int)count - mesa_epoll_arg.op_len > 0){ /* test if already sent some data */
		return (int)count - mesa_epoll_arg.op_len;
	}
	
	return ret;
}

/*
	args:
		three args like the write(2),
		but this function guarantee write count bytes even if buf space is not enough. 
	return value:
		positive : the number of bytes written, maybe smaller than 'count', 
				  because timeout but no enough buf available right now;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_writen(int fd, const void *buf, size_t count)
{
	int ret;
	int unsnd_count = (int)count;
	const char *snd_ptr = (const char *)buf;
	
	while(unsnd_count > 0){
re_send:
		ret = write(fd, snd_ptr, unsnd_count);
		if(ret < 0){
			switch(errno){
				case EINTR:
				case EAGAIN:
				case ENOSPC:
					goto re_send;
				break;

				case EPIPE:
					ret = MESA_SOCK_PEER_CLOSE;
					goto err;
				break;

				default:
					ret = MESA_SOCK_COMMON_ERR;
					goto err;
			}	
		}else{
			snd_ptr += ret;
			unsnd_count -= ret;
		}	
	}

	return count - unsnd_count;
err:
	return ret;
}

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
ssize_t MESA_sock_recv(int s, void *buf, size_t len, int flags, int timeout_ms)
{
	int ret = MESA_SOCK_COMMON_ERR;
	MESA_epoll_arg_t mesa_epoll_arg;

	MESA_sock_preprocess(s, buf, len, timeout_ms, &mesa_epoll_arg);

	if(0 == timeout_ms){
		ret = recv(s, buf, len, flags);
		goto recovery;
	}
	
re_recv:
	ret = recv(s, buf, len, flags);
	if(ret < 0){
		switch(errno){
			case EINTR:
				goto re_recv;
			break;

			case EAGAIN:
			break;

			default:
				ret = MESA_SOCK_COMMON_ERR;
				goto recovery;
		}
		
		ret = MESA_sock_is_operable(s, MESA_SOCK_OP_READ, timeout_ms);
		if(1 == ret){
			ret = recv(s, buf, len, flags);
		}else{
			goto recovery;	
		}
	}
	
recovery:
	MESA_sock_recovery(s, &mesa_epoll_arg);
	
	return ret;
}


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
                        			   struct sockaddr *from, socklen_t *fromlen, int timeout_ms)
{
	int ret = MESA_SOCK_COMMON_ERR;
	MESA_epoll_arg_t mesa_epoll_arg;

	MESA_sock_preprocess(s, buf, len, timeout_ms, &mesa_epoll_arg);

	if(0 == timeout_ms){
		ret =  recvfrom(s, buf, len, flags, from, fromlen);
		goto recovery;
	}
	
re_recv:
	ret = recvfrom(s, buf, len, flags, from, fromlen);
	if(ret < 0){
		switch(errno){
			case EINTR:
				goto re_recv;
			break;

			case EAGAIN:
			break;

			default:
				ret = MESA_SOCK_COMMON_ERR;
				goto recovery;
		}
		
		ret = MESA_sock_is_operable(s, MESA_SOCK_OP_READ, timeout_ms);
		if(1 == ret){
			ret = recvfrom(s, buf, len, flags, from, fromlen);
		}else{
			goto recovery;	
		}
	}
	
recovery:
	MESA_sock_recovery(s, &mesa_epoll_arg);
	
	return ret;
}


/*
	args:
		the first four args like the send(2), 'timeout_ms' arg as follow:
		timeout_ms:
			>0: timeout value, units:millisecond.
 			0 : return immediately, as if the socket was specified to be non-blocking.
 			-1: block infinite if no available buf whether sockfd is block or non-block, 
 				return until 'len' bytes has been sent, or timeout, some error occur.
	return value:
		0		: do nothing.
		positive : the number of characters sent;
		negative : see also "MESA_sock_errno_t".
*/
ssize_t MESA_sock_send(int s, const void *buf, size_t len, int flags, int timeout_ms)
{
	int ret = MESA_SOCK_COMMON_ERR;
	MESA_epoll_arg_t mesa_epoll_arg;

	if(NULL == buf || 0 == len){
		return 0;
	}
	
	MESA_sock_preprocess(s, (void *)buf, len, timeout_ms, &mesa_epoll_arg);

	if(0 == timeout_ms){
		ret =  send(s, buf, len, flags);
		goto recovery;
	}
	
re_send:
	ret = send(s, buf, len, flags);
	if(ret < 0){
		switch(errno){
			case EINTR:
				goto re_send;
			break;

			case EPIPE:
				ret = MESA_SOCK_PEER_CLOSE;
				goto recovery;
			break;

			case EAGAIN:
			case ENOMEM:
			case ENOBUFS:
			break;

			default:
				ret = MESA_SOCK_COMMON_ERR;
				goto recovery;
		}

		ret = MESA_sock_is_operable(s, MESA_SOCK_OP_WRITE, timeout_ms);
		if(1 == ret){
			ret = send(s, buf, len, flags);
		}else{
			goto recovery;	
		}
	}

recovery:
	MESA_sock_recovery(s, &mesa_epoll_arg);
	
	return ret;
}

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
						const struct sockaddr *to, socklen_t tolen, int timeout_ms)
{
	int ret = MESA_SOCK_COMMON_ERR;
	MESA_epoll_arg_t mesa_epoll_arg;

	MESA_sock_preprocess(s, (void *)buf, len, timeout_ms, &mesa_epoll_arg);

	if(0 == timeout_ms){
		ret = sendto(s, buf, len, flags, to, tolen);
		goto recovery;
	}
	
re_send:
	ret = sendto(s, buf, len, flags, to, tolen);
	if(ret < 0){
		switch(errno){
			case EINTR:
				goto re_send;
			break;

			case EPIPE:
				ret = MESA_SOCK_PEER_CLOSE;
				goto recovery;
			break;

			case EAGAIN:
			case ENOMEM:
			case ENOBUFS:
			break;

			default:
				ret = MESA_SOCK_COMMON_ERR;
				goto recovery;
		}

		ret = MESA_sock_is_operable(s, MESA_SOCK_OP_WRITE, timeout_ms);
		if(1 == ret){
			ret = sendto(s, buf, len, flags, to, tolen);
		}else{
			goto recovery;
		}
	}

recovery:
	MESA_sock_recovery(s, &mesa_epoll_arg);
	
	return ret;
}

#ifdef __cplusplus
}
#endif

