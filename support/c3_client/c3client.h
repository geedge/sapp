#ifndef __C3CLIENT_H
#define __C3CLIENT_H

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
 #include <sys/types.h>
       #include <sys/socket.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include "grule.h"
#include "efd_eventfd.h"

#include "ccchdr.h"
#include "util.h"

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


#define SOCKADDR_MAX_NUM 8

#define MESSAGE_MAX_LENGTH 65536


#define C3CLIENT_STATE_IDLE       1
#define C3CLIENT_STATE_CONNECT    2
#define C3CLIENT_STATE_CONNECTING 3
#define C3CLIENT_STATE_CONNECTED  4
#define C3CLIENT_STATE_AUTH_SENDING 5
#define C3CLIENT_STATE_AUTH_SENDED  6
#define C3CLIENT_STATE_AUTH_RECIEVING 7
#define C3CLIENT_STATE_AUTH_RECIEVED 8
#define C3CLIENT_STATE_AUTH_SUCCEEDED 9
#define C3CLIENT_STATE_ACTIVE 10
#define C3CLIENT_STATE_STOPPING 11
#define C3CLIENT_STATE_STOPPED 12

#define C3CLIENT_APPSTATE_IDLE 1
#define C3CLIENT_APPSTATE_CONNECTED 2
#define C3CLIENT_APPSTATE_ACTIVE 3



#define C3CLIENT_INSTATE_IDLE 1
#define C3CLIENT_INSTATE_HDR 2
#define C3CLIENT_INSTATE_BODY 3

#define C3CLIENT_OUTSTATE_IDLE 1
#define C3CLIENT_OUTSTATE_HDR 2
#define C3CLIENT_OUTSTATE_BODY 3


#define C3CLIENT_MAGIC 0xffddeecc

#define AUTHDATA_LENGTH 8
#define CACHED_RULE_NUM 1000


#define C3CLIENT_KASTATE_IDLE 1
#define C3CLIENT_KASTATE_SENDING 2
#define C3CLIENT_KASTATE_RECIEVING 3


#define C3CLIENT_OUTDATA_AUTH 1
#define C3CLIENT_OUTDATA_KA   2
#define C3CLIENT_OUTDATA_DATA 3



struct cached_rst{
	uint64_t user_id;
	uint16_t msg_id;
};

typedef struct __c3client{
	unsigned int       magic;
	pthread_mutex_t    lock;
	int                sock;
	struct sockaddr_in addr[SOCKADDR_MAX_NUM];
	int                addr_no;
	int                addr_index;
	int                state;
	uint8_t            indata[MESSAGE_MAX_LENGTH];
	uint8_t            outdata[MESSAGE_MAX_LENGTH];
	int                indata_len;
	int                indata_len_expect;
	int                outdata_len;
	message_hdr_t      inhdr;
	message_hdr_t      outhdr;
	int                instate;
	int                outstate;
	uint8_t            authdata[AUTHDATA_LENGTH];
	int                c3errno;

	pthread_t          thread_id;
	sem_t              sem_w;
	sem_t              sem_r;

	int                is_stopped;
	int                msg_id;

	int                flag_ignor_result;
	time_t             last_data_time;
	int                keepalive_interval;
	int                kastate;
	int                keepalive_state_out;
	uint32_t           keepalive_state_out_id;
	int                send_data_type;

	grule_t            cached_rule[CACHED_RULE_NUM];
	uint32_t           cached_msgid[CACHED_RULE_NUM];
	volatile size_t             cached_rule_no;
	struct cached_rst  cached_result[CACHED_RULE_NUM];
	size_t             cached_rst_no;

	struct nn_efd      fd_event;

	int                app_state;
	int                flag;
	
}c3client_t;



c3client_t * c3client_open();

int c3client_opt_get(c3client_t * client, int level, int type, void * opt, size_t opt_size);

int c3client_opt_set(c3client_t * client, int level, int type, const void * opt, size_t opt_size);

int c3client_connect(c3client_t * client, const char * addr);

int c3client_send(c3client_t * client, grule_t *rules, size_t rule_num, int flags);

int c3client_recv(c3client_t * client, grule_result_t *rst, size_t rst_num, int flags);


const char * c3client_bad_results_str(grule_result_t *rst);

const char * c3client_error_str(int err_no);

int c3client_errno(c3client_t * client);

int c3client_app_status(c3client_t *client);

/*#define nn_assert(x) \
    do {\
        if (nn_slow (!(x))) {\
            nn_backtrace_print (); \
            fprintf (stderr, "Assertion failed: %s (%s:%d)\n", #x, \
                __FILE__, __LINE__);\
            fflush (stderr);\
            abort ();\
        }\
    } while (0)
*/
/*  Check the condition. If false prints out the errno. */
/*#define errno_assert(x) \
    do {\
        if (nn_slow (!(x))) {\
            nn_backtrace_print (); \
            fprintf (stderr, "%s [%d] (%s:%d)\n", nn_err_strerror (errno),\
                (int) errno, __FILE__, __LINE__);\
            fflush (stderr);\
            abort ();\
        }\
    } while (0)
  */  
/*
* release hdl
*/
int c3client_close(c3client_t * client);

/*
get app status
	return -1 if it failed, otherwise return status
*/


#ifdef __cplusplus
}
#endif


#endif

