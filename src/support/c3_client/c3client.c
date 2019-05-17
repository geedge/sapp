#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include "alloc.h"

#include <sys/eventfd.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <execinfo.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "c3client.h"

void nn_backtrace_print (void)
{
	void *frames[50];
	int size;
	size = backtrace (frames, sizeof (frames) / sizeof (frames[0]));
	if (size > 1) {
		/*  Don't include the frame nn_backtrace_print itself. */
		backtrace_symbols_fd (&frames[1], size-1, fileno (stderr));
	}
}

uint16_t nn_gets (const void * _buf)
{
	const	uint8_t * buf;

	buf = (uint8_t*) _buf;

	return (((uint16_t) buf [0]) << 8) |
		((uint16_t) buf [1]);
}

void nn_puts (void *_buf, uint16_t val)
{
	uint8_t * buf;

	buf = (uint8_t*)_buf;

	buf [0] = (uint8_t) (((val) >> 8) & 0xff);
	buf [1] = (uint8_t) (val & 0xff);
}

uint32_t nn_getl (const void *_buf)
{
	const	uint8_t* buf;

	buf = (uint8_t*)_buf;

	return (((uint32_t) buf [0]) << 24) |
		(((uint32_t) buf [1]) << 16) |
		(((uint32_t) buf [2]) << 8) |
		((uint32_t) buf [3]);
}

void nn_putl (void *_buf, uint32_t val)
{
	uint8_t* buf;
	buf = (uint8_t*)_buf;
	buf [0] = (uint8_t) (((val) >> 24) & 0xff);
	buf [1] = (uint8_t) (((val) >> 16) & 0xff);
	buf [2] = (uint8_t) (((val) >> 8) & 0xff);
	buf [3] = (uint8_t) (val & 0xff);
}

uint64_t nn_getll (const void *_buf)
{
	const uint8_t* buf;
	buf = (uint8_t*)_buf;

	return (((uint64_t) buf [0]) << 56) |
		(((uint64_t) buf [1]) << 48) |
		(((uint64_t) buf [2]) << 40) |
		(((uint64_t) buf [3]) << 32) |
		(((uint64_t) buf [4]) << 24) |
		(((uint64_t) buf [5]) << 16) |
		(((uint64_t) buf [6]) << 8) |
		(((uint64_t) buf [7] << 0));
}

void nn_putll (uint8_t *buf, uint64_t val)
{
	buf [0] = (uint8_t) ((val >> 56) & 0xff);
	buf [1] = (uint8_t) ((val >> 48) & 0xff);
	buf [2] = (uint8_t) ((val >> 40) & 0xff);
	buf [3] = (uint8_t) ((val >> 32) & 0xff);
	buf [4] = (uint8_t) ((val >> 24) & 0xff);
	buf [5] = (uint8_t) ((val >> 16) & 0xff);
	buf [6] = (uint8_t) ((val >> 8) & 0xff);
	buf [7] = (uint8_t) (val & 0xff);
}

/*
   pthread_mutex_t    lock;
   int                fd;
   struct sockaddr_in addr[SOCKADDR_MAX_NUM];
   int                addr_no;
   int                addr_index;
   int                state;
   uint8_t            indata[MESSAGE_MAX_LENGTH];
   uint8_t            outdata[MESSAGE_MAX_LENGTH];
   int                indata_len;
   int                outdata_len;
   message_hdr_t      inhdr;
   message_hdr_t      outhdr;
   int                instate;
   int                outstate;
   uint8_t            authdata[8];
   int                c3errno;

   pthread_t          thread_id;
   sem_t              sem_w;
   sem_t              sem_r;

   int                flag_ignor_result;
   time_t             last_data_time;
   int                keepalive_interval;
   */

c3client_t * c3client_open()
{

	c3client_t *c3;

	c3 = (c3client_t*) nn_alloc( sizeof(c3client_t), "c3client");

	if(!c3) return c3;

	memset(c3, 0, sizeof(c3client_t));
	c3->magic = C3CLIENT_MAGIC;
	pthread_mutex_init(&c3->lock, NULL);
	//c3->fd  = -1;
	c3->sock = -1;
	c3->state = C3CLIENT_STATE_IDLE;
	c3->instate = C3CLIENT_INSTATE_IDLE;
	c3->outstate = C3CLIENT_OUTSTATE_IDLE;
	c3->kastate = C3CLIENT_KASTATE_IDLE;
	sem_init(&c3->sem_w, 0, 0);
	sem_init(&c3->sem_r, 0, 0);
	c3->keepalive_interval = 15;
	c3->app_state = GRULE_APP_STATUS_IDLE;

	nn_efd_init(&c3->fd_event);

	return c3;
}


static inline void c3client_lock(c3client_t * client)
{
	pthread_mutex_lock(&client->lock);
}

static inline void c3client_unlock(c3client_t *client)
{
	pthread_mutex_unlock(&client->lock);
}


int c3client_opt_get(c3client_t * client, int level, int type, void * opt, size_t opt_size)
{
	int opt_data;
	nn_assert(client->magic == C3CLIENT_MAGIC);

	if(level == GRULE_SOL_PROTO && type == GRULE_TYPE_AUTH){

		if(opt_size != 8){
			return -1;
		}
		c3client_lock(client);
		memcpy(client->authdata, opt, opt_size);
		c3client_unlock(client);
	}else if(level == GRULE_SOL_PROTO && type == GRULE_TYPE_NONBLOCK){
		if(opt_size != 4){
			return -1;
		}
		c3client_lock(client);
                //memcpy(client->authdata, opt, opt_size);
                /*memcpy(&opt_data, opt, 4);
		if(opt_data){
			client->flag |= 1;
		}else{
			client->flag &= ~1u;
		}*/
		opt_data = (client->flag & 1) ? 1 : 0;
		memcpy(opt, &opt_data, 4);
                c3client_unlock(client);
	}else{
		nn_assert(0);
	}
	return 0;
}

int c3client_opt_set(c3client_t * client, int level, int type, const void * opt, size_t opt_size)
{

	int opt_data;
	nn_assert(client->magic == C3CLIENT_MAGIC);

	if(level == GRULE_SOL_PROTO && type == GRULE_TYPE_AUTH){

		if(opt_size < 8){
			return -1;
		}
		c3client_lock(client);
		memcpy( client->authdata, opt ,opt_size);
		c3client_unlock(client);
	}else if(level == GRULE_SOL_PROTO && type == GRULE_TYPE_NONBLOCK){

		if(opt_size != 4){
                        return -1;
                }
		c3client_lock(client);
		memcpy(&opt_data, opt, 4);
		if(opt_data){
			client->flag |= 1;
		}else{
			client->flag &= ~1u;
		}	
		c3client_unlock(client);
	}

	return 0;

}

static int ccc_auth_check(const uint8_t * data, size_t size)
{
	message_hdr_t hdr;
	uint16_t      resp_code;

	if(do_checksum(data, size) != 0 ){
		return -1;
	}

	memcpy(&hdr, data, sizeof(hdr));

	if(hdr.version != CCC_VERSION){
		return -1;
	}

	if(hdr.msg_type != CCC_CMD_AUTH){
		return -1;
	}

	if(nn_gets((uint8_t*)&hdr.msg_code) != CCC_CMD_AUTH_REP){
		return -1;
	}

	if(nn_getl((uint8_t*)&hdr.msg_id) != 1){
		return -1;
	}

	hdr.len_flag &= 0xff3f;

	if(nn_gets((uint8_t*)&hdr.len_flag) != size){
		return -1;
	}

	if(nn_gets((uint8_t*)&hdr.msg_count) != 1){
		return -1;
	}

	if(hdr.resv != 0){
		return -1;
	}

	//if(nn_gets(data + sizeof(hdr)) != )

	resp_code = nn_gets(data + sizeof(hdr));

	if(resp_code == 0x00){
		return 0;
	}

	if(resp_code == 0x11){
		return 1;
	}
	return -1;
}


/*
   typedef struct{
   uint8_t  version;
   uint8_t  msg_type;
   uint16_t msg_code;
   uint32_t msg_id;
#if  __BYTE_ORDER == __BIG_ENDIAN
uint16_t more_flag:2;
uint16_t msg_len:14;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
union{
struct{
uint8_t  msg_len1:6;
uint8_t  more_flag:2;
uint8_t  msg_len2;		
};
uint16_t len_flag;
};
#else 
#error "Please fix <bits/endian.h>"
#endif
uint16_t  msg_count;
uint16_t  resv;
uint16_t  checksum;
}message_hdr_t;


*/

static int do_fill_auth(uint8_t *data, size_t * size, uint8_t * authdata)
{
	message_hdr_t hdr;
	//uint16_t     cksum;
	cksum_vec_t vec[2];

	nn_assert(*size >= sizeof(message_hdr_t) + AUTHDATA_LENGTH);

	memset(&hdr, 0, sizeof(hdr));

	hdr.version  = CCC_VERSION;
	hdr.msg_type = CCC_CMD_AUTH;
	//hdr->msg_code = CCC_CMD_
	nn_puts(&hdr.msg_code, CCC_CMD_AUTH_REQ);
	nn_putl((uint8_t*)&hdr.msg_id, 1);
	nn_puts((uint8_t*)&hdr.len_flag, 8 + sizeof(message_hdr_t));
	nn_puts((uint8_t*)&hdr.msg_count, 1);

	vec[0].data = (uint8_t*)&hdr;
	vec[0].size = sizeof(hdr);
	vec[1].data = (uint8_t*)authdata;
	vec[1].size = AUTHDATA_LENGTH;

	hdr.checksum = do_checksum_multidata(vec, 2);

	memcpy(data, &hdr, sizeof(hdr));
	memcpy(data + sizeof(hdr), authdata, sizeof(hdr));

	*size = sizeof(message_hdr_t) + AUTHDATA_LENGTH;
	return 0;
}

static int do_fill_keepalive(uint8_t *data, size_t * size, uint32_t msg_id, int is_req)
{
	message_hdr_t hdr;
	//uint16_t     cksum;
	cksum_vec_t vec[2];

	nn_assert(*size >= sizeof(message_hdr_t));

	memset(&hdr, 0, sizeof(hdr));

	hdr.version  = CCC_VERSION;
	hdr.msg_type = CCC_CMD_KEEPALIVE;
	//hdr->msg_code = CCC_CMD_
	if(is_req){
		nn_puts(&hdr.msg_code, CCC_CMD_KEEPALIVE_REQ);
	}else{
		nn_puts(&hdr.msg_code, CCC_CMD_KEEPALIVE_REP);
	}
	nn_putl((uint8_t*)&hdr.msg_id, msg_id);
	nn_puts((uint8_t*)&hdr.len_flag, sizeof(message_hdr_t));
	nn_puts((uint8_t*)&hdr.msg_count, 1);

	vec[0].data = (uint8_t*)&hdr;
	vec[0].size = sizeof(hdr);
	//vec[1].data = authdata;
	//vec[1].size = AUTHDATA_LENGTH;

	hdr.checksum = do_checksum_multidata(vec, 1);

	memcpy(data, &hdr, sizeof(hdr));
	//memcpy(data + sizeof(hdr), authdata, sizeof(hdr));

	*size = sizeof(message_hdr_t);
	return 0;
}


int c3client_hdr_check(uint8_t * data, size_t size)
{
	message_hdr_t hdr;
	uint32_t len = 0;

	memcpy(&hdr, data, sizeof(hdr));

	if(hdr.version != CCC_VERSION){
		return -1;
	}

	if(hdr.msg_type != CCC_CMD_AUTH && hdr.msg_type != CCC_CMD_KEEPALIVE && hdr.msg_type != CCC_CMD_DATA){
		return -1;
	}

	if(hdr.msg_type == CCC_CMD_AUTH && nn_gets((uint8_t*)&hdr.msg_code) != CCC_CMD_AUTH_REP){
		return -1;
	}

	if(hdr.msg_type == CCC_CMD_KEEPALIVE && 
			(nn_gets((uint8_t*)&hdr.msg_code) != CCC_CMD_KEEPALIVE_REP && nn_gets((uint8_t*)&hdr.msg_code) != CCC_CMD_KEEPALIVE_REQ)){
		//len = (nn_gets(&hdr.len_flag) & 0x3ffff);
		return -1;
	}


	if(hdr.msg_type == CCC_CMD_DATA && nn_gets((uint8_t*)&hdr.msg_code) != CCC_CMD_FDATA_REP){
		return -1;
	}

	if(hdr.resv != 0){
		return -1;
	}

	len = (nn_gets(&hdr.len_flag) & 0x3fff);

	if(len == 0 && hdr.msg_type != CCC_CMD_KEEPALIVE){
		return -1;
	}

	if(hdr.msg_type == CCC_CMD_KEEPALIVE){
		if(do_checksum(data, size) != 0){
			return -1;
		}else{
			return 0;
		}
	}
	return (int)len;

}

static int c3client_keepalive_in(c3client_t * client)
{
	message_hdr_t hdr;
	uint8_t * data; 
	//size_t size;
	//uint32_t len = 0;

	data = client->indata;
	//size = client->indata_len;

	memcpy(&hdr, data, sizeof(hdr));
	uint16_t cmd;

	cmd = nn_gets(&hdr.msg_code);
	if(cmd == CCC_CMD_KEEPALIVE_REQ){
		client->keepalive_state_out = 1;
		client->keepalive_state_out_id = nn_getl(&hdr.msg_id);
	}

	client->last_data_time = time(NULL) + client->keepalive_interval;
	return 0;

}

static int c3client_data_rep(c3client_t *client)
{
	message_hdr_t hdr;
	uint8_t * data; 
	//size_t size;
	//uint32_t len = 0;
	uint32_t rst_no;
	unsigned short rst;

	data = client->indata;
	//size = client->indata_len;

	rst = nn_gets(data + sizeof(message_hdr_t));

	memcpy(&hdr, data, sizeof(hdr));

	if(nn_gets(&hdr.msg_code) != CCC_CMD_FDATA_REP){
		return -1;
	}

	rst_no = nn_gets(&hdr.msg_count);

	if(rst_no * sizeof(unsigned short) + sizeof(message_hdr_t) != (size_t)client->indata_len){
		return -1;
	}

	if(rst != 0x0000){
		fprintf(stderr, "response %04x\n", rst);
	}


	return 0;

}

static int c3client_in(c3client_t * client)
{
	int ret;
	switch(client->instate){
		case C3CLIENT_INSTATE_HDR:
			ret = c3client_hdr_check(client->indata, client->indata_len);
			if(ret > 0){
				client->instate = C3CLIENT_INSTATE_BODY;
				client->indata_len_expect += ret - sizeof(message_hdr_t);
				return 0;
			}else if(ret == 0){
				c3client_keepalive_in(client);
				client->instate = C3CLIENT_INSTATE_HDR;
				client->indata_len_expect = sizeof(message_hdr_t);
				client->indata_len  = 0;
				return 0;
			}else{
				return -1;
			}
			break;
		case C3CLIENT_INSTATE_BODY:
			if(do_checksum(client->indata, client->indata_len) != 0){
				return -1;
			}
			ret = c3client_data_rep(client);
			if(ret != 0){
				return -1;
			}
			client->indata_len_expect = sizeof(message_hdr_t);
			client->indata_len  = 0;
			client->instate = C3CLIENT_INSTATE_HDR;
			break;

		default:
			nn_assert(0);
	};

	client->last_data_time = time(NULL) + client->keepalive_interval;
	return 0;
}

static int c3client_out(c3client_t * client)
{
	if(client->send_data_type == C3CLIENT_OUTDATA_AUTH){

	}else if(client->send_data_type == C3CLIENT_OUTDATA_KA){

	}else if(client->send_data_type == C3CLIENT_OUTDATA_DATA){

	}
	return 0;
}

static int do_check_rule(grule_t * rule)
{
	//uint8_t      *ptr;
	//uint32_t      data_len;

	//uint32_t chl_id;



	if(rule->rule_scope & 0xff000000){
		return -1;
	}

	grule_type_t rule_type;

	rule_type = rule->rule_type;

	if(rule_type.grule_type == 0) return -1;



	switch(rule->big_type){
		case GRULE_BIG_TYPE_SIMPLE4:
			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				if(rule->s4.sip == 0) return -1;
				rule_type.sip_flag = 0;
			}

			if(rule_type.dip_flag){
				if(rule->s4.dip == 0) return -1;
				rule_type.dip_flag = 0;
			}

			if(rule_type.sport_flag){
				if(rule->s4.sport == 0) return -1;
				rule_type.sport_flag = 0;
			}

			if(rule_type.dport_flag){
				if(rule->s4.dport == 0) return -1;
				rule_type.dport_flag = 0;
			}

			if(rule_type.proto_flag){
				if(rule->s4.proto == 0) return -1;
				rule_type.proto_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}

			break;
		case GRULE_BIG_TYPE_SIMPLE6:
			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				rule_type.sip_flag = 0;
			}

			if(rule_type.dip_flag){
				rule_type.dip_flag = 0;
			}

			if(rule_type.sport_flag){
				rule_type.sport_flag = 0;
			}

			if(rule_type.dport_flag){
				rule_type.dport_flag = 0;
			}

			if(rule_type.proto_flag){
				rule_type.proto_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}
			break;
		case GRULE_BIG_TYPE_MASK4:
			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				if(rule->m4.sip == 0) return -1;
				rule_type.sip_flag = 0;
			}

			if(rule_type.sipmsk_flag){
				if(rule->m4.sip_mask == 0) return -1;
				//nn_putl(data + data_len, );
				rule_type.sipmsk_flag = 0;
			}

			if(rule_type.dip_flag){
				if(rule->m4.dip == 0) return -1;
				rule_type.dip_flag = 0;
			}

			if(rule_type.dipmsk_flag){
				if(rule->m4.dip_mask == 0) return -1;
				//nn_putl(data + data_len, );
				rule_type.dipmsk_flag = 0;
			}

			if(rule_type.sport_flag){
				if(rule->m4.sport == 0) return -1;
				rule_type.sport_flag = 0;
			}

			if(rule_type.spmsk_flag){
				if(rule->m4.sport_mask == 0) return -1;
				//nn_putl(data + data_len, );
				rule_type.spmsk_flag = 0;
			}

			if(rule_type.dport_flag){
				if(rule->m4.dport == 0) return -1;
				rule_type.dport_flag = 0;
			}

			if(rule_type.dpmsk_flag){
				if(rule->m4.dport_mask == 0) return -1;
				//nn_putl(data + data_len, );
				rule_type.dpmsk_flag = 0;
			}

			if(rule_type.proto_flag){
				if(rule->m4.proto == 0) return -1;
				rule_type.proto_flag = 0;
			}

			if(rule_type.pmsk_flag){
				if(rule->m4.proto_mask == 0) return -1;
				//nn_putl(data + data_len, );
				rule_type.pmsk_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}
			break;
		case GRULE_BIG_TYPE_MASK6:

			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				rule_type.sip_flag = 0;
			}

			if(rule_type.sipmsk_flag){
				//nn_putl(data + data_len, );
				rule_type.sipmsk_flag = 0;
			}

			if(rule_type.dip_flag){
				rule_type.dip_flag = 0;
			}
			if(rule_type.dipmsk_flag){
				rule_type.dipmsk_flag = 0;
			}


			if(rule_type.sport_flag){
				rule_type.sport_flag = 0;
			}

			if(rule_type.spmsk_flag){
				rule_type.spmsk_flag = 0;
			}

			if(rule_type.dport_flag){
				rule_type.dport_flag = 0;
			}

			if(rule_type.dpmsk_flag){
				rule_type.dpmsk_flag = 0;
			}

			if(rule_type.proto_flag){
				rule_type.proto_flag = 0;
			}

			if(rule_type.pmsk_flag){
				rule_type.pmsk_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}
			break;
		default:
			return -1;
	}

	return 0;
}

static int do_fill_data(uint8_t *data, size_t *size, uint32_t msg_id, grule_t * rule)
{
	message_hdr_t hdr;
	channel_hdr_t chl;
	ip_rule_hdr_t rule_hdr;
	//uint8_t      *ptr;
	uint32_t      data_len;
	uint32_t      routekey;

	uint32_t chl_id;

	cksum_vec_t vec[4];


	memset(&hdr, 0, sizeof(hdr));
	memset(&rule_hdr, 0, sizeof(rule_hdr));

	hdr.version = CCC_VERSION;
	hdr.msg_type = CCC_CMD_DATA;
	nn_puts(&hdr.msg_code, CCC_CMD_FDATA_REQ);
	nn_putl(&hdr.msg_id, msg_id);
#ifdef PERMORMANCE_DEBUG
	int i;
	//grule_type_t rule_type;
	nn_puts(&hdr.msg_count, PERFORMANCE_RULE_COUNT);
#else
	nn_puts(&hdr.msg_count, 1);
#endif
	chl.dev_type = CCC_ROUTE_G;

	if(rule->rule_scope & 0xff000000){
		return -1;
	}

	//nn_putl(&chl_id, rule->rule_scope);
	chl_id = rule->rule_scope;
	//chl_id >>= 8;
	//chl.chnl_id = chl_id;

	routekey = ( ( (uint32_t)CCC_ROUTE_G & 0x1f) << 27 ) | ((uint32_t)chl_id & 0x7fffffff);
	nn_putl(&chl.route_key, routekey);


	rule_hdr.serv_type = rule->srv_type;

	//ptr = 
	data_len = sizeof(message_hdr_t) + sizeof(channel_hdr_t) + sizeof(ip_rule_hdr_t);


	/*
#define GRULE_BIG_TYPE_SIMPLE4   1
#define GRULE_BIG_TYPE_SIMPLE6   2
#define GRULE_BIG_TYPE_MASK4     3
#define GRULE_BIG_TYPE_MASK6     4
*/

	grule_type_t rule_type;

	rule_type = rule->rule_type;

	if(rule_type.grule_type == 0) return -1;

	if(rule->big_type == GRULE_BIG_TYPE_SIMPLE4 || rule->big_type == GRULE_BIG_TYPE_MASK4){
		rule_hdr.ipv6 = 0;
	}else if(rule->big_type == GRULE_BIG_TYPE_SIMPLE6 || rule->big_type == GRULE_BIG_TYPE_MASK6){
		rule_hdr.ipv6 = 1;
	}

	if(!rule->durable){
		rule_hdr.durable = 1;
	}

	if(rule->action == 0){
		rule_hdr.action = 0;
	}else{
		rule_hdr.action = 1;
	}

	if(rule_type.sip_flag){
		rule_hdr.sip_flag = 1;
	}

	if(rule_type.dip_flag){
		rule_hdr.dip_flag = 1;
	}

	if(rule_type.sport_flag){
		rule_hdr.sport_flag = 1;
	}

	if(rule_type.dport_flag){
		rule_hdr.dport_flag = 1;
	}

	if(rule_type.proto_flag){
		rule_hdr.proto_flag = 1;
	}

	if(rule_type.sipmsk_flag){
		rule_hdr.sipmsk_flag = 1;
	}

	if(rule_type.dipmsk_flag){
		rule_hdr.dipmsk_flag = 1;
	}

	if(rule_type.spmsk_flag){
		rule_hdr.spmsk_flag = 1;
	}

	if(rule_type.dpmsk_flag){
		rule_hdr.dpmsk_flag = 1;
	}

	if(rule_type.pmsk_flag){
		rule_hdr.pmsk_flag = 1;
	}

#ifdef PERMORMANCE_DEBUG
	for(i = 0; i < PERFORMANCE_RULE_COUNT; i++){
	rule_type = rule->rule_type;
#endif
	switch(rule->big_type){
		case GRULE_BIG_TYPE_SIMPLE4:
			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->s4.sip, sizeof(rule->s4.sip));
				data_len += sizeof(rule->s4.sip);
				rule_type.sip_flag = 0;
			}

			if(rule_type.dip_flag){
				memcpy(data + data_len, &rule->s4.dip, sizeof(rule->s4.dip));
				data_len += sizeof(rule->s4.dip);
				rule_type.dip_flag = 0;
			}

			if(rule_type.sport_flag){
				memcpy(data + data_len, &rule->s4.sport, sizeof(rule->s4.sport));
				data_len += sizeof(rule->s4.sport);
				rule_type.sport_flag = 0;
			}

			if(rule_type.dport_flag){
				memcpy(data + data_len, &rule->s4.dport, sizeof(rule->s4.dport));
				data_len += sizeof(rule->s4.dport);
				rule_type.dport_flag = 0;
			}

			if(rule_type.proto_flag){
				memcpy(data + data_len, &rule->s4.proto, sizeof(rule->s4.proto));
				data_len += sizeof(rule->s4.proto);
				rule_type.proto_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}

			break;
		case GRULE_BIG_TYPE_SIMPLE6:
			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->s6.sip, sizeof(rule->s6.sip));
				data_len += sizeof(rule->s6.sip);
				rule_type.sip_flag = 0;
			}

			if(rule_type.dip_flag){
				memcpy(data + data_len, &rule->s6.dip, sizeof(rule->s6.dip));
				data_len += sizeof(rule->s6.dip);
				rule_type.dip_flag = 0;
			}

			if(rule_type.sport_flag){
				memcpy(data + data_len, &rule->s6.sport, sizeof(rule->s6.sport));
				data_len += sizeof(rule->s6.sport);
				rule_type.sport_flag = 0;
			}

			if(rule_type.dport_flag){
				memcpy(data + data_len, &rule->s6.dport, sizeof(rule->s6.dport));
				data_len += sizeof(rule->s6.dport);
				rule_type.dport_flag = 0;
			}

			if(rule_type.proto_flag){
				memcpy(data + data_len, &rule->s6.proto, sizeof(rule->s6.proto));
				data_len += sizeof(rule->s6.proto);
				rule_type.proto_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}
			break;
		case GRULE_BIG_TYPE_MASK4:
			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m4.sip, sizeof(rule->m4.sip));
				data_len += sizeof(rule->m4.sip);
				rule_type.sip_flag = 0;
			}

			if(rule_type.sipmsk_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m4.sip_mask, sizeof(rule->m4.sip_mask));
				data_len += sizeof(rule->m4.sip_mask);
				rule_type.sipmsk_flag = 0;
			}

			if(rule_type.dip_flag){
				memcpy(data + data_len, &rule->m4.dip, sizeof(rule->m4.dip));
				data_len += sizeof(rule->m4.dip);
				rule_type.dip_flag = 0;
			}

			if(rule_type.dipmsk_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m4.dip_mask, sizeof(rule->m4.dip_mask));
				data_len += sizeof(rule->m4.dip_mask);
				rule_type.dipmsk_flag = 0;
			}

			if(rule_type.sport_flag){
				memcpy(data + data_len, &rule->m4.sport, sizeof(rule->m4.sport));
				data_len += sizeof(rule->m4.sport);
				rule_type.sport_flag = 0;
			}

			if(rule_type.spmsk_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m4.sport_mask, sizeof(rule->m4.sport_mask));
				data_len += sizeof(rule->m4.sport_mask);
				rule_type.spmsk_flag = 0;
			}

			if(rule_type.dport_flag){
				memcpy(data + data_len, &rule->m4.dport, sizeof(rule->m4.dport));
				data_len += sizeof(rule->m4.dport);
				rule_type.dport_flag = 0;
			}

			if(rule_type.dpmsk_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m4.dport_mask, sizeof(rule->m4.dport_mask));
				data_len += sizeof(rule->m4.dport_mask);
				rule_type.dpmsk_flag = 0;
			}

			if(rule_type.proto_flag){
				memcpy(data + data_len, &rule->m4.proto, sizeof(rule->m4.proto));
				data_len += sizeof(rule->m4.proto);
				rule_type.proto_flag = 0;
			}

			if(rule_type.pmsk_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m4.proto_mask, sizeof(rule->m4.proto_mask));
				data_len += sizeof(rule->m4.proto_mask);
				rule_type.pmsk_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}
			break;
		case GRULE_BIG_TYPE_MASK6:

			if(rule_type.sip_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m6.sip, sizeof(rule->m6.sip));
				data_len += sizeof(rule->m6.sip);
				rule_type.sip_flag = 0;
			}

			if(rule_type.sipmsk_flag){
				//nn_putl(data + data_len, );
				memcpy(data + data_len, &rule->m6.sip_mask, sizeof(rule->m6.sip));
				data_len += sizeof(rule->m6.sip);
				rule_type.sipmsk_flag = 0;
			}

			if(rule_type.dip_flag){
				memcpy(data + data_len, &rule->m6.dip, sizeof(rule->m6.dip));
				data_len += sizeof(rule->m6.dip);
				rule_type.dip_flag = 0;
			}
			if(rule_type.dipmsk_flag){
				memcpy(data + data_len, &rule->m6.dip_mask, sizeof(rule->m6.dip_mask));
				data_len += sizeof(rule->m6.dip_mask);
				rule_type.dipmsk_flag = 0;
			}


			if(rule_type.sport_flag){
				memcpy(data + data_len, &rule->m6.sport, sizeof(rule->m6.sport));
				data_len += sizeof(rule->m6.sport);
				rule_type.sport_flag = 0;
			}

			if(rule_type.spmsk_flag){
				memcpy(data + data_len, &rule->m6.sport_mask, sizeof(rule->m6.sport_mask));
				data_len += sizeof(rule->m6.sport_mask);
				rule_type.spmsk_flag = 0;
			}

			if(rule_type.dport_flag){
				memcpy(data + data_len, &rule->m6.dport, sizeof(rule->m6.dport));
				data_len += sizeof(rule->m6.dport);
				rule_type.dport_flag = 0;
			}

			if(rule_type.dpmsk_flag){
				memcpy(data + data_len, &rule->m6.dport_mask, sizeof(rule->m6.dport_mask));
				data_len += sizeof(rule->m6.dport);
				rule_type.dpmsk_flag = 0;
			}

			if(rule_type.proto_flag){
				memcpy(data + data_len, &rule->m6.proto, sizeof(rule->m6.proto));
				data_len += sizeof(rule->m6.proto);
				rule_type.proto_flag = 0;
			}

			if(rule_type.pmsk_flag){
				memcpy(data + data_len, &rule->m6.proto_mask, sizeof(rule->m6.proto_mask));
				data_len += sizeof(rule->m6.proto_mask);
				rule_type.pmsk_flag = 0;
			}

			if(rule_type.grule_type != 0){
				return -1;
			}
			break;
		default:
			return -1;
	}
#ifdef PERMORMANCE_DEBUG
	}
#endif
	nn_puts(&hdr.len_flag, data_len);
	vec[0].data = (uint8_t*)&hdr;
	vec[0].size = sizeof(hdr);
	vec[1].data = (uint8_t*)&chl;
	vec[1].size = sizeof(chl);
	vec[2].data = (uint8_t*)&rule_hdr;
	vec[2].size = sizeof(rule_hdr);
	vec[3].data = data + sizeof(hdr) + sizeof(chl) + sizeof(rule_hdr);
	vec[3].size = data_len - sizeof(hdr) - sizeof(chl) - sizeof(rule_hdr);

	hdr.checksum = do_checksum_multidata(vec, 4);
	memcpy(data, &hdr, sizeof(hdr));
	memcpy(data + sizeof(hdr), &chl, sizeof(chl));
	memcpy(data + sizeof(hdr) + sizeof(chl), &rule_hdr, sizeof(rule_hdr));

	*size = data_len;
	return 0;
}

int c3client_app_status(c3client_t *client)
{
	nn_assert(client->magic == C3CLIENT_MAGIC);
	switch(client->app_state){
		case GRULE_APP_STATUS_ACTIVE:
			//return GRULE_APP_STATUS_ACTIVE;
		case GRULE_APP_STATUS_IDLE:
			return client->app_state;
		case GRULE_APP_STATUS_CONNECTED:
			client->app_state = GRULE_APP_STATUS_ACTIVE;
			return GRULE_APP_STATUS_CONNECTED;
		default:
			nn_assert(0);
	}
	return 0;
}

static void * c3client_process(void * c3)
{

#define PIPE_IN  1
#define PIPE_OUT 2

	c3client_t *client;
	int ret;
	int flags;
	fd_set pollset, pollset_in, pollset_out;
	int maxfd;
	struct timeval tv;
	size_t size;
	size_t data_size;
	time_t curr_time;
	char buf[256];

	client = (c3client_t *)c3;

	nn_assert(client != NULL && client->magic == C3CLIENT_MAGIC);

	while(!client->is_stopped){
		//
__begin:
		switch(client->state){
			case C3CLIENT_STATE_CONNECT:
				sleep(1);
				client->app_state = C3CLIENT_APPSTATE_IDLE;
				if(client->sock >= 0) close(client->sock);
				client->sock = socket(AF_INET, SOCK_STREAM, 0);
				nn_assert(client->sock >= 0);
				flags = fcntl (client->sock , F_GETFL, 0);
				if (flags == -1)
					flags = 0;
				ret = fcntl (client->sock, F_SETFL, flags | O_NONBLOCK);
				errno_assert (ret != -1);

				ret = connect(client->sock, (struct sockaddr*)&client->addr[client->addr_index], sizeof(struct sockaddr_in));
				client->addr_index = (client->addr_index + 1) % client->addr_no;
				if(ret < 0 && errno == EINPROGRESS){
					client->state = C3CLIENT_STATE_CONNECTING;
					continue;
				}else if(ret == 0){
					client->state = C3CLIENT_STATE_CONNECTED;
				}
				break;
			case C3CLIENT_STATE_CONNECTING:
				FD_ZERO (&pollset);
				FD_SET (client->sock, &pollset);
				maxfd = client->sock + 1;
				//tv.tv_sec = 1;
				//tv.tv_usec = 0;
				ret = select (maxfd, NULL,&pollset, NULL, NULL);
				errno_assert (ret >= 0);

				//nn_assert(FD_ISSET(client->sock, &pollset));
				if(FD_ISSET(client->sock, &pollset)){
					client->state = C3CLIENT_STATE_CONNECTED;
				}else{
					client->state = C3CLIENT_STATE_CONNECT;
				}
				break;
			case C3CLIENT_STATE_CONNECTED:
				client->msg_id = 2;
				size =  sizeof(client->outdata);
				do_fill_auth(client->outdata, &size, client->authdata);
				client->outdata_len = size;
				ret = send(client->sock, client->outdata, client->outdata_len, 0);
				//nn_assert();
				if(ret ==  client->outdata_len){
					client->outdata_len = 0;
					client->state = C3CLIENT_STATE_AUTH_SENDED;
					break;
				}else if(ret > 0){
					memmove(client->outdata, client->outdata + ret, client->outdata_len - ret);
					client->outdata_len -= ret;
				}else if(ret < 0 && ( errno == EAGAIN  || errno == EWOULDBLOCK)) {

				}else{
					client->state = C3CLIENT_STATE_CONNECT;
					break;
				}
				while(client->outdata_len > 0){
					FD_ZERO(&pollset);
					FD_SET(client->sock, &pollset);
					maxfd = client->sock + 1;
					ret = select(maxfd, NULL, &pollset, NULL, NULL);
					errno_assert(ret >= 0);
					if(FD_ISSET(client->sock, &pollset)){
						ret = send(client->sock, client->outdata, client->outdata_len, 0);
						if(ret > 0){
							memmove(client->outdata, client->outdata + ret, client->outdata_len - ret);
							client->outdata_len -= ret;
							continue;
						}else if(ret < 0 && (errno == EAGAIN  || errno == EWOULDBLOCK)){
							continue;
						}else{
							client->state = C3CLIENT_STATE_CONNECT;
							goto __begin;
						}
					}
				}
				nn_assert(client->outdata_len == 0);
				client->state = C3CLIENT_STATE_AUTH_SENDED;
				break;
			case C3CLIENT_STATE_AUTH_SENDED:
				data_size = sizeof(message_hdr_t) + 2;
				client->indata_len = 0;
				while((size_t)client->indata_len < data_size){
					FD_ZERO(&pollset);
					FD_SET(client->sock, &pollset);
					maxfd = client->sock + 1;
					ret = select(maxfd, &pollset, NULL, NULL, NULL);
					errno_assert(ret >= 0);
					ret = recv(client->sock, client->indata + client->indata_len, data_size - client->indata_len, 0);

					if(ret > 0){
						client->indata_len += ret;
						continue;
					}else if(ret < 0 && (errno == EAGAIN  || errno == EWOULDBLOCK)){

					}else{
						client->state = C3CLIENT_STATE_CONNECT;
						goto __begin;
					}
				}
				nn_assert((size_t)client->indata_len == data_size);
				ret = do_checksum(client->indata, data_size);
				if(ret != 0){
					fprintf(stderr, "server error, bad checksum\n");
					client->state = C3CLIENT_STATE_CONNECT;
					goto __begin;
				}
				ret = ccc_auth_check(client->indata, data_size);
				if(ret != 0){
					fprintf(stderr, "authdata error\n");
					client->state = C3CLIENT_STATE_CONNECT;
					goto __begin;
				}
				client->last_data_time = time(NULL) + client->keepalive_interval;
				printf("auth successfully\n");

				client->state = C3CLIENT_STATE_ACTIVE;
				client->instate = C3CLIENT_INSTATE_HDR;
				client->indata_len_expect = sizeof(message_hdr_t);
				client->indata_len = 0;
				client->outstate = C3CLIENT_OUTSTATE_IDLE;
				client->kastate = C3CLIENT_KASTATE_IDLE;
				client->app_state = C3CLIENT_APPSTATE_CONNECTED;	
				break;
			case C3CLIENT_STATE_ACTIVE:

				while(!client->is_stopped){

					FD_ZERO(&pollset_in);
					FD_ZERO(&pollset_out);
					flags = 0;

					//if(client->cached_rst_no < CACHED_RULE_NUM)

					if(client->indata_len_expect == 0){
						do{
							client->instate = C3CLIENT_INSTATE_HDR;
							if(client->cached_rst_no < CACHED_RULE_NUM){
								nn_assert(client->instate == C3CLIENT_INSTATE_HDR);
								client->indata_len_expect = sizeof(message_hdr_t);
								break;
							}
						}while(0);
					}

					if(client->indata_len_expect > 0){
						flags |= PIPE_IN;
					}

					curr_time = time(NULL);
					while(client->outdata_len == 0){
						//nn_assert(client->keepalive_state);
						if(client->keepalive_state_out != 0){
							data_size = sizeof(client->outdata);
							do_fill_keepalive(client->outdata, &data_size, client->keepalive_state_out_id, 0);
							client->msg_id++;
							client->outdata_len = data_size;
							client->send_data_type = C3CLIENT_OUTDATA_KA;
							break;
						}

						if(curr_time >= client->last_data_time && client->kastate == C3CLIENT_KASTATE_IDLE){
							//nn_assert(client->keepalive_state == KEEPA);
							data_size = sizeof(client->outdata);
							do_fill_keepalive(client->outdata, &data_size, client->msg_id, 1);
							client->last_data_time = curr_time + client->keepalive_interval;
							client->msg_id++;
							client->outdata_len = data_size;
							break;
						}

						if(client->cached_rule_no > 0){

							data_size = sizeof(client->outdata);
							do_fill_data(client->outdata, &data_size, client->msg_id, client->cached_rule);
							c3client_lock(client);
							memmove(client->cached_rule, client->cached_rule + 1, sizeof(grule_t) * (client->cached_rule_no - 1));
							client->cached_rule_no --;
							sem_post(&client->sem_w);
							c3client_unlock(client);
							client->msg_id++;
							client->outdata_len = data_size;
							break;
						}

						break;
					}

					if(client->outdata_len > 0){
						flags |= PIPE_OUT;
					}

					maxfd = -1;
					if(flags & PIPE_IN){
						FD_SET(client->sock, &pollset_in);
						if(client->sock > maxfd) maxfd = client->sock;
					}

					if(flags & PIPE_OUT){
						FD_SET(client->sock, &pollset_out);
						if(client->sock > maxfd) maxfd = client->sock;
					}

					FD_SET(client->fd_event.efd, &pollset_in);
					if(client->fd_event.efd > maxfd) maxfd = client->fd_event.efd;

					tv.tv_sec = client->last_data_time > curr_time ? client->last_data_time - curr_time : 1;
					tv.tv_usec = 0;
					maxfd ++;
					ret = select(maxfd, &pollset_in, &pollset_out, NULL, &tv);
					nn_assert(ret >= 0);
					if(FD_ISSET(client->sock, &pollset_in)){
						//
						nn_assert(client->indata_len_expect >= client->indata_len);
						ret = recv(client->sock, client->indata + client->indata_len, client->indata_len_expect - client->indata_len, 0);
						if(ret > 0 || (ret == 0 && client->indata_len_expect - client->indata_len == 0)){
							client->indata_len += ret;
							if(client->indata_len == client->indata_len_expect){
								ret = c3client_in(client);
								if(ret != 0){
									fprintf(stderr, "c3client_in error\n");
									client->state = C3CLIENT_STATE_CONNECT;
									goto __begin;
								}
								//client->indata_len = 0;
								//client->indata_len_expect = 0;
								//client->indata_len_expect = 0;
								//client->indata_len = 0;
							}
						}else if(ret < 0 && (errno == EAGAIN  || errno == EWOULDBLOCK)){

						}else{
							fprintf(stderr, "recv error: %s\n", strerror_r(errno, buf, sizeof(buf)));
							client->state = C3CLIENT_STATE_CONNECT;
							goto __begin;
						}
					}

					if(FD_ISSET(client->sock, &pollset_out)){
						nn_assert(client->outdata_len > 0);
						ret = send(client->sock, client->outdata, client->outdata_len, 0);
						if(ret >= 0){

							memmove(client->outdata, client->outdata + ret, client->outdata_len - ret);
							client->outdata_len -= ret;
							if(client->outdata_len == 0){
								ret = c3client_out(client);
								if(ret != 0){
									fprintf(stderr, "c3client_out error\n");
									client->state = C3CLIENT_STATE_CONNECT;
									goto __begin;
								}

							}
						}else if(ret < 0 && (errno == EAGAIN  || errno == EWOULDBLOCK)){

						}else{
							fprintf(stderr, "recv error: %s\n", strerror_r(errno, buf, sizeof(buf)));
							client->state = C3CLIENT_STATE_CONNECT;
							goto __begin;
						}
					}

					if(FD_ISSET(client->fd_event.efd, &pollset_in)){
						nn_efd_unsignal(&client->fd_event);

					}


				}
				break;
			default:
				nn_assert(0);
				break;

		};


	}

	return NULL;
}

int c3client_connect(c3client_t * client, const char * addr)
{
	char buf[1024];
	char * ptr, * saved_ptr;
	int port;
	pthread_attr_t  tattr;
	int ret;

	nn_assert(client->magic == C3CLIENT_MAGIC);
	nn_assert(client->state == C3CLIENT_STATE_IDLE);
	c3client_lock(client);
	nn_assert(client->addr_no == 0);

	if(strlen(addr) > sizeof(buf) - 1){
		return -1;
	}

	strcpy(buf, addr);

	ptr = strtok_r(buf, ":", &saved_ptr);
	while(ptr){

		memset(&client->addr[client->addr_no], 0, sizeof(struct sockaddr_in));
		client->addr[client->addr_no].sin_family = AF_INET;
		client->addr[client->addr_no].sin_addr.s_addr = inet_addr(ptr);
		if(client->addr[client->addr_no].sin_addr.s_addr == 0xffffffff){
			client->addr_no = 0;
			c3client_unlock(client);
			return -1;
		}
		ptr = strtok_r(NULL, ";", &saved_ptr);
		if(ptr == NULL){
			client->addr_no = 0;
			c3client_unlock(client);
			return -1;
		}

		port = atoi(ptr);

		if(port <= 0 || port > 65535){
			client->addr_no = 0;
			c3client_unlock(client);
			return -1;
		}

		port = ntohs(port);

		client->addr[client->addr_no].sin_port = (unsigned short)port;

		client->addr_no++;

		ptr = strtok_r(NULL, ":", &saved_ptr);
	}

	pthread_attr_init(&tattr);
	pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
	ret = pthread_create(&client->thread_id, &tattr, c3client_process, client);
	pthread_attr_destroy(&tattr);
	if(ret != 0){
		client->addr_no = 0;
		c3client_unlock(client);
		return -1;
	}
	client->state = C3CLIENT_STATE_CONNECT;
	c3client_unlock(client);
	return 0;
}





int c3client_send(c3client_t * client, grule_t *rules, size_t rule_num, int flags)
{
	size_t size;
	int ret;

	size = 0;
	nn_assert(client->magic == C3CLIENT_MAGIC);
	nn_assert(rule_num == 1);
	while(client->cached_rule_no < CACHED_RULE_NUM && size < rule_num){

		ret = do_check_rule(&rules[size]);
		if(ret != 0){
			return -1;
		}
		c3client_lock(client);
		if(client->cached_rule_no < CACHED_RULE_NUM){
			memcpy(client->cached_rule + client->cached_rule_no, rules + size, sizeof(grule_t));
			size ++;
			client->cached_rule_no++;
		}
		c3client_unlock(client);
	}
	if(size > 0){
		nn_efd_signal(&client->fd_event);
	}

	return size;
}

int c3client_recv(c3client_t * client, grule_result_t *rst, size_t rst_num, int flags)
{
	return 0;
}


const char * c3client_bad_results_str(grule_result_t *rst)
{
	return NULL;
}

const char * c3client_error_str(int err_no)
{
	return NULL;
}

int c3client_errno(c3client_t * client)
{
	return 0;
}

/*
 * release hdl
 */
int c3client_close(c3client_t * client)
{
	nn_assert(0);
	return 0;
}
