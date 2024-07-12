#ifndef __GRULE_H
#define __GRULE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/ip.h>

typedef void * grule_hdl_t;
//typedef void * rule_item_t;




#if __BYTE_ORDER != __LITTLE_ENDIAN
#error "machine is not little-endian"
#endif


/*#define GRULE_TYPE_SIP                 1
#define GRULE_TYPE_SIP_DIP             5
#define GRULE_TYPE_SIP_SPORT           9
#define GRULE_TYPE_SIP_PROTO         257
#define GRULE_TYPE_SIP_SPORT_PROTO   273
#define GRULE_TYPE_SIP_DPORT          65
#define GRULE_TYPE_SIP_DPORT_PROTO   321   
#define GRULE_TYPE_SIP_DIP_PROTO     261
#define GRULE_TYPE_DIP                 4
#define GRULE_TYPE_DIP_DPORT          68
#define GRULE_TYPE_DIP_DPORT_PROTO   324 
#define GRULE_TYPE_DIP_PROTO         260 
#define GRULE_TYPE_DIP_SPORT_PROTO   276    
*/

typedef union{
	struct{
		uint16_t  sip_flag:1;
		uint16_t  sipmsk_flag:1;
		uint16_t  dip_flag:1;
		uint16_t  dipmsk_flag:1;
		uint16_t  sport_flag:1;
		uint16_t  spmsk_flag:1;
		uint16_t  dport_flag:1;
		uint16_t  dpmsk_flag:1;
		uint16_t  proto_flag:1;
		uint16_t  pmsk_flag:1;
		uint16_t  resv:6; // resv must be zero
	};
	uint16_t grule_type;
}grule_type_t;




typedef uint32_t ip4_addr_t;
typedef uint16_t port_t;
typedef union{
		unsigned long ip6_l[2];
		unsigned int  ip6_i[4];
		unsigned char ip6_c[16];
}ip6_addr_t;


typedef struct{
	ip4_addr_t sip;
	ip4_addr_t dip;
	port_t     sport;
	port_t     dport;
	uint8_t    proto;
}simple4_rule_t;

typedef struct{
	ip6_addr_t sip;
	ip6_addr_t dip;
	port_t     sport;
	port_t     dport;
	uint8_t    proto;
}simple6_rule_t;

typedef struct{
	ip4_addr_t sip;
	ip4_addr_t sip_mask;
	ip4_addr_t dip;
	ip4_addr_t dip_mask;
	port_t     sport;
	port_t     sport_mask;
	port_t     dport;
	port_t     dport_mask;
	uint8_t    proto;
	uint8_t    proto_mask;
}mask4_rule_t;


typedef struct{
	ip6_addr_t sip;
	ip6_addr_t sip_mask;
	ip6_addr_t dip;
	ip6_addr_t dip_mask;
	port_t     sport;
	port_t     sport_mask;
	port_t     dport;
	port_t     dport_mask;
	uint8_t    proto;
	uint8_t    proto_mask;
}mask6_rule_t;


#define GRULE_BIG_TYPE_SIMPLE4   1
#define GRULE_BIG_TYPE_SIMPLE6   2
#define GRULE_BIG_TYPE_MASK4     3
#define GRULE_BIG_TYPE_MASK6     4

#define GRULE_ACTION_ADD 1
#define GRULE_ACTION_DEL 2

typedef struct{
	uint64_t    rule_id;// rule uniq id
	uint32_t    srv_type; // rule service type
	uint32_t    rule_scope; // rule scope, such as all of carrier, China unicom
	uint16_t    big_type; // GRULE_BIG_TYPE_SIMPLE4, GRULE_BIG_TYPE_SIMPLE6, GRULE_BIG_TYPE_MASK4, 
	uint16_t    durable; // rule is durable
	uint16_t    action; // add or delete
	grule_type_t rule_type;
	union{
		simple4_rule_t  s4;
		simple6_rule_t  s6;
		mask4_rule_t    m4;
		mask6_rule_t    m6;
	};
}grule_t;



#define GRULE_SOL_PROTO 1

#define GRULE_TYPE_AUTH 1
#define GRULE_TYPE_NONBLOCK 2

#define GRULE_OK  	 0
#define GRULE_ERR   -1

#define GRULE_ERRNO_AGAIN            99
#define GRULE_ERRNO_BAD_RULE 		100
#define GRULE_ERRNO_BAD_OPT  		101
#define GRULE_ERRNO_BAD_CONNECTION 	102
#define GRULE_ERRNO_AUTH            103

#define GRULE_RESP_OK        0
#define GRULE_RESP_WHITELIST 1


typedef struct{
	//uint64_t rule_id;
	uint32_t result;
}grule_result_t;



/*
* return 0, if rule is ok. otherwise rule is bad.
*/
int grule_check_rule(const grule_t * rule);


/*#define GRULE_APP_STATUS_AUTHING          1         // authenticaing, it cannot send data;
#define GRULE_APP_STATUS_AUTH_ERROR       2
//#define GRULE_APP_STATUS_AUTH_SUCC
#define GRULE_APP_STATUS_CONNECTED        3         // connected, send all durable rules;
#define GRULE_APP_STATUS_ACTIVE           4         // active, send one rule;
#define GRULE_APP_STATUS_CLOSE            5         // close.
*/


#define GRULE_APP_STATUS_IDLE      1
#define GRULE_APP_STATUS_CONNECTED 2
#define GRULE_APP_STATUS_ACTIVE    3


//int grule_restart(grule_hdl_t hdl);


/*
get app status
	return -1 if it failed, otherwise return status
*/
int grule_app_status(grule_hdl_t hdl);

/*
	init grule handle
*/
grule_hdl_t grule_open();

/*
	get option value of rule handle, including rule handle, tcp.
	return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 
*/
int grule_opt_get(grule_hdl_t hdl, int level, int type, void * opt, size_t opt_size);


/*
*  set option of rule handle
return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 

*/
int grule_opt_set(grule_hdl_t hdl, int level, int type, const void * opt, size_t opt_size);

/*
* connect server;
return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 

*/
int grule_connect(grule_hdl_t hdl, const char * addr);

/*
* send rules, flags=0
* return > 1 if it succeded, 0: connecting state, try again, <0 rule error 

*/
int grule_send(grule_hdl_t hdl, grule_t *rules, size_t rule_num, int flags);


/*
* recieve result;flags=0
* return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 
*/
int grule_recv(grule_hdl_t hdl, grule_result_t *rst, size_t rst_num, int flags);

/*
* get error info of result;
*/
const char * grule_bad_results_str(grule_result_t *rst);

const char * grule_error_str(int err_no);

int grule_errno(grule_hdl_t hdl);

/*
* release hdl
*/
int grule_close(grule_hdl_t hdl);

void parse_rule(grule_t * rule);

char * parse_rule_str(grule_t * rule, char * buf, size_t *size);
char * parse_rule_str_full(grule_t * rule, char * buf, size_t *size);

//usage

#define RULE_SIP     0x0001
#define RULE_SIPMASK 0x0002
#define RULE_DIP     0x0004
#define RULE_DIPMASK 0x0008
#define RULE_SPORT   0x0010
#define RULE_SPMASK  0x0020
#define RULE_DPORT   0x0040
#define RULE_DPMASK  0x0080
#define RULE_PROTO   0x0100
#define RULE_PMASK   0x0200


#ifdef __cplusplus
}
#endif


#endif

