#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "grule.h"
#include "c3client.h"



/*
get app status
	return -1 if it failed, otherwise return status
*/
int grule_app_status(grule_hdl_t hdl)
{
	return c3client_app_status((c3client_t*)hdl);
}

/*
	init grule handle
*/
grule_hdl_t grule_open()
{
	return c3client_open();
}

/*
	get option value of rule handle, including rule handle, tcp.
	return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 
*/
int grule_opt_get(grule_hdl_t hdl, int level, int type, void * opt, size_t opt_size)
{
	return c3client_opt_get((c3client_t*)hdl, level, type, opt, opt_size);
}


/*
*  set option of rule handle
return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 

*/
int grule_opt_set(grule_hdl_t hdl, int level, int type, const void * opt, size_t opt_size)
{
	return c3client_opt_set((c3client_t*)hdl, level, type, opt, opt_size);
}

/*
* connect server;
return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 

*/
int grule_connect(grule_hdl_t hdl, const char * addr)
{
	return c3client_connect((c3client_t *) hdl, addr);
}

/*
* send rules, flags=0
* return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 

*/
int grule_send(grule_hdl_t hdl, grule_t *rules, size_t rule_num, int flags)
{
	return c3client_send((c3client_t *) hdl, rules, rule_num, flags);
}


/*
* recieve result;flags=0
* return 0 if it succeded, otherwise -1. grule_errno() indicates the detailed error. 
*/
int grule_recv(grule_hdl_t hdl, grule_result_t *rst, size_t rst_num, int flags)
{
	return c3client_recv((c3client_t *) hdl, rst, rst_num, flags);
}

/*
* get error info of result;
*/
const char * grule_bad_results_str(grule_result_t *rst)
{
	return c3client_bad_results_str(rst);
}

const char * grule_error_str(int err_no)
{
	return c3client_error_str( err_no);
}

int grule_errno(grule_hdl_t hdl)
{
	return c3client_errno((c3client_t *)hdl);
}

/*
* release hdl
*/
int grule_close(grule_hdl_t hdl)
{
	return c3client_close((c3client_t *)hdl);
}


/*

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
**/


int  check_rule(grule_t * rule)
{
	//if()

	return 0;
}

const char * print_bigtype(uint16_t bigtype)
{
	switch(bigtype){
		case GRULE_BIG_TYPE_SIMPLE4:
			return "simple4";
			break;
		case GRULE_BIG_TYPE_SIMPLE6:
			return "simple6";
			break;
		case GRULE_BIG_TYPE_MASK4:
			return "mask4";
			break;
		case GRULE_BIG_TYPE_MASK6:
			return "mask6";
			break;
		default:
			return "unkown bigtype";
	};
}


#define check_snprintf_return_ptr(ret, remained, pos, ptr)  do{ \
	if( (ret) >= (remained) || ret < 0) return ptr; \
		else { remained -= ret; pos += ret;} \
			}while(0)


char * print_ruletype(grule_type_t t, char * ptr, size_t size)
{
	const char * flag;
	int i;
	int pos;
	int remained;
	int ret;
	uint32_t bit;

	bit = 1;

	remained = size;
	pos  = 0;

	for(i = 0; i < 10; i++, bit = bit << 1){
		if(!(t.grule_type & bit)){
			continue;
		}

		switch(bit){
			case RULE_SIP     :
				flag = "SIP";
				break;
			case RULE_SIPMASK :
				flag = "SIPMSK";
				break;
			case RULE_DIP     :
				flag = "DIP";
				break;
			case RULE_DIPMASK :
				flag = "DIPMSK";
				break;
			case RULE_SPORT   :
				flag = "SP";
				break;
			case RULE_SPMASK  :
				flag = "SPMSK";
				break;
			case RULE_DPORT   :
				flag = "DP";
				break;
			case RULE_DPMASK  :
				flag = "DPMSK";
				break;
			case RULE_PROTO   :
				flag = "PROTO";
				break;
			case RULE_PMASK   :
				flag = "PMSK";
				break;
			default:
				flag = "UKN";
				break;
		}
		ret = snprintf(ptr + pos, remained, "%s_", flag);
		check_snprintf_return_ptr(ret, remained, pos, ptr);
	}
	if(pos >= 1 && ptr[pos - 1] == '_'){
		ptr[pos - 1] = 0;
	}
	return ptr;
}


const char * print_rule(uint16_t bigtype, grule_type_t grule_type, void * rule, char * str, size_t size, int is_full)
{
	int i;
	int flag;
	void * addr;
	const char * ptr;
	char buf[128];
	int domain;
	uint16_t port;
	int ret;

	int remained;
	int pos;

	simple4_rule_t * s4;
	simple6_rule_t * s6;
	mask4_rule_t   * m4;
	mask6_rule_t   * m6;

	if(bigtype == GRULE_BIG_TYPE_SIMPLE4 || bigtype == GRULE_BIG_TYPE_MASK4){
		domain = AF_INET;
	}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6 || bigtype == GRULE_BIG_TYPE_MASK6){
		domain = AF_INET6;
	}

	s4 = (simple4_rule_t*)rule;
	s6 = (simple6_rule_t*)rule;
	m4 = (mask4_rule_t*)rule;
	m6 = (mask6_rule_t*)rule;

	pos = 0;
	remained = size;

	flag = 1;
	
	
	for(i = 0; i < 10; i++, flag = flag << 1){

		if(!is_full && !(grule_type.grule_type & flag)){
			continue;
		}

		//ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);
		buf[0] = 0;
		ptr = NULL;
		switch(flag){
			case RULE_SIP     :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &s4->sip;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &s6->sip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->sip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->sip;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_SIPMASK :
				
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//return -1;	
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->sip_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->sip_mask;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_DIP     :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &s4->dip;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &s6->dip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->dip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->dip;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_DIPMASK :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.dip;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->dip_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->dip_mask;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_SPORT   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					port = s4->sport;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					port = s6->sport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->sport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->sport;	
				}
				snprintf(buf, sizeof(buf), "%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_SPMASK  :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.sport_mask;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//addr = &rule->s6.sport;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->sport_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->sport_mask;	
				}
				snprintf(buf,sizeof(buf), "%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_DPORT   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					port = s4->dport;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					port = s6->dport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->dport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->dport;	
				}
				snprintf(buf, sizeof(buf), "%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_DPMASK  :

				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.dport_mask;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//addr = &rule->s6.dport_mask;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->dport_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->dport_mask;	
				}
				snprintf(buf, sizeof(buf),"%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_PROTO   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					port = s4->proto;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					port = s6->proto;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->proto;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->proto;	
				}
				snprintf(buf, sizeof(buf), "%u", (port));
				ptr = buf;
				break;
			case RULE_PMASK   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//port = &rule->s4.proto;	
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//port = &rule->s6.proto;	
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->proto_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->proto_mask;	
				}
				snprintf(buf, sizeof(buf), "%u", (port));
				ptr = buf;
				break;
			default:
				break;

		}
		ret = snprintf(str + pos, remained, "%s\t", buf);
		check_snprintf_return_ptr(ret, remained, pos, ptr);
	}

	return str;
}
const char * print_rule_full(uint16_t bigtype, grule_type_t grule_type, void * rule, char * str, size_t size)
{
	int i;
	int flag;
	void * addr;
	const char * ptr;
	char buf[128];
	int domain;
	uint16_t port;
	int ret;

	int remained;
	int pos;

	simple4_rule_t * s4;
	simple6_rule_t * s6;
	mask4_rule_t   * m4;
	mask6_rule_t   * m6;

	if(bigtype == GRULE_BIG_TYPE_SIMPLE4 || bigtype == GRULE_BIG_TYPE_MASK4){
		domain = AF_INET;
	}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6 || bigtype == GRULE_BIG_TYPE_MASK6){
		domain = AF_INET6;
	}

	s4 = (simple4_rule_t*)rule;
	s6 = (simple6_rule_t*)rule;
	m4 = (mask4_rule_t*)rule;
	m6 = (mask6_rule_t*)rule;

	pos = 0;
	remained = size;

	flag = 1;
	
	
	for(i = 0; i < 10; i++, flag = flag << 1){

		/*if(!(grule_type.grule_type & flag)){
			continue;
		}*/

		//ptr = strtok_r(NULL, RULE_DELEMITER, &savedptr);
		buf[0] = 0;
		ptr = NULL;
		switch(flag){
			case RULE_SIP     :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &s4->sip;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &s6->sip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->sip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->sip;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_SIPMASK :
				
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//return -1;	
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->sip_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->sip_mask;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_DIP     :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					addr = &s4->dip;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					addr = &s6->dip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->dip;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->dip;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_DIPMASK :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.dip;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					addr = &m4->dip_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					addr = &m6->dip_mask;	
				}
				ptr = inet_ntop(domain, addr, buf, sizeof(buf));
				break;
			case RULE_SPORT   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					port = s4->sport;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					port = s6->sport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->sport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->sport;	
				}
				snprintf(buf, sizeof(buf), "%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_SPMASK  :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.sport_mask;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//addr = &rule->s6.sport;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->sport_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->sport_mask;	
				}
				snprintf(buf,sizeof(buf), "%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_DPORT   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					port = s4->dport;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					port = s6->dport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->dport;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->dport;	
				}
				snprintf(buf, sizeof(buf), "%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_DPMASK  :

				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//addr = &rule->s4.dport_mask;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//addr = &rule->s6.dport_mask;	
					//return -1;
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->dport_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->dport_mask;	
				}
				snprintf(buf, sizeof(buf),"%u", ntohs(port));
				ptr = buf;
				break;
			case RULE_PROTO   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					port = s4->proto;	
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					port = s6->proto;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->proto;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->proto;	
				}
				snprintf(buf, sizeof(buf), "%u", (port));
				ptr = buf;
				break;
			case RULE_PMASK   :
				if(bigtype == GRULE_BIG_TYPE_SIMPLE4){
					//port = &rule->s4.proto;	
					break;
				}else if(bigtype == GRULE_BIG_TYPE_SIMPLE6){
					//port = &rule->s6.proto;	
					break;
				}else if(bigtype == GRULE_BIG_TYPE_MASK4){
					port = m4->proto_mask;	
				}else if(bigtype == GRULE_BIG_TYPE_MASK6){
					port = m6->proto_mask;	
				}
				snprintf(buf, sizeof(buf), "%u", (port));
				ptr = buf;
				break;
			default:
				break;

		}
		ret = snprintf(str + pos, remained, "%s\t", buf);
		check_snprintf_return_ptr(ret, remained, pos, ptr);
	}

	return str;
}

#define check_snprintf_noreturn(ret, remained, pos)  do{ \
	if( (ret) >= (remained) || ret < 0) return ; \
		else { remained -= ret; pos += ret;} \
			}while(0)
#define check_snprintf_return(ret, remained, pos)  do{ \
	if( (ret) >= (remained) || ret < 0) return NULL; \
		else { remained -= ret; pos += ret;} \
			}while(0)

		
void parse_rule(grule_t * rule)
{
	char buf[65536];
	char str[1024];

	int remained;
	int pos;
	int ret;
	//const char * ptr;
	//socklen_t  size;


	remained = sizeof(buf);
	pos = 0;
	//ret = snprintf(buf + pos, remained, "service_type: %u ; channel_id: %u ; ", rule->srv_type, rule->rule_scope);
	//check_snprintf_return(ret, remained, pos);


	ret = snprintf(buf + pos, remained, "%16s;%s;%s; %u\t%u\t%-16s\t",  \
		 print_bigtype(rule->big_type), \
		 rule->durable == 0 ? "T" : "D", rule->action == 0 ? "DEL" :  "ADD", \
		 rule->srv_type, rule->rule_scope,
		 print_ruletype(rule->rule_type, str, sizeof(str)));
		 
	check_snprintf_noreturn(ret, remained, pos);

	ret = snprintf(buf + pos, remained, "%s", \
		print_rule(rule->big_type, rule->rule_type, &rule->s4, str, sizeof(str), 0) );

	check_snprintf_noreturn(ret, remained, pos);



	printf("%s\n", buf);
}
char * parse_rule_str(grule_t * rule, char * buf, size_t *buf_size)
{
	//char buf[65536];
	char str[1024];

	int remained;
	int pos;
	int ret;
	//const char * ptr;
	//socklen_t  size;


	//remained = sizeof(buf);
	remained = *buf_size;
	pos = 0;
	//ret = snprintf(buf + pos, remained, "service_type: %u ; channel_id: %u ; ", rule->srv_type, rule->rule_scope);
	//check_snprintf_return(ret, remained, pos);


	ret = snprintf(buf + pos, remained, "%16s;%s;%s; %u\t%u\t%-16s\t",  \
		 print_bigtype(rule->big_type), \
		 rule->durable == 0 ? "T" : "D", rule->action == 0 ? "DEL" :  "ADD", \
		 rule->srv_type, rule->rule_scope,
		 print_ruletype(rule->rule_type, str, sizeof(str)));
		 
	check_snprintf_return(ret, remained, pos);

	ret = snprintf(buf + pos, remained, "%s", \
		print_rule(rule->big_type, rule->rule_type, &rule->s4, str, sizeof(str), 0));

	check_snprintf_return(ret, remained, pos);

	*buf_size -= remained;

	return buf;

	//printf("%s\n", buf);
}
char * parse_rule_str_full(grule_t * rule, char * buf, size_t *buf_size)
{
	//char buf[65536];
	char str[1024];

	int remained;
	int pos;
	int ret;
	//const char * ptr;
	//socklen_t  size;


	//remained = sizeof(buf);
	remained = *buf_size;
	pos = 0;
	//ret = snprintf(buf + pos, remained, "service_type: %u ; channel_id: %u ; ", rule->srv_type, rule->rule_scope);
	//check_snprintf_return(ret, remained, pos);


	ret = snprintf(buf + pos, remained, "%16s;%s;%s; %u\t%u\t%-16s\t",  \
		 print_bigtype(rule->big_type), \
		 rule->durable == 0 ? "T" : "D", rule->action == 0 ? "DEL" :  "ADD", \
		 rule->srv_type, rule->rule_scope,
		 print_ruletype(rule->rule_type, str, sizeof(str)));
		 
	check_snprintf_return(ret, remained, pos);

	ret = snprintf(buf + pos, remained, "%s", \
		print_rule(rule->big_type, rule->rule_type, &rule->s4, str, sizeof(str), 1) );

	check_snprintf_return(ret, remained, pos);

	*buf_size -= remained;

	return buf;

	//printf("%s\n", buf);
}



void print_rule_conf_format()
{

	printf("%s", "#Comment by '#' or ';'");
	printf("%s", "#// dev rule_scope srv_type durable action bigtype ruletype rule...");
	printf("%s", "#Column 1: [char]    S:Server; G:Gdevice; D:DDevice");
	printf("%s", "#Column 2: [numeric] Channel_ID");
	printf("%s", "#Column 3: [numeric] Service_type");
	printf("%s", "#Column 4: [numeric] Durable, 0:temporary 1:Durable");
	printf("%s", "#Column 5: [varchar] BigType, s4:simple-ipv4-tuple5 s6:simple-ipv6-tuple5 m4:mask-ipv4-tuple10 m6:mask-ipv6-tuple10");
	printf("%s", "#Column 6: [varchar] RuleType, Delimited by '_', SIP/S:SourceIP DIP/D:DestinationIP");
	printf("%s", "#                    SPORT/SP:SourcePort DPORT/DP:DestinationPort MSIP/MS:Mask-SourceIP");
	printf("%s", "#                    MDIP/MD:Mask-DestinationIP MSPORT/MSP:Mask-SourcePort MDPORT/MD:Mask-DestinationIP");
	printf("%s", "#                    PROTO/P:Protocol MPROTO/MP:Mask-Protocol");
	printf("%s", "#Column 7+:     rule: sequence must be keep, (1)SIP;(2)MSIP;(3)DIP;(4)MDIP;(5)SPORT;(6)MSPORT;(7)DPORT;(8)MDPORT;(9)PROTO;(10)MPROTO");
}
