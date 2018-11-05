#ifndef __DEALPKT_H_
#define __DEALPKT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h"

#define TCP_FLOOD_DETECT_OFF 0x0
#define TCP_SYNFLOOD_DETECT_ON 0x01
#define TCP_DATAFLOOD_DETECT_ON 0x02

#define ADDRINFO_MAXLEN_FILENAME	256
#define ADDRINFO_PATHNAME	"./addrinfo/"
#define ADDRINFO_FILENAME	"pthread.log"


int ipv4_frag_init(int thread_count, unsigned int hash_size);
int ipv6_frag_init(int thread_count, unsigned hash_size);


int init_stream_manage(int threadcount);
int tcp_set_stream_num(int tcpsyn,int tcpdata,int tcpnouse);
int tcp_set_default_unorder_num(unsigned short max_unorder);
int tcp_set_creatlink_model(int model);

int tcp_set_flood_detect_model(int model);

void setneedack(struct streaminfo *pstream);
void set_tcp_takeoverflag(struct streaminfo *pstream,int flag);



int synflood_detect_init(int thread_num);


int udp_set_stream_num(int udp1,int udp2,int udp3);
void udp_set_stream_resettime(unsigned short timeout);

int tmp_ip_callback_entry(struct ip * a_packet , unsigned char routedir , int thread_id);


#ifdef __cplusplus
}
#endif
#endif
