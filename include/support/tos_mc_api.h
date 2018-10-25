#ifndef _MC_API_H
#define _MC_API_H
#include <sys/types.h>
#include <unistd.h>
/* 
	update log:
	2015-06-30, lijia(lijia@nismail.iie.ac.cn), 接口初始化接口、增加pid参数; 
 */

typedef unsigned long long __u64;
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned char __u8;

// 描述包的结构体
struct mc_desc {        
	int type; 
	int family;
	int tot_len; 	// 第三层长度，包含了第三层、第四层及更高层的总长度
	void *l2_header; 
	int l2_len;
	void *ip_hdr;	
	void *ip_lable;
	int ip_label_len;
	void *pkt_label;
	int pkt_label_len;
	/*topsec session*/
	int dir;
	int ifindex;
	char  ifname[32];
	void *ts;
	char buffer[0]; // 指向第三层包头数据，由此获取数据包
}; 

/* 2015-06-30 add, 初始化时先要获取句柄 */
void *tos_get_handle(pid_t pid);

void tos_format_log_pro1(char *buf);
int tos_tr_packet_recv(struct mc_desc **tr_packet, void *handle);
int tos_tr_packet_send(struct mc_desc *tr_packet, void *handle);



#endif
