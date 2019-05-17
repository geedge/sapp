#ifndef _APP_STREAM_CUSTOM_H_
#define _APP_STREAM_CUSTOM_H_ 

#ifdef __cplusplus
extern "C" {
#endif


#define TCP_FLOOD_DETECT_OFF 0x0
#define TCP_SYNFLOOD_DETECT_ON 0x01
#define TCP_DATAFLOOD_DETECT_ON 0x02

#define TCP_SUPPORT_ENTRYALL_OFF 0x0
#define TCP_SUPPORT_ENTRYALL_ON 0x1


//ip碎片管理管理相关函数

int ipv4_frag_init(int thread_count, unsigned int hash_size);
int ipv6_frag_init(int thread_count, unsigned hash_size);

//链接管理函数
//初始化链接线程数目
int init_stream_manage(int threadcount);

// 链接 (tcp,udp通用)的最大无包保持时间为设定的timeout(单位:秒)
//默认值为0,此时只进行lru淘汰，不进行按时间淘汰
void stream_set_default_nopkt_time(unsigned short timeout);


//设置不同状态链接的保持并发链接数目
int udp_set_stream_num(int udp1,int udp2,int udp3);
int tcp_set_stream_num(int tcpsyn,int tcpdata,int tcpnouse);

//设置默认的乱序存储包数目
int tcp_set_default_unorder_num(unsigned short max_unorder);

//设置链接建立模式
int tcp_set_creatlink_model(int model);

//设置是否开启tcpall模式,默认off
int tcp_set_support_tcpall_model(int model);
//设置攻击检测模式，默认未开启
int tcp_set_flood_detect_model(int model);

//设置链接的重置时间
void udp_set_stream_resettime(unsigned short timeout);

//设置默认的乱序存储包数目
int tcp_set_default_unorder_num(unsigned short max_unorder);

/* 2014-10-11 lijia add, for rst pkt finger */
int set_rst_rand_key(int rnd_key);
int set_rst_max_rnd_val(int max_rnd_val);



#ifdef __cplusplus
}
#endif

#endif

