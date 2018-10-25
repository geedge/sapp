#ifdef __cplusplus
extern "C" {
#endif

/*
	通用保活接口, 适用于一主多从模式, 以id为主键, UDP-socket为底层通信接口.

	主应用:
		主必须明确工作模式, 启动后等待从注册, 然后进入request-reply循环保活状态;
		从应用重启后可能会再次注册, 且绑定端口可能有变化(被其他进程占用), 此时需要更新已有配置.
		一段时间从应用不回复, 从node列表中删除, 等待下次从再注册.
		
	从应用:
		为了方便, 从应用可以不设置任何参数 (前提是起始端口默认值和主应用一样).
		如果不设置模式, 则自动默认为是从应用, 启动后自动发现主, 待主回复确认后, 等待主的request包, 回应reply包.
		如果一段时间连续无保活包到达, 则认为是主不在了(如死机、网络中断), 需要重新进入初始化阶段, 即寻找主应用模式.
*/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <link.h>
#include <dlfcn.h>
#include <sys/time.h>
#include "libping.h"
#include "MESA_socket_wrap.h"

int libping_version_VERSION_20180427;

#ifndef MIN
#define MIN(a, b)  	(((a) < (b)) ? (a) : (b))
#endif

#define LIBPING_DEBUG    				(1)
#if LIBPING_DEBUG
#define PING_PRT(fmt, args...) printf(fmt, ##args)
#else
#define PING_PRT(fmt, args...) 
#endif

#define BYTE_ALIGNED(n)    __attribute__((packed, aligned(n)))

#define LIBPING_KEEPALIVE_ACCURACY		(50) /* 保活精度, 单位:毫秒 */
#define LIBPING_SILENT_TIME				(200)   /* 静默时间, 经过多少个LIBPING_KEEPALIVE_ACCURACY周期, 双方都无正常保活, 则认为对方已不在, 删除相关id, ip, port信息 */
#define LIBPING_BEGIN_BIND_PORT 		(65000)

typedef struct{
	unsigned int slave_id;
	unsigned int ip_net_order;
	unsigned short port_net_order;
	unsigned short state;
	unsigned int last_send_request_time_mark; /* 上一次发送请求的时间戳 */
	unsigned int last_rcv_reply_time_mark; /* 最后一次收到回复的时间戳 */
	unsigned int send_req_pkt;
	unsigned int recv_rep_pkt;
	unsigned short last_send_seq_num;
}libping_node_t;


typedef struct{
	unsigned int pair_tag;
	int sock_fd;
	/************** 8 bytes separator ************/
	unsigned long long identification; /* 唯一标识, 初始化时随机生成 */
	/************** 8 bytes separator ************/
	unsigned short work_mode;
	unsigned short bind_begin_port_net;
	unsigned short actual_bind_port_net;
	unsigned short master_port_net;    /* 主应用的端口, 如果没有明确配置, 靠自动轮询查找发现  */
	/************** 8 bytes separator ************/
	unsigned int master_ip_net;		/* 主应用的IP, 如果没有明确配置, 靠自动轮询查找发现 */
	unsigned int slave_id;
	/************** 8 bytes separator ************/
	libping_node_t *slave_node_array; /* 从应用默认为1个元素, slave复用slave_node_array变量, 用于存储相关变量和状态 */
	int slave_node_num; /* 当前slave_node_array内的元素数, 包括状态不保活, 未注册的slave */
	unsigned int last_rcv_request_time_mark; /* 从最后一次收到主request的时间戳 */
	/************** 8 bytes separator ************/
	pthread_mutex_t mutex;
	libping_slave_pre_replay_cb_t *slave_pre_reply_cb; /* 收到主的保活请求, 是否要回复保活应答, 根据回调函数返回值决定, 1:回复; 2:丢弃静默 */
	/************** 8 bytes separator ************/
	int keepalive_interval;
	unsigned int g_current_time_mark; /* 每隔一个保活周期, 即keepalive_interval, 此值加1, 注意不是1毫秒! */
	/************** 8 bytes separator ************/
	unsigned char master_ip_port_by_manual; 
}libping_inner_t;


enum libping_msg_type{
	LIBPING_MSG_TYPE_DETECT,    /* 从探测主是否存在 */
	LIBPING_MSG_TYPE_DETECT_BINGO, /* 主回应从, 表示我是master */
	LIBPING_MSG_TYPE_REGISTER, /* 从向主注册 */
	LIBPING_MSG_TYPE_REGISTER_RESPONSE, /* 主回复从, 注册成功or失败 */
	LIBPING_MSG_TYPE_REQUEST,
	LIBPING_MSG_TYPE_REPLY,
};


#define LIBPING_MSG_MAGIC		(0x676e6970) /* "ping"字符的二进制, 网络序 */

struct _libping_msg{
	unsigned int magic; /* 魔数 */
	unsigned int pair_tag; /* 保活双方的标识符, 用于多个不同业务 */
	unsigned char version; /* 目前为1 */
	unsigned char msg_type; /* enum ping_msg_type */
	unsigned char reserved[6]; /* 预留位 */
}BYTE_ALIGNED(1);  /* 保活通信包格式 */
typedef struct _libping_msg libping_msg_t;

static const unsigned long long LIBPING_DETECT_XOR_MAGIC = 0x0000A1B2C3D4E5F6L;
struct _libping_msg_detect{
	long long detect_seed; /* 探测包的负载, slave生成一个随机数, master回复detect_seed ^ LIBPING_DETECT_OR_MAGIC */
}BYTE_ALIGNED(1);
typedef struct _libping_msg_detect libping_msg_detect_t;


struct _libping_msg_register{
	unsigned int slave_id;
}BYTE_ALIGNED(1);
typedef struct _libping_msg_register libping_msg_register_t;


struct _libping_msg_keepalive{
	unsigned int seq;
	unsigned int slave_id;
}BYTE_ALIGNED(1);
typedef struct _libping_msg_keepalive libping_msg_keepalive_t;


/*
	格式:
		SEQ:xxxxx\0; 
		ID:xxxxxx\0;
*/
struct _libping_msg_keepalive_str{ 
	unsigned char __pad[4]; /* 仅为了tcpdump -X时看着更舒服点 */
	unsigned char seq_in_string[16];       /* 因libping不是强制绑定某个端口和slave_id有关联, 为了调试方便, 此处使用字符串形式, tcpdump -X可以看到右侧ascii字符 */
	unsigned char slave_id_in_string[16]; /* 因libping不是强制绑定某个端口和slave_id有关联, 为了调试方便, 此处使用字符串形式, tcpdump -X可以看到右侧ascii字符 */	
}BYTE_ALIGNED(1);
typedef struct _libping_msg_keepalive_str libping_msg_keepalive_str_t;


/* 
	检验是否是libping发出的包, 防止其他数据包误识别.
*/
static inline int libping_pkt_verify(const libping_inner_t *pih, const libping_msg_t *pmsg, int rcv_len)
{
	if(rcv_len < sizeof(libping_msg_t)){
		return 0;
	}
	
	if(LIBPING_MSG_MAGIC != pmsg->magic){
		return 0;
	}

	if(pmsg->pair_tag != pih->pair_tag){ /* 虽然是libping的包, 但不是本业务的包 */
		return 0;
	}

	return 1;
}

static int libping_master_recv_detect_proc(libping_inner_t *pih, const libping_msg_t *raw_msg, struct sockaddr *peer_addr)
{
	char send_buf[128];

	libping_msg_t *send_msg = (libping_msg_t *)send_buf;
	libping_msg_detect_t *send_msg_det = (libping_msg_detect_t *)(send_buf + sizeof(libping_msg_t));
	const libping_msg_detect_t *raw_msg_det = (libping_msg_detect_t *)((char *)raw_msg + sizeof(libping_msg_t));

	send_msg->magic = LIBPING_MSG_MAGIC;
	send_msg->pair_tag = pih->pair_tag;
	send_msg->version = 1;
	send_msg->msg_type = LIBPING_MSG_TYPE_DETECT_BINGO;

	send_msg_det->detect_seed = raw_msg_det->detect_seed ^ LIBPING_DETECT_XOR_MAGIC;
	PING_PRT("[master] rcv slave detect pkt, raw seed:%llx, reply seed:%llx\n", raw_msg_det->detect_seed, send_msg_det->detect_seed);
	sendto(pih->sock_fd, send_buf, sizeof(libping_msg_t)+sizeof(libping_msg_detect_t), 0, 
	          peer_addr, sizeof(struct sockaddr));

	return 0;
}

/*
	 0: SUCC;
	-1: ERROR;
*/
static int libping_master_resigter_new_slave(libping_inner_t *pih, unsigned int ip_net, unsigned short port_net, unsigned int slave_id)
{
	int i;
	int ret = 0;
	libping_node_t *new_slave_place = NULL;

	/* 此过程中, 主应用另一个线程可能正在发送request包, 即正在轮询slave_node_array数组, 需要加锁保护 */
	pthread_mutex_lock(&pih->mutex);

	for(i = 0; i < pih->slave_node_num; i++){
		/* 
		   如果新注册slave的slave_id已存在, 目前采取的策略是: 
		   如果存在的slave_id还是正常状态, 则可能是误操作, 启动了两个相同的slave, 新注册失败;
		   
		   如果存在的slave_id是INIT或ERR状态, 则更新之前的IP和端口, 因为从应用可能崩溃重启了, 并绑定了新的端口;
		   如果两个slave错误的设置了相同的id, 则后续的会覆盖之前slave已存储的ip和port.
		 */
		if(slave_id == pih->slave_node_array[i].slave_id){
			if(LIBPING_STATE_KEEPALIVE_SUCC == pih->slave_node_array[i].state){
				ret = -1;
				PING_PRT("[master]recv slave register pkt, but slave ip:%x, port:%u, id:%d is already exist and state is SUCC!\n", ntohl(ip_net), ntohs(port_net), slave_id);
				goto done;
			}else{
				new_slave_place = &pih->slave_node_array[i];
				goto save_new_slave;
			}
		}
	}

	if(NULL == new_slave_place){
		/* 目前slave_node_array里没有相同的slave_id, 尝试找个空位, 暂不扩展内存 */
		for(i = 0; i < pih->slave_node_num; i++){
			if((0 ==pih->slave_node_array[i].slave_id)
			|| (LIBPING_STATE_INIT == pih->slave_node_array[i].state)){
					new_slave_place = &pih->slave_node_array[i];
					goto save_new_slave;
			}
		}
	}

	if(NULL == new_slave_place){ /* 没有空位, 扩展内存 */
		pih->slave_node_array = realloc(pih->slave_node_array, sizeof(libping_node_t) * (pih->slave_node_num + 1));
		memset(&pih->slave_node_array[pih->slave_node_num], 0, sizeof(libping_node_t));
		new_slave_place = &pih->slave_node_array[pih->slave_node_num];
		pih->slave_node_num++;
	}

save_new_slave:

	new_slave_place->slave_id = slave_id;
	new_slave_place->ip_net_order = ip_net;
	new_slave_place->port_net_order = port_net;
	new_slave_place->state = LIBPING_STATE_REGISTERED;
	new_slave_place->last_rcv_reply_time_mark = pih->g_current_time_mark;
	ret = 0;

done:
	pthread_mutex_unlock(&pih->mutex);

	return ret;
}

static int libping_master_recv_register_proc(libping_inner_t *pih, const libping_msg_t *raw_msg, struct sockaddr *peer_addr)
{
	char send_buf[128];
	int ret;

	libping_msg_t *send_msg = (libping_msg_t *)&send_buf[0];
	libping_msg_register_t *send_msg_det = (libping_msg_register_t *)(send_buf + sizeof(libping_msg_t));
	const libping_msg_register_t *raw_msg_reg = (libping_msg_register_t *)((char *)raw_msg + sizeof(libping_msg_t));

	struct sockaddr_in *slave_addr = (struct sockaddr_in *)peer_addr;
	ret = libping_master_resigter_new_slave(pih, slave_addr->sin_addr.s_addr, slave_addr->sin_port,  raw_msg_reg->slave_id);
	if(0 == ret){
		send_msg->magic = LIBPING_MSG_MAGIC;
		send_msg->pair_tag = pih->pair_tag;
		send_msg->version = 1;
		send_msg->msg_type = LIBPING_MSG_TYPE_REGISTER_RESPONSE;

		send_msg_det->slave_id = raw_msg_reg->slave_id;

		sendto(pih->sock_fd, send_buf, sizeof(libping_msg_t)+sizeof(libping_msg_register_t), 0, 
		          peer_addr, sizeof(struct sockaddr));

		PING_PRT("[master]slave register SUCC!ip:%x, port:%u, id:%d\n", ntohl(slave_addr->sin_addr.s_addr), ntohs(slave_addr->sin_port), raw_msg_reg->slave_id);
	}
	
	return 0;
}


static int libping_keepalive_msg_pton(const libping_msg_keepalive_str_t *msg_kep_str , libping_msg_keepalive_t *msg_kep_bin)
{
	const char *ptr = (char *)msg_kep_str->seq_in_string;

	if(strncasecmp("SEQ:", ptr, 4) != 0){
		return -1;
	}
	ptr += 4; /* skip prefix */
	msg_kep_bin->seq = strtoul((const char *)ptr,NULL, 10);

	ptr = (char *)msg_kep_str->slave_id_in_string;
	if(strncasecmp("ID:", ptr, 3) != 0){
		return -1;
	}	
	ptr += 3; /* skip prefix */
	msg_kep_bin->slave_id = strtoul((const char *)ptr,NULL, 10);

	return 0;
}

static int libping_keepalive_msg_ntop(const libping_msg_keepalive_t *msg_kep_bin, libping_msg_keepalive_str_t *msg_kep_str)
{
	memset(msg_kep_str, 0, sizeof(libping_msg_keepalive_str_t));
	snprintf((char *)msg_kep_str->seq_in_string, 16, "SEQ:%u", msg_kep_bin->seq);
	snprintf((char *)msg_kep_str->slave_id_in_string, 16, "ID:%u", msg_kep_bin->slave_id);

	return 0;
}

static int libping_master_recv_keepalive_proc(libping_inner_t *pih, const libping_msg_t *raw_msg, struct sockaddr *peer_addr)
{
	int i, ret = 0;
	struct sockaddr_in *slave_addr = (struct sockaddr_in *)peer_addr;
	const libping_msg_keepalive_str_t *raw_msg_kep_str = (libping_msg_keepalive_str_t *)((char *)raw_msg + sizeof(libping_msg_t));
	libping_msg_keepalive_t raw_msg_kep_bin;
	libping_node_t *cur_slave_node = NULL;

	if(libping_keepalive_msg_pton(raw_msg_kep_str, &raw_msg_kep_bin) < 0){
		return -1;
	}

	pthread_mutex_lock(&pih->mutex);

	for(i = 0; i < pih->slave_node_num; i++){
		if((raw_msg_kep_bin.slave_id == pih->slave_node_array[i].slave_id)
		 &&(slave_addr->sin_addr.s_addr == pih->slave_node_array[i].ip_net_order)
		 &&(slave_addr->sin_port == pih->slave_node_array[i].port_net_order)){
		 	cur_slave_node = &pih->slave_node_array[i];
		 	break;
		}
	}

	if(NULL == cur_slave_node){
		ret = -1;
	}else{
		cur_slave_node->state = LIBPING_STATE_KEEPALIVE_SUCC;
		cur_slave_node->recv_rep_pkt++;
		cur_slave_node->last_rcv_reply_time_mark = pih->g_current_time_mark;
	}

	pthread_mutex_unlock(&pih->mutex);
	
	return ret;
}

/*
	主模式接收线程, 阻塞接收从的探测包, reply包.
*/
static void *libping_master_recv_thread(void *arg)
{
	libping_inner_t *pih = (libping_inner_t *)arg;
	struct sockaddr_in sockadd;
	char rcv_buf[1500];
	socklen_t saddr_len;
	libping_msg_t *pmsg = (libping_msg_t *)&rcv_buf[0];
	int msg_len;
	
	while(1){
		saddr_len = sizeof(struct sockaddr);
		msg_len = recvfrom(pih->sock_fd, rcv_buf, 1500, 0, (struct sockaddr *)&sockadd, &saddr_len);
		if(msg_len < 0){
			continue;
		}
		
		if(libping_pkt_verify(pih, pmsg, msg_len) == 0){
			continue;
		}

		switch(pmsg->msg_type){
			case LIBPING_MSG_TYPE_DETECT:
				if(msg_len != sizeof(libping_msg_t) + sizeof(libping_msg_detect_t)){
					continue;
				}
				libping_master_recv_detect_proc(pih, pmsg, (struct sockaddr *)&sockadd);
			break;

			case LIBPING_MSG_TYPE_REGISTER:
				if(msg_len != sizeof(libping_msg_t) + sizeof(libping_msg_register_t)){
					continue;
				}
				libping_master_recv_register_proc(pih, pmsg, (struct sockaddr *)&sockadd);			
			break;

			case LIBPING_MSG_TYPE_REPLY:
				if(msg_len != sizeof(libping_msg_t) + sizeof(libping_msg_keepalive_str_t)){
					continue;
				}	
				libping_master_recv_keepalive_proc(pih, pmsg, (struct sockaddr *)&sockadd);
			break;
			
			default:
			break;
		}
	}

	return NULL;
}

static int libping_master_run_state_proc(libping_inner_t *pih)
{
	int i;
	struct sockaddr_in sockadd;
	char send_buf[128];
	libping_msg_t *kp_msg = (libping_msg_t *)send_buf;
	libping_msg_keepalive_t kp_msg_bin;
	libping_msg_keepalive_str_t *kp_msg_str = (libping_msg_keepalive_str_t *)(send_buf + sizeof(libping_msg_t));
	
	if(0 == pih->slave_node_num){
		usleep(10);
		return -1;
	}

	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family = AF_INET;

	/* 固定不变的值预先设置 */
	kp_msg->magic = LIBPING_MSG_MAGIC;
	kp_msg->pair_tag = pih->pair_tag;
	kp_msg->version = 1;
	kp_msg->msg_type = LIBPING_MSG_TYPE_REQUEST;

	/* 此过程中, 随时可能有新的slave注册进来, 需要加锁保护 */
	pthread_mutex_lock(&pih->mutex);
	for(i = 0; i < pih->slave_node_num; i++){
		if((LIBPING_STATE_REGISTERED == pih->slave_node_array[i].state) 
		 || (LIBPING_STATE_KEEPALIVE_SUCC == pih->slave_node_array[i].state)){ 	
			if(pih->slave_node_array[i].last_send_request_time_mark < pih->g_current_time_mark){ /* 每隔一定时间发送一次 */
				pih->slave_node_array[i].last_send_request_time_mark = pih->g_current_time_mark;
				sockadd.sin_addr.s_addr = pih->slave_node_array[i].ip_net_order;
				sockadd.sin_port = pih->slave_node_array[i].port_net_order;
				
				kp_msg_bin.seq = pih->slave_node_array[i].last_send_seq_num++;
				kp_msg_bin.slave_id = pih->slave_node_array[i].slave_id;
				libping_keepalive_msg_ntop(&kp_msg_bin, kp_msg_str);
				sendto(pih->sock_fd, send_buf, sizeof(libping_msg_t)+sizeof(libping_msg_keepalive_str_t), 0, 
				          (struct sockaddr *)&sockadd, sizeof(sockadd));
				pih->slave_node_array[i].send_req_pkt++;
			}
		}
	}
	pthread_mutex_unlock(&pih->mutex);
	
	return 0;
}


static void libping_master_check_node_status(libping_inner_t *pih)
{
	int i;
	
	pthread_mutex_lock(&pih->mutex);
	for(i = 0; i < pih->slave_node_num; i++){
		if((LIBPING_STATE_INIT == pih->slave_node_array[i].state)
                  ||(0 == pih->slave_node_array[i].slave_id)){ 	
			continue;
		}
		
		/* 超过3个保活周期, 仍未收到回复 */
		if(pih->slave_node_array[i].last_rcv_reply_time_mark  + pih->keepalive_interval * 3 < pih->g_current_time_mark){
			if(pih->slave_node_array[i].state != LIBPING_STATE_KEEPALIVE_ERR){
				PING_PRT("[master]slave_id:%d, ip:%x, port:%u, timeout, state to err!\n", 
						   pih->slave_node_array[i].slave_id,
						   ntohl(pih->slave_node_array[i].ip_net_order),
						   ntohs(pih->slave_node_array[i].port_net_order));
			}
			pih->slave_node_array[i].state = LIBPING_STATE_KEEPALIVE_ERR;
		}

		/* 超过静默周期, 可能从已经崩溃重启, 需要重置, 等待从应用再重新注册 */
		if(pih->slave_node_array[i].last_rcv_reply_time_mark  + LIBPING_SILENT_TIME < pih->g_current_time_mark){
			PING_PRT("[master]slave_id:%d, ip:%x, port:%u, silent timeout, state to init!\n", 
					   pih->slave_node_array[i].slave_id,
					   ntohl(pih->slave_node_array[i].ip_net_order),
					   ntohs(pih->slave_node_array[i].port_net_order));
			pih->slave_node_array[i].state = LIBPING_STATE_INIT;
			pih->slave_node_array[i].slave_id = 0;
			pih->slave_node_array[i].last_rcv_reply_time_mark = pih->g_current_time_mark;
		}
	}
	pthread_mutex_unlock(&pih->mutex);

	return;
}

static void *libping_master_main_thread(void *arg)
{
	libping_inner_t *pih = (libping_inner_t *)arg;

	while(1){
		/* 向slave发送request请求包 */
		libping_master_run_state_proc(pih);

		/* 检测超时 */
		libping_master_check_node_status(pih);

		usleep(1000 * pih->keepalive_interval);
	}

	return NULL;
}

#if 0
static int  libping_slave_search_master(libping_inner_t *pih, unsigned int ip_net, unsigned short port_net)
{
	struct sockaddr_in sockadd;	
	char send_buf[128];
	char rcv_buf[1500];
	socklen_t saddr_len;
	int ret;

	libping_msg_t *snd_msg = (libping_msg_t *)send_buf;
	libping_msg_detect_t *snd_msg_det = (libping_msg_detect_t *)(send_buf + sizeof(libping_msg_t));

	snd_msg->magic = LIBPING_MSG_MAGIC;
	snd_msg->pair_tag = pih->pair_tag;
	snd_msg->version = 1;
	snd_msg->msg_type = LIBPING_MSG_TYPE_DETECT;

	snd_msg_det->detect_seed = random() | (random() << 32);
	
	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family = AF_INET;
	
	sockadd.sin_addr.s_addr = ip_net;
	sockadd.sin_port = port_net;

	/* note:
		slave因故障立即重启后, 可能master还未探测到超时情况, 还会继续发送正常的keeplive_request, 
		默认每50ms一个, 还是很频繁的.
		此时的detect_bingo包可能会穿插在keeplive_request包之间,

		再加上使用UDP协议, 可能发出去的丢失, 可能回复包丢失, 造成校验不过,
		所以此处要多收几次, 暂定20次.
	*/
	int retry_times = 20;
	while(--retry_times){
		ret = sendto(pih->sock_fd, send_buf, sizeof(libping_msg_t)+sizeof(libping_msg_detect_t), 0,
		       	   (struct sockaddr *)&sockadd, sizeof(sockadd));
		if(ret < 0){
			PING_PRT("slave search master, send detect request error, %s!\n", strerror(errno));
			usleep(1000);
			return -1;
		}

		/* 尝试一直收包, 直到超时, 或收到正确的detect_bingo应答包为止 */
		while(1){
			saddr_len = sizeof(struct sockaddr);
			int msg_len = MESA_sock_recvfrom(pih->sock_fd, rcv_buf, 1500, 0, (struct sockaddr *)&sockadd, &saddr_len, 500);
			if(msg_len < 0){
				PING_PRT("slave search master, but recv error, ret=%d!\n", msg_len);
				if(MESA_SOCK_TIMEOUT == msg_len){ /* 接收超时, 说明网络中没有新包到达, 再次重新发送 */
					break;
				}else{
					continue;
				}
			}
			if(libping_pkt_verify(pih, (libping_msg_t *)rcv_buf, msg_len) < 0){
				usleep(1000);
				continue;
			}
			const libping_msg_t *rcv_msg = (libping_msg_t *)rcv_buf;
			if(rcv_msg->msg_type != LIBPING_MSG_TYPE_DETECT_BINGO){
				/* 可能master还在发送keeplive_request */
				usleep(1000);
				continue;
			}
			const libping_msg_detect_t *rcv_msg_det = (libping_msg_detect_t *)(rcv_buf + sizeof(libping_msg_t));	
			if(rcv_msg_det->detect_seed != (snd_msg_det->detect_seed ^ LIBPING_DETECT_XOR_MAGIC)){
				PING_PRT("[slave] rcv master detect reply pkt, but seed invalid:  raw seed:%llx, master reply seed:%llx\n", snd_msg_det->detect_seed, rcv_msg_det->detect_seed);
				usleep(1000 * 1000);
				continue;
			}

			PING_PRT("[slave] rcv master detect reply pkt, state turn to 'LIBPING_STATE_DETECTING'.\n");
			goto done;
		}
	}
	
	if(retry_times <= 0){ /* 超过重试最大次数, 异常退出 */
		PING_PRT("[slave] try rcv master detect reply pkt, but failed after more than %d times\n", 100);
		return -1;
	}

done:
	pih->slave_node_array[0].state = LIBPING_STATE_DETECTING;
	PING_PRT("slave search master bingo, master ip:%x, port:%u!\n", 
			   ntohl(sockadd.sin_addr.s_addr),
			   ntohs(sockadd.sin_port));
	
	return 0;
}

static int  libping_slave_register_master(libping_inner_t *pih, unsigned int ip_net, unsigned short port_net)
{
	struct sockaddr_in sockadd;	
	char send_buf[128];
	char rcv_buf[1500];
	socklen_t saddr_len;
	int ret;

	libping_msg_t *snd_msg = (libping_msg_t *)send_buf;
	libping_msg_register_t *snd_msg_reg = (libping_msg_register_t *)(send_buf + sizeof(libping_msg_t));

	snd_msg->magic = LIBPING_MSG_MAGIC;
	snd_msg->pair_tag = pih->pair_tag;
	snd_msg->version = 1;
	snd_msg->msg_type = LIBPING_MSG_TYPE_REGISTER;

	snd_msg_reg->slave_id = pih->slave_id;
	
	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family = AF_INET;
	
	sockadd.sin_addr.s_addr = ip_net;
	sockadd.sin_port = port_net;

	/* note:
		slave因故障重启后, 可能master还未探测到超时情况, 还会继续发送keeplive_request, 
		默认每50ms一个, 还是很频繁的.
		此时的register_response包可能会穿插在keeplive_request包之间,

		再加上使用UDP协议, 可能发出去的丢失, 可能回复包丢失, 造成校验不过,
		所以此处要用while(1)多收几次.
	*/

	int retry_times = 20;
	while(--retry_times){	
		ret = sendto(pih->sock_fd, send_buf, sizeof(libping_msg_t)+sizeof(libping_msg_register_t), 0,
		        	  (struct sockaddr *)&sockadd, sizeof(sockadd));
		if(ret < 0){
			PING_PRT("slave register master, send register request error, %s!\n", strerror(errno));
			usleep(1000);
			return -1;
		}

		while(1){
			saddr_len = sizeof(struct sockaddr);
			int msg_len = MESA_sock_recvfrom(pih->sock_fd, rcv_buf, 1500, 0, (struct sockaddr *)&sockadd, &saddr_len, 500);
			if(msg_len < 0){
				PING_PRT("slave register master, but recv error, ret=%d!\n", msg_len);
				if(MESA_SOCK_TIMEOUT == msg_len){ /* 接收超时, 说明网络中没有新包到达, 再次重新发送 */
					break;
				}else{
					continue;
				}
			}
			if(libping_pkt_verify(pih, (libping_msg_t *)rcv_buf, msg_len) < 0){
				usleep(1000);
				continue;
			}
			const libping_msg_t *rcv_msg = (libping_msg_t *)rcv_buf;
			if(rcv_msg->msg_type != LIBPING_MSG_TYPE_REGISTER_RESPONSE){
				usleep(1000);
				continue;
			}
			const libping_msg_register_t *rcv_msg_reg= (libping_msg_register_t *)(rcv_buf + sizeof(libping_msg_t));	
			if(rcv_msg_reg->slave_id != snd_msg_reg->slave_id){
				usleep(1000 * 1000);
				continue;
			}

			PING_PRT("[slave] rcv master register response pkt, state turn to 'LIBPING_STATE_REGISTERED'.\n");
			goto done;
		}
	}
	
	if(retry_times <= 0){ /* 超过重试最大次数, 异常退出 */
		PING_PRT("[slave] try rcv master register response pkt, but failed after more than %d times\n", 20);
		return -1;
	}

done:	
	pih->slave_node_array[0].state = LIBPING_STATE_REGISTERED;

	PING_PRT("slave register master bingo, master ip:%x, port:%u!\n", 
			   ntohl(sockadd.sin_addr.s_addr),
			   ntohs(sockadd.sin_port));

	return 0;
}

static int libping_slave_contact_master(libping_inner_t *pih)
{
	unsigned short port;
	int ret = -1;

	/* 主动设置了mater的ip和port */
	if((pih->master_ip_net != 0) && (pih->master_port_net != 0)){
		ret = libping_slave_search_master(pih, pih->master_ip_net, pih->master_port_net);
		if(ret < 0){
			return -1;
		}
		ret = libping_slave_register_master(pih, pih->master_ip_net, pih->master_port_net);
		if(ret < 0){
			return -1;
		}		
	}else{
		/* 没有设置mater的ip和port, 靠自动轮询发现, 只限定于本机范围内,
            从LIBPING_BEGIN_BIND_PORT开始尝试, 一般主从两端都不设置的话, 很快就能探测到.
		   */
		for(port = LIBPING_BEGIN_BIND_PORT; port <= 65535; port++){ 
			ret = libping_slave_search_master(pih, ntohl(0x7f000001), ntohs(port));
			if(ret < 0){
				continue;
			}
			ret = libping_slave_register_master(pih, ntohl(0x7f000001), ntohs(port));
			if(ret >= 0){
				pih->master_ip_net = ntohl(0x7f000001);
				pih->master_port_net = ntohs(port);
				break;
			}
		}
	}

	return ret;
}
#endif

static int libping_slave_reply_pkt(libping_inner_t *pih, const libping_msg_keepalive_str_t *pmsg_kp_req, struct sockaddr_in *sockadd)
{
	char snd_buf[128];
	int can_be_reply = 1; /* 默认为1, 如果设置了slave_pre_reply_cb, 取决于回调函数返回值 */
	
	if(pih->slave_pre_reply_cb != NULL){
		can_be_reply = pih->slave_pre_reply_cb(pih, pih->pair_tag, pih->slave_id);
	}

	if(can_be_reply != 0){
		libping_msg_t *snd_msg = (libping_msg_t *)snd_buf;
		libping_msg_keepalive_str_t *snd_msg_kp = (libping_msg_keepalive_str_t *)(snd_buf + sizeof(libping_msg_t));

		snd_msg->magic = LIBPING_MSG_MAGIC;
		snd_msg->pair_tag = pih->pair_tag;
		snd_msg->version = 1;
		snd_msg->msg_type = LIBPING_MSG_TYPE_REPLY;

		memcpy(snd_msg_kp, pmsg_kp_req, sizeof(libping_msg_keepalive_str_t));

		sendto(pih->sock_fd, snd_buf, sizeof(libping_msg_t)+sizeof(libping_msg_keepalive_str_t), 0, 
		          (struct sockaddr *)sockadd, sizeof(struct sockaddr));
		PING_PRT("slave recv master keepalive request, master ip:%x, port:%u!\n", 
				   ntohl(sockadd->sin_addr.s_addr),
				   ntohs(sockadd->sin_port));		          
		pih->slave_node_array[0].recv_rep_pkt++; /* 从应用 */
		pih->slave_node_array[0].send_req_pkt++;
		pih->slave_node_array[0].state = LIBPING_STATE_KEEPALIVE_SUCC;		
	}

	pih->last_rcv_request_time_mark = pih->g_current_time_mark;

	return 0;
}

static int libping_slave_recv_pkt(libping_inner_t *pih)
{
	struct sockaddr_in sockadd;
	char rcv_buf[1500];
	socklen_t saddr_len;
	const libping_msg_t *pmsg = (libping_msg_t *)&rcv_buf[0];
	const libping_msg_keepalive_str_t *pmsg_kp_req;
	int msg_len;

	saddr_len = sizeof(struct sockaddr);
	msg_len = MESA_sock_recvfrom(pih->sock_fd, rcv_buf, 1500, 0, (struct sockaddr *)&sockadd, &saddr_len, 100);
	if(msg_len < 0){
		return -1;
	}
	
	if(libping_pkt_verify(pih, pmsg, msg_len) == 0){
		return -1;
	}

	switch(pmsg->msg_type){
		case LIBPING_MSG_TYPE_DETECT_BINGO:
		{
			const libping_msg_detect_t *rcv_msg_det = (libping_msg_detect_t *)(rcv_buf + sizeof(libping_msg_t));	
			if(rcv_msg_det->detect_seed != (pih->identification ^ LIBPING_DETECT_XOR_MAGIC)){
				PING_PRT("[slave] rcv master detect reply pkt, but seed invalid:  raw seed:%llx, master reply seed:%llx\n", pih->identification, rcv_msg_det->detect_seed);
				break;
			}

			if(0 == pih->master_ip_port_by_manual){
				pih->master_ip_net = sockadd.sin_addr.s_addr;
				pih->master_port_net = sockadd.sin_port;
			}
			pih->slave_node_array[0].state = LIBPING_STATE_FOUND;
			
		}
		break;

		case LIBPING_MSG_TYPE_REGISTER_RESPONSE:
		{
			const libping_msg_register_t *rcv_msg_reg= (libping_msg_register_t *)(rcv_buf + sizeof(libping_msg_t));	
			if(rcv_msg_reg->slave_id != pih->slave_id){
				break;
			}
			pih->slave_node_array[0].state = LIBPING_STATE_REGISTERED;
		}	
		break;

		case LIBPING_MSG_TYPE_REQUEST:
			if((LIBPING_STATE_REGISTERED != pih->slave_node_array[0].state)
			&& (LIBPING_STATE_KEEPALIVE_SUCC != pih->slave_node_array[0].state)){
				PING_PRT("[slave] rcv master request pkt, but slave state is:%d, ignore it!\n", pih->slave_node_array[0].state);
				break;
			}
			pmsg_kp_req = (libping_msg_keepalive_str_t *)(rcv_buf + sizeof(libping_msg_t));
			libping_slave_reply_pkt(pih, pmsg_kp_req, &sockadd);
		break;

		default:
		break;
	}

	return 0;
}

static void libping_slave_check_status(libping_inner_t *pih)
{
	if((LIBPING_STATE_REGISTERED == pih->slave_node_array[0].state)
	||(LIBPING_STATE_KEEPALIVE_SUCC ==  pih->slave_node_array[0].state)){

		if(pih->last_rcv_request_time_mark + LIBPING_KEEPALIVE_ACCURACY * 5 < pih->g_current_time_mark){
			/* 经过三个保活周期都收不到主的保活请求, 
			   可能原因是:
			       1-master崩溃了
			       2-master重启, 但是绑定的端口变了
			       3-网络故障
			       4-相同的slave被误操作启动了两个进程, 
			       
			   此类情况设置为ERR状态. 
			*/
			PING_PRT("slave:%d has not recv any packet from master, state to ERROR!\n", pih->slave_id);
			pih->slave_node_array[0].state = LIBPING_STATE_KEEPALIVE_ERR;
		}
		
		if(pih->last_rcv_request_time_mark + LIBPING_SILENT_TIME < pih->g_current_time_mark){
			/* 经过静默期后, 还收不到主的保活请求, 重置初始状态 */
			PING_PRT("slave:%d has not recv any packet from master, state to INIT!\n", pih->slave_id);

			pih->last_rcv_request_time_mark = pih->g_current_time_mark; /* 重置为当前时间, 否则错误检测立刻就会触发 */
			pih->slave_node_array[0].state = LIBPING_STATE_INIT;
			if(0 == pih->master_ip_port_by_manual){
				pih->master_ip_net = htonl(0x7f000001);
				pih->master_port_net = htons(LIBPING_BEGIN_BIND_PORT);
			}		
			pih->slave_node_array[0].recv_rep_pkt = 0;  
			pih->slave_node_array[0].send_req_pkt = 0;		
		}
	}

	return;
}

static int libping_slave_send_detect_pkt(libping_inner_t *pih)
{
	struct sockaddr_in sockadd;	
	char send_buf[128];
	int i, loop_num, ret;
	unsigned short master_port_host;

	libping_msg_t *snd_msg = (libping_msg_t *)send_buf;
	libping_msg_detect_t *snd_msg_det = (libping_msg_detect_t *)(send_buf + sizeof(libping_msg_t));

	snd_msg->magic = LIBPING_MSG_MAGIC;
	snd_msg->pair_tag = pih->pair_tag;
	snd_msg->version = 1;
	snd_msg->msg_type = LIBPING_MSG_TYPE_DETECT;

	snd_msg_det->detect_seed = pih->identification;
	
	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family = AF_INET;

	if(0 == pih->master_ip_port_by_manual){ /* 自动探测模式 */
		sockadd.sin_addr.s_addr = htonl(0x7f000001);
		master_port_host = LIBPING_BEGIN_BIND_PORT;
		loop_num = 65535 - LIBPING_BEGIN_BIND_PORT;
	}else{
		sockadd.sin_addr.s_addr = pih->master_ip_net;
		sockadd.sin_port = pih->master_port_net;
		loop_num = 1;
	}

	for(i = 0; i < loop_num; i++){
		ret = sendto(pih->sock_fd, send_buf, sizeof(libping_msg_t)+sizeof(libping_msg_detect_t), 0,
		       	   (struct sockaddr *)&sockadd, sizeof(sockadd));
		if(ret < 0){
			PING_PRT("[slave] send detect packet error, %s!\n", strerror(errno));
		}
		if((LIBPING_STATE_INIT != pih->slave_node_array[0].state)
		&&(LIBPING_STATE_DETECTING != pih->slave_node_array[0].state)){
			PING_PRT("[slave] %d has recv detect bingo packet from master, state to FOUND!\n", pih->slave_id);
			break; /* 其他接收线程收到了应答, 修改了状态 */
		}
		sockadd.sin_port = htons(++master_port_host);
		
		usleep(1000 * 10);
	}

	return 0;
}

static int libping_slave_send_register_pkt(libping_inner_t *pih)
{
	struct sockaddr_in sockadd;	
	char send_buf[128];
	int i;
	const int retry_times = 10;

	libping_msg_t *snd_msg = (libping_msg_t *)send_buf;
	libping_msg_register_t *snd_msg_reg = (libping_msg_register_t *)(send_buf + sizeof(libping_msg_t));

	snd_msg->magic = LIBPING_MSG_MAGIC;
	snd_msg->pair_tag = pih->pair_tag;
	snd_msg->version = 1;
	snd_msg->msg_type = LIBPING_MSG_TYPE_REGISTER;

	snd_msg_reg->slave_id = pih->slave_id;
	
	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family = AF_INET;

	sockadd.sin_addr.s_addr = pih->master_ip_net; /* 收到master应答时, 要填充此值 */
	sockadd.sin_port = pih->master_port_net; /* 收到master应答时, 要填充此值 */

	for(i = 0; i < retry_times; i++){
		sendto(pih->sock_fd, send_buf, sizeof(libping_msg_t)+sizeof(libping_msg_register_t), 0,
		       	   (struct sockaddr *)&sockadd, sizeof(sockadd));
		if(LIBPING_STATE_FOUND != pih->slave_node_array[0].state){
			PING_PRT("[slave] %d has recv register response packet from master, state to REGISTERED!\n", pih->slave_id);
			break; /* 其他接收线程收到了注册应答, 修改了状态 */
		}
		
		usleep(1000 * 1000);
	}

	if(i == retry_times){
		/* 发送retry_times次注册包, 都未收到应答, 可能是刚探测到master, master就重启或出现其他错误, 重置为LIBPING_STATE_DETECTING状态 */
		pih->slave_node_array[0].state = LIBPING_STATE_INIT;
	}
	
	return 0;
}

static void *libping_slave_send_thread(void *arg)
{
	libping_inner_t *pih = (libping_inner_t *)arg;
	
	while(1){
		switch(pih->slave_node_array[0].state){ 
			case LIBPING_STATE_INIT:
			case LIBPING_STATE_DETECTING:
				libping_slave_send_detect_pkt(pih);
			break;

			case LIBPING_STATE_FOUND:
				libping_slave_send_register_pkt(pih);
			break;

			default:
				/* 其他状态无需主动发包, 被动等待主发送请求 */
			break;
		}

		usleep(1000 * 10);
	}

	return NULL;
}

static void *libping_slave_recv_thread(void *arg)
{
	libping_inner_t *pih = (libping_inner_t *)arg;
	
	while(1){
		libping_slave_recv_pkt(pih);

		libping_slave_check_status(pih);

		usleep(1);
	}

	return NULL;
}

static void *libping_time_thread(void *arg)
{
	libping_inner_t *pih = (libping_inner_t *)arg;
	struct timeval time1, time2;
	
	while(1){
		gettimeofday(&time1, NULL);
		usleep(100);
		gettimeofday(&time2, NULL);

		/* 获取当前毫秒数, usleep(1), 再获取, 直到keepalive_interval后, 把g_current_time_mark加1 */
		while((time2.tv_sec*1000 + time2.tv_usec/1000)  - (time1.tv_sec*1000 + time1.tv_usec/1000) < pih->keepalive_interval){
			usleep(10);
			gettimeofday(&time2, NULL);
		}

		pih->g_current_time_mark++;
	}

	return NULL;
}

/* 从起始端口开始, 依次查找可用端口, 自动绑定 */
static int libping_bind_available_port(libping_inner_t *pih)
{
	unsigned short tport;
	struct sockaddr_in sockadd;
	int auto_try_flag = 0;

	bzero(&sockadd, sizeof(sockadd));
	sockadd.sin_family = AF_INET;
	sockadd.sin_addr.s_addr = htonl(INADDR_ANY);

	if(0 == pih->bind_begin_port_net){
		tport = LIBPING_BEGIN_BIND_PORT; /* 未明确指定本地绑定端口 */
		auto_try_flag = 1;	
	}else{
		tport = ntohs(pih->bind_begin_port_net);
	}

	for(; tport < 65535; tport++){
		sockadd.sin_port = htons(tport);
		if(bind(pih->sock_fd, (struct sockaddr *) &sockadd, sizeof(sockadd)) < 0){
			if(0 == auto_try_flag){
				break;
			}else{
				continue;
			}
		}else{
			goto bingo;
		}
	}
	
	pih->actual_bind_port_net = 0;
	return -1;

bingo:
	pih->actual_bind_port_net = ntohs(tport);
	return 0;
}


static void libping_set_default_args(libping_inner_t *pih)
{
	pih->keepalive_interval = 50; /* 默认50毫秒精度 */
	pih->identification = random();

	return;
}

static int libping_args_check(libping_inner_t *pih)
{
	if(pih->master_ip_port_by_manual != 0){
		if(0 == pih->master_ip_net){
			PING_PRT("[slave] has set master port, but not set ip!\n");
			return -1;	
		}
		if(0 == pih->master_port_net){
			PING_PRT("[slave] has set master ip, but not set port!\n");
			return -1;	
		}		
	}

	return 1;
}

static int libping_pre_run_init(libping_inner_t *pih)
{
	int ret;

	/* 到此阶段, 如果work_mode仍未明确设置, 默认为slave模式 */
	if(0 == pih->work_mode){
		pih->work_mode = LIBPING_WORK_MODE_SLAVE;
		pih->bind_begin_port_net = htons(ntohs(pih->bind_begin_port_net) + 1);
	}

	if(libping_args_check(pih) < 0){
		return -1;
	}
	
	pih->sock_fd = socket(AF_INET,SOCK_DGRAM,0);
	if(pih->sock_fd  < 0){
		return -1;
	}
	/* NOTE:  UDP-socket千万不要使用SO_REUSEADDR选项, 否则多个进程可以绑定成功同一个端口!! */
#if 0	
	int opt = 1;
	setsockopt(pih->sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(int));
#endif

	ret = libping_bind_available_port(pih);
	if(ret < 0){
		return -1;
	}

	if(LIBPING_WORK_MODE_SLAVE == pih->work_mode){
		/* slave复用slave_node_array变量, 用于存储相关变量和状态 */
		pih->slave_node_array = (libping_node_t *)calloc(1, sizeof(libping_node_t));
		pih->slave_node_num = 1;
	}
	
	pthread_mutex_init(&pih->mutex, NULL);

	return 0;
}

ping_handle libping_create(void)
{
	libping_inner_t *pih;

	pih = (libping_inner_t *)calloc(1, sizeof(libping_inner_t));

	libping_set_default_args(pih);
	
	return pih;
}



int libping_run(ping_handle ph)
{
	pthread_t pid_master_send, pid_master_rcv, pid_slave, pid_slave_send, time_mark;
	libping_inner_t *pih = (libping_inner_t *)ph;

	if(0 == pih->pair_tag){
		PING_PRT("libping must assign pair_tag!!!\n");
		return -1;
	}
	
	libping_pre_run_init(pih);

	srand(time(NULL));
	
	pthread_create(&time_mark, NULL, libping_time_thread, ph);

	if(LIBPING_WORK_MODE_MASTER == pih->work_mode){
		pthread_create(&pid_master_send, NULL, libping_master_main_thread, ph);
		pthread_create(&pid_master_rcv, NULL, libping_master_recv_thread, pih);

		PING_PRT("libping master starting......\n");
	}else{
		pthread_create(&pid_slave_send, NULL, libping_slave_send_thread, ph);
		pthread_create(&pid_slave, NULL, libping_slave_recv_thread, ph);
		PING_PRT("libping slave starting......\n");
	}
	
	return 0;
}

static int libping_get_opt_node_status_for_master(libping_inner_t *pih, node_status_t *nst)
{
	int i, ret = -1;
	
	pthread_mutex_lock(&pih->mutex);
	for(i = 0; i < pih->slave_node_num; i++){
		if(pih->slave_node_array[i].slave_id == nst->slave_id){
			nst->slave_ip_net = pih->slave_node_array[i].ip_net_order;
			nst->slave_port_net = pih->slave_node_array[i].port_net_order;
			nst->state = pih->slave_node_array[i].state;
			nst->send_req_pkt = pih->slave_node_array[i].send_req_pkt;
			nst->recv_rep_pkt = pih->slave_node_array[i].recv_rep_pkt;
			ret = 0;
			break;
		}
	}
	pthread_mutex_unlock(&pih->mutex);

	return ret;
}

static int libping_get_opt_node_status_for_slave(libping_inner_t *pih, node_status_t *nst)
{
	nst->slave_port_net = pih->actual_bind_port_net;
	nst->state = pih->slave_node_array[0].state;
	nst->send_req_pkt = pih->slave_node_array[0].send_req_pkt;
	nst->recv_rep_pkt = pih->slave_node_array[0].recv_rep_pkt;

	return 0;
}

static int libping_get_opt_node_list(libping_inner_t *pih, int *node_array, int *node_array_num)
{
	int out_index, pih_inner_index;
	int valid_out_num; /* 可输出的最大数量 */
	int actual_out_node_num = 0; /* 实际输出的元素个数 */

	pthread_mutex_lock(&pih->mutex);

	/* 实际slave数量和外部可接收数量, 取最小值 */
	valid_out_num = MIN(pih->slave_node_num, *node_array_num);

	if(0 == valid_out_num){
		*node_array_num = 0;
		goto done;
	}

	for(out_index = 0, pih_inner_index = 0; ((pih_inner_index < pih->slave_node_num) && (actual_out_node_num <= valid_out_num)); ){
		if(0 != pih->slave_node_array[pih_inner_index].slave_id){
			node_array[out_index++] = pih->slave_node_array[pih_inner_index++].slave_id;
			actual_out_node_num++;
		}else{
			pih_inner_index++;
		}
	}

	*node_array_num = actual_out_node_num;

done:
	pthread_mutex_unlock(&pih->mutex);
	
	return actual_out_node_num;
}

int libping_get_opt(ping_handle ph, enum libping_opt_t opt_type, void *opt_value, int *opt_len)
{
	int ret = 0;
	libping_inner_t *pih = (libping_inner_t *)ph;

	if(NULL == opt_value || opt_len <= 0){
		return -1;
	}

	switch((int)opt_type){
		case PO_NODE_LIST:
			if(LIBPING_WORK_MODE_MASTER == pih->work_mode){
				ret = libping_get_opt_node_list(pih, (int *)opt_value, opt_len);
			}else{
				PING_PRT("libping_get_opt error! in slave mode, not support 'PO_NODE_LIST'!\n");
				return -1;
			}
		break;
		
		case PO_NODE_STATUS:
		{
			node_status_t *nst = (node_status_t *)opt_value;
			if(0 == nst->slave_id){
				return -1;
			}
			if(LIBPING_WORK_MODE_MASTER == pih->work_mode){
				ret = libping_get_opt_node_status_for_master(pih, nst);
			}else{
				ret = libping_get_opt_node_status_for_slave(pih, nst);
			}
		}
		break;

		default:
			ret = -1;
		break;
	}

	return ret;
}

int libping_set_opt(ping_handle ph, enum libping_opt_t opt_type, void *opt_value, int opt_len)
{
	int ret = 0;
	libping_inner_t *pih = (libping_inner_t *)ph;

	if(NULL == opt_value || opt_len <= 0){
		return -1;
	}

	switch((int)opt_type){
		case PO_PAIR_TAG:
		{
			unsigned int *pair_tag = (unsigned int *)opt_value;
			pih->pair_tag = *pair_tag;
		}
		break;

		case PO_WORK_MODE:
		{
			unsigned short *wmode = (unsigned short *)opt_value;
			pih->work_mode= *wmode;
		}
		break;

		case PO_SLAVE_PRE_REPLAY_CB:
		{
			pih->slave_pre_reply_cb = opt_value;
		}
		break;		

		case PO_SLAVE_ID:
		{
			unsigned int *sid = (unsigned int *)opt_value;
			pih->slave_id = *sid;
		}
		break;

		case PO_MASTER_IP_NET_ORDER:
		{
			unsigned int *ipnet = (unsigned int *)opt_value;
			pih->master_ip_net= *ipnet;
			pih->master_ip_port_by_manual = 1;
		}
		break;

		case PO_MASTER_PORT_NET_ORDER:
		{
			unsigned short *portnet = (unsigned short *)opt_value;
			pih->master_port_net= *portnet;
			pih->master_ip_port_by_manual = 1;
		}
		break;

		case PO_KEEPALIVE_INTERVAL:
		{
			int *kintval = (int *)opt_value;
			pih->keepalive_interval = *kintval;
		}		
		break;

		case PO_BIND_BEGIN_PORT_NET_ORDER:
		{
			unsigned short *bport = (unsigned short *)opt_value;
			pih->bind_begin_port_net = *bport;
		}
		break;

		default:
			ret = -1;
		break;
	}

	return ret;
}


#ifdef __cplusplus
}
#endif

