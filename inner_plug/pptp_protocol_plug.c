#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <MESA/MESA_htable.h>
#include "stream.h"
#include "stream_internal.h" 
#include "stream_manage.h"
#include "mesa_net.h"
#include "sysinfo.h"
#include "stream_tunnel.h"

const int pptp_protocol_version_VERSION_20170105 = 20170105;

extern void pptp_stream_free(struct streaminfo *pptp_stream);
/*
	虚拟pptp解析层, 
	1)用于获取全局插件ID, 并存储于g_pptp_plugid;
	2)插件名称设为pptp, 用于创建一个"pptp"层的协议解析层入口,
	  真正的业务插件需要挂载到"pptp"层.
	3)本插件处理pptp的控制连接, 其余与隧道相关解析逻辑放在deal_ppp.c中.

	相关RFC: RFC2637.
*/

#define PPTP_CONTROL_LINK_PORT		(1723)

#define PPTP_CONTROL_LINK_MAGIC		(0x1A2B3C4D)

enum pptp_messge_type_t{
	PPTP_MESSAGE_CONTROL 	= 1,
	PPTP_MESSAGE_MANAGE 		= 2, /* RFC定义但未实际使用 */
};


struct pptp_control_out_go_req{
	unsigned short length; /* 全部数据长度, 包括本头部 */
	unsigned short pptp_message_type;
	unsigned int magic_cookie;
	unsigned short control_message_type;	
	unsigned short reserved0;
	unsigned short call_id;
	unsigned short call_serial_num;
	unsigned int min_bps;
	unsigned int max_bps;
	unsigned int bearer_type;
	unsigned int framing_type;
	unsigned short pkt_rcv_win;
	unsigned short pkt_process_delay;
	unsigned short pbone_number_len;
	unsigned short reserved1;
	char phone_number[64];
	char subaddress[64];
};

struct pptp_control_out_go_reply{
	unsigned short length; /* 全部数据长度, 包括本头部 */
	unsigned short pptp_message_type;
	unsigned int magic_cookie;
	unsigned short control_message_type;	
	unsigned short reserved0;
	unsigned short call_id;
	unsigned short peer_call_id;
	unsigned char result_code;
	unsigned char error_code;
	unsigned short cause_code;
	unsigned int connect_speed;
	unsigned short pkt_rcv_win;
	unsigned short pkt_process_delay;
	unsigned int phy_channel_id;
};

struct pptp_control_set_link_info{
	unsigned short length; /* 全部数据长度, 包括本头部 */
	unsigned short pptp_message_type;
	unsigned int magic_cookie;
	unsigned short control_message_type;	
	unsigned short reserved0;
	unsigned short peer_call_id;
	unsigned short reserved1;
	unsigned int send_accm;
	unsigned int recv_accm;
};

extern unsigned short g_pptp_plugid;

extern MESA_htable_handle *g_pptp_htable_array;


static int pptp_control_protocol_identify(const struct streaminfo *a_tcp)
{
	const struct stream_tuple4_v4 *tuple4_v4;
	const struct stream_tuple4_v6 *tuple4_v6;
	const struct mesa_pptp_control_hdr *pptp_ctrl_hdr;

	if(a_tcp->ptcpdetail->datalen < sizeof(struct mesa_pptp_control_hdr)){
		/* 数据小于最小可识别长度, 或长度和pptp头部不相等 */
		return 0;
	}

	pptp_ctrl_hdr = (const struct mesa_pptp_control_hdr *)a_tcp->ptcpdetail->pdata;

	if(ntohs(pptp_ctrl_hdr->length) != a_tcp->ptcpdetail->datalen){
		/* 数据长度和pptp头部不相等 */
		return 0;
	}

	if(ADDR_TYPE_IPV4 == a_tcp->addr.addrtype){
		tuple4_v4 = a_tcp->addr.tuple4_v4;
		if((PPTP_CONTROL_LINK_PORT != ntohs(tuple4_v4->source))
		 && (PPTP_CONTROL_LINK_PORT != ntohs(tuple4_v4->dest))){
			return 0;
		}
	}else{
		tuple4_v6 = a_tcp->addr.tuple4_v6;
		if((PPTP_CONTROL_LINK_PORT != ntohs(tuple4_v6->source))
		 && (PPTP_CONTROL_LINK_PORT != ntohs(tuple4_v6->dest))){
			return 0;
		}
	}


	if(PPTP_CONTROL_LINK_MAGIC != ntohl(pptp_ctrl_hdr->magic_cookie)){
		return 0;
	}

	/* manage type 实际未使用 */
	if(PPTP_MESSAGE_CONTROL != ntohs(pptp_ctrl_hdr->pptp_message_type)){
		return 0;
	}

	if(ntohs(pptp_ctrl_hdr->control_message_type) > PPTP_CTRL_SET_LINK_INFO){
		return 0;
	}

	/* 都符合PPTP协议规范, 可以认为是PPTP控制协议流 */
	return 1;
}

static char pptp_control_call_biz_plug(const struct streaminfo *stream, struct pptp_info_pri *pptp_pri, const void *ip_hdr)
{
	char biz_plug_ret;

	biz_plug_ret = PROT_PROCESS(&pptp_pri->ssinfo, &pptp_pri->biz_pme, stream->threadnum, (struct streaminfo * )stream, ip_hdr);
	pptp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;
	pptp_pri->ssinfo.buf = NULL;
	pptp_pri->ssinfo.buflen = 0;
	
	return biz_retval_to_platform(biz_plug_ret);
}


static inline void pptp_context_init(struct pptp_info_pri *pptp_pri, unsigned char threadnum)
{
	memset(pptp_pri, 0, sizeof(struct pptp_info_pri)); 

	pptp_pri->threadnum = threadnum;

	pptp_pri->tunnel_context.tunnel_type = STREAM_TYPE_PPTP;

	pptp_pri->ssinfo.plugid = g_pptp_plugid;
	pptp_pri->ssinfo.session_state = SESSION_STATE_PENDING;
	pptp_pri->ssinfo.prot_flag = TUNNEL_PHONY_PROT_FLAG;

	pptp_pri->ssinfo.app_info = &pptp_pri->tunnel_context;
}

/*
	数据连接阶段, 因PPTP层还没有流管理结构, 所以在控制连接阶段, 为pptp数据阶段临时构造一个streaminfo结构, 并创建pfather链表,
	保证pptp业务插件看起来像pptp层有流结构.

	控制连接从TCP开始, pptp数据连接先创建一个PPTP层, 再创建一个纯IPv4层, 
	然后余下的从a_tcp->pfather开始复制底层流信息.
*/
struct streaminfo *pptp_build_data_stream_info(const struct streaminfo *a_tcp, struct pptp_stream_key *pptp_key)
{
	UCHAR threadnum = a_tcp->threadnum;
	struct streaminfo *pptp_data_stream = (struct streaminfo *)dictator_malloc(threadnum, sizeof(struct streaminfo));

	/* PPTP层, 先复制一下整体, 具体变量后面再修改 */
	memcpy(pptp_data_stream, a_tcp, sizeof(struct streaminfo));

	pptp_data_stream->addr.addrtype = ADDR_TYPE_PPTP;
	pptp_data_stream->addr.addrlen =  sizeof(struct layer_addr_pptp);
	pptp_data_stream->addr.paddr = dictator_malloc(threadnum, sizeof(struct layer_addr_pptp));
	pptp_data_stream->addr.pptp->C2S_call_id = pptp_key->sip_side_call_id;
	pptp_data_stream->addr.pptp->S2C_call_id = pptp_key->dip_side_call_id;
	pptp_data_stream->type = STREAM_TYPE_PPTP;
	pptp_data_stream->pdetail = NULL;

	/* IP pair层 */
	pptp_data_stream->pfather = (struct streaminfo *)dictator_malloc(threadnum, sizeof(struct streaminfo));
	struct streaminfo *ip_layer_stream = pptp_data_stream->pfather;
	memcpy(ip_layer_stream, a_tcp, sizeof(struct streaminfo));
	if(ADDR_TYPE_IPV4 == a_tcp->addr.addrtype){
		ip_layer_stream->addr.addrtype = __ADDR_TYPE_IP_PAIR_V4;
		ip_layer_stream->addr.addrlen =  sizeof(struct layer_addr_ipv4);
		ip_layer_stream->addr.paddr = dictator_malloc(threadnum, sizeof(struct layer_addr_ipv4));
		ip_layer_stream->addr.ipv4->saddr = a_tcp->addr.tuple4_v4->saddr;
		ip_layer_stream->addr.ipv4->daddr = a_tcp->addr.tuple4_v4->daddr;
		ip_layer_stream->addr.ipv4->source = 0;
		ip_layer_stream->addr.ipv4->dest = 0;
		ip_layer_stream->type = STREAM_TYPE_NON;
		ip_layer_stream->pdetail = NULL;
		ip_layer_stream->pfather = NULL;
	}else{
		ip_layer_stream->addr.addrtype = __ADDR_TYPE_IP_PAIR_V6;
		ip_layer_stream->addr.addrlen =  sizeof(struct layer_addr_ipv6);
		ip_layer_stream->addr.paddr = dictator_malloc(threadnum, sizeof(struct layer_addr_ipv6));
		memcpy(ip_layer_stream->addr.ipv6->saddr,  a_tcp->addr.tuple4_v6->saddr, IPV6_ADDR_LEN);
		memcpy(ip_layer_stream->addr.ipv6->daddr,  a_tcp->addr.tuple4_v6->daddr, IPV6_ADDR_LEN);
		ip_layer_stream->addr.ipv6->source = 0;
		ip_layer_stream->addr.ipv4->dest = 0;
		ip_layer_stream->type = STREAM_TYPE_NON;
		ip_layer_stream->pdetail = NULL;
		ip_layer_stream->pfather = NULL;
	}

	/* 原始流中IP层以下的流 */
	const struct streaminfo *raw_stream_ip_low_layer = a_tcp->pfather;
	struct streaminfo *tmp_stream;
	
	while(raw_stream_ip_low_layer != NULL){
		tmp_stream = (struct streaminfo *)dictator_malloc(threadnum, sizeof(struct streaminfo));
		memcpy(tmp_stream, raw_stream_ip_low_layer, sizeof(struct streaminfo));
		tmp_stream->addr.paddr = dictator_malloc(threadnum, raw_stream_ip_low_layer->addr.addrlen);
		memcpy(tmp_stream->addr.paddr, raw_stream_ip_low_layer->addr.paddr, raw_stream_ip_low_layer->addr.addrlen);
		tmp_stream->pfather = NULL;
		ip_layer_stream->pfather = tmp_stream;
		ip_layer_stream = ip_layer_stream->pfather;
		raw_stream_ip_low_layer = raw_stream_ip_low_layer->pfather;
	}

	return pptp_data_stream;
}

static int pptp_stream_key_insert_hash(const struct streaminfo *a_tcp, int tid, struct pptp_stream_key *pptp_key)
{
	struct pptp_info_pri *pptp_pri;
	int hash_ret;

	/* 因为控制连接首先创建HASH节点, 同时插入一个空的pptp_pri结构, HASH表中的元素在data_channel连接终止时, 在data通道中删除 */
	pptp_pri = (struct pptp_info_pri *)dictator_malloc(tid, sizeof(struct pptp_info_pri));
	pptp_context_init(pptp_pri, tid);
	pptp_pri->ssinfo.session_state = 0; /* PPTP数据传输阶段, 不方便判断pending, data, close状态, 靠判断当前session-state值决定 */
	memcpy(&pptp_pri->pptp_key, pptp_key, sizeof(struct pptp_stream_key));

	pptp_pri->my_stream = pptp_build_data_stream_info(a_tcp, pptp_key);

	/* TODO 1, pptp_key增加嵌套地址链表 */
	hash_ret = MESA_htable_add(g_pptp_htable_array[tid], (const uchar *)pptp_key, sizeof(struct pptp_stream_key), pptp_pri);
	if(hash_ret < 0){
		/* NOTE: 底层隧道一样, 但隧道内有多个TCP连接时, 会HASH冲突, 需要free */
		pptp_stream_free(pptp_pri->my_stream);
		dictator_free(tid, pptp_pri);
	}else{
#if 0	
		if(hash_ret > 29){
			/* 
				2016-12-30 lijia add, 被迫添加此判断:
				受限于HASH算法只能用IP对,
				当HASH冲突严重时, 主动丢弃部分PPTP流, 防止单包处理延时太长, 保证不影响其他业务. 
			*/
			MESA_htable_del(g_pptp_htable_array[tid], (const uchar *)pptp_key, sizeof(struct pptp_stream_key), NULL);
		}
#endif
#ifdef MESA_HTABLE_VERSION_MACRO
	#if MESA_HTABLE_VERSION_MACRO >= 20170104
		int len, max_times;
		double avg_times;
		len = sizeof(int);
		MESA_htable_get_opt(g_pptp_htable_array[tid], MHO_HASH_SEARCH_MAX_TIMES, &max_times, &len);

		len = sizeof(double);
		MESA_htable_get_opt(g_pptp_htable_array[tid], MHO_HASH_SEARCH_AVG_TIMES, &avg_times, &len);

		if(max_times > sapp_global_mthread[tid].pptp_hash_max_search_times){
			sapp_global_mthread[tid].pptp_hash_max_search_times = max_times;
			sapp_runtime_log(30, "pptp hash max search times: %d, thread seq:%d.\n", max_times, tid);
		}
		if(avg_times > sapp_global_mthread[tid].pptp_hash_avg_search_times){
			sapp_global_mthread[tid].pptp_hash_avg_search_times = avg_times;
			sapp_runtime_log(30, "pptp hash avg search times: %.2f, thread seq:%d.\n", avg_times, tid);
		}
	#endif
#else
		/* 在旧版机器上, 为了安全不写冲突日志, 还是要判断最大冲突链节点数 */
		if(hash_ret > 29){
			/* 
				2016-12-30 lijia add, 被迫添加此判断:
				受限于HASH算法只能用IP对,
				当HASH冲突严重时, 主动丢弃部分PPTP流, 防止单包处理延时太长, 保证不影响其他业务. 
			*/
			MESA_htable_del(g_pptp_htable_array[tid], (const uchar *)pptp_key, sizeof(struct pptp_stream_key), NULL);
		}
#endif	
	}
	return hash_ret;
}


static inline void pptp_control_set_key(const struct streaminfo *a_tcp, int tid, struct pptp_info_pri *pptp_pri, 
		unsigned int sip, unsigned int dip, unsigned short sip_side_callid, unsigned short dip_side_callid)
{
	pptp_pri->pptp_key.sip = sip;
	pptp_pri->pptp_key.dip = dip;
	pptp_pri->pptp_key.sip_side_call_id = sip_side_callid;
	pptp_pri->pptp_key.dip_side_call_id = dip_side_callid;

	/* 双向的call_id都已获取到, 可以插入HASH表, 用于识别对应的数据连接 */
	if((0 == pptp_pri->insert_hash_flag)
	  && (pptp_pri->pptp_key.sip_side_call_id != 0)
	  &&(pptp_pri->pptp_key.dip_side_call_id != 0)){
   		pptp_stream_key_insert_hash(a_tcp, tid, &pptp_pri->pptp_key);
   		pptp_pri->insert_hash_flag = 1;
	}
	
	return;
}

static int pptp_control_protocol_process_data(const struct streaminfo *a_tcp,  
				struct pptp_info_pri *pptp_pri, const struct mesa_ip4_hdr *ip_hdr)
{
	/*
		TODO 1,
		跟踪控制连接, 解析出callid, 暂存于struct pptp_stream_key,
		当两个方向的callid都获取到(即便单向流, 也可以获取对方的),
		加入全局的PPTP_HASH表, 
		在PPTP数据通道里, 跟踪LCP和CCP协议, 记录认证算法、加密算法、压缩算法等等.
		进入IPCP阶段后, 根据struct pptp_stream_key(数据通道只有三元组),
		在HASH表找到相关元素,
		调用biz_plug, 输出数据通道相关信息.

		PPTP全局HASH表项在数据通道调用biz_plug之后即可主动删除, 
		或者靠被动超时淘汰.
	*/

	const struct mesa_pptp_control_hdr *pptp_ctrl_hdr;
	unsigned short control_message_type;

	if(NULL == a_tcp->ptcpdetail->pdata){
		return APP_STATE_GIVEME;
	}
	
	pptp_ctrl_hdr = (const struct mesa_pptp_control_hdr *)a_tcp->ptcpdetail->pdata;
	control_message_type = ntohs(pptp_ctrl_hdr->control_message_type);
	
	if(ntohs(pptp_ctrl_hdr->pptp_message_type) != PPTP_MESSAGE_CONTROL){
		return APP_STATE_GIVEME;
	}

	switch(control_message_type){
		case PPTP_CTRL_OUT_GO_REQ:
		{
			const struct pptp_control_out_go_req *pptp_ctrl_out_go_req_hdr;
			pptp_ctrl_out_go_req_hdr = (const struct pptp_control_out_go_req *)pptp_ctrl_hdr;
			pptp_control_set_key(a_tcp, a_tcp->threadnum, pptp_pri, ip_hdr->ip_src.s_addr,  
								 ip_hdr->ip_dst.s_addr, 0, pptp_ctrl_out_go_req_hdr->call_id);
		}
		break;

		/* 其实可以在PPTP_CTRL_OUT_GO_REPLY消息中获取双方的callid, 但考虑单向流情况, 仍然监测PPTP_CTRL_OUT_GO_REQ和PPTP_CTRL_SET_LINK_INFO */
		case PPTP_CTRL_OUT_GO_REPLY:
		{
			const struct pptp_control_out_go_reply *pptp_ctrl_out_go_rep_hdr;
			pptp_ctrl_out_go_rep_hdr = (const struct pptp_control_out_go_reply *)pptp_ctrl_hdr;
			pptp_control_set_key(a_tcp, a_tcp->threadnum, pptp_pri, ip_hdr->ip_src.s_addr,  ip_hdr->ip_dst.s_addr,  
								pptp_ctrl_out_go_rep_hdr->peer_call_id, 
								pptp_ctrl_out_go_rep_hdr->call_id);
		}
		break;

		/* 控制连接发出第一个SET_LINK_INFO命令后, 数据连接开始建立PPP_LCP通道 */
		case PPTP_CTRL_SET_LINK_INFO:
		{
			const struct pptp_control_set_link_info *pptp_ctrl_set_link_info;
			pptp_ctrl_set_link_info = (const struct pptp_control_set_link_info *)pptp_ctrl_hdr;
			/* 此命令是对方的callid */
			pptp_control_set_key(a_tcp, a_tcp->threadnum, pptp_pri, ip_hdr->ip_src.s_addr,  ip_hdr->ip_dst.s_addr, 
								pptp_ctrl_set_link_info->peer_call_id, 0);
		}
		break;
	}

	pptp_pri->ssinfo.session_state = SESSION_STATE_DATA;
	pptp_control_call_biz_plug(a_tcp, pptp_pri, ip_hdr);

	if(PPTP_CTRL_STOP_CONN_REPLY == control_message_type){
		/* 收到主动结束控制包, 及时删除pptp流 */
		MESA_htable_del(g_pptp_htable_array[a_tcp->threadnum], 
						(const uchar *)&pptp_pri->pptp_key, sizeof(struct pptp_stream_key), 
						NULL);
	}

	return APP_STATE_GIVEME;
}


static int pptp_control_protocol_process_close(const struct streaminfo *a_tcp,  struct pptp_info_pri *pptp_pri, const struct mesa_ip4_hdr *ip_hdr)
{
	/*
		CLOSE状态可能也包含数据, 在调用pptp_control_protocol_process_data()一次.
	*/
	pptp_control_protocol_process_data(a_tcp, pptp_pri, ip_hdr);
	pptp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
	pptp_control_call_biz_plug(a_tcp, pptp_pri, ip_hdr);

	/*
		NOTE: 控制连接流结束时, 可能是因超时或LRU淘汰导致, 并不一定是PPTP隧道真正关闭了, 
		所以此处不能主动删除pptp隧道连接.
	*/

	return APP_STATE_GIVEME;
}

static int pptp_control_protocol_process_pending(const struct streaminfo *a_tcp,  void **pme, const struct mesa_ip4_hdr *ip_hdr)
{
	struct pptp_info_pri *pptp_pri;
	
	pptp_pri = (struct pptp_info_pri *)dictator_malloc(a_tcp->threadnum, sizeof(struct pptp_info_pri)); /* 暂时用标准malloc, free_cb中没有传递线程ID, 只能用free */
	pptp_context_init(pptp_pri, a_tcp->threadnum);
	pptp_pri->tunnel_context.pptp_info.link_type = TUNNEL_CHANNEL_TYPE_CONTROL;
	pptp_pri->tunnel_context.pptp_info.encrypt_pro = -1;
	pptp_pri->tunnel_context.pptp_info.authentication_pro = -1;
	
	*pme = pptp_pri;

	pptp_pri->ssinfo.prot_flag = PPTP_OPT_LINK_TYPE;
	pptp_pri->ssinfo.buf = &pptp_pri->tunnel_context.pptp_info.link_type;
	pptp_pri->ssinfo.buflen = sizeof(int);
	pptp_control_call_biz_plug(a_tcp, pptp_pri, ip_hdr);
	
	/*
		PENDING状态可能也包含数据, 再调用pptp_control_protocol_process_data()一次.
	*/
	pptp_control_protocol_process_data(a_tcp, pptp_pri, ip_hdr);

	return APP_STATE_GIVEME;
}


void pptp_protocol_funstat(unsigned long long protflag)
{
	;
}

long long pptp_protocol_flag_change(char* flag_str)
{
	return 0xFFFF;
}

void pptp_protocol_get_plugid(unsigned short plugid)
{
	g_pptp_plugid = plugid;
}

static uint pptp_stream_key2index(const MESA_htable_handle table, const uchar * key, uint size)
{
	const struct pptp_stream_key *pptp_key = (const struct pptp_stream_key *)key;
	/* NOTE:
	   不能使用call_id做为key, 
	   因为当前包只有一个方向有callid, 另一个方向没有, 导致双向hash不一致 
	 */
	unsigned int i;
	unsigned char *ptr;
	unsigned int seed = 13131;
	unsigned int hash = 0;
	unsigned int sip, dip;

	if(pptp_key->sip >= pptp_key->dip){
		sip = pptp_key->sip;
		dip = pptp_key->dip;
	}else{
		sip = pptp_key->dip;
		dip = pptp_key->sip;
	}
	
	ptr = (unsigned char *)&sip;
	for(i = 0; i < sizeof(int); i++){
		hash = hash * seed + (*ptr++);
	}

	ptr = (unsigned char *)&dip;
	for(i = 0; i < sizeof(int); i++){
		hash = hash * seed + (*ptr++);
	}

	return hash;
}

static  int pptp_stream_key_comp(const uchar * key1, uint size1, const uchar * key2, uint size2)
{
	const struct pptp_stream_key *pptp_key1 = (const struct pptp_stream_key *)key1;
	const struct pptp_stream_key *pptp_key2 = (const struct pptp_stream_key *)key2;	

	/* 先判断IP地址, 分两个方向 */
	if((pptp_key1->sip == pptp_key2->sip) && (pptp_key1->dip == pptp_key2->dip)){ 
		/* 数据连接只能获取单方向的callid, 所以此处只能做三元组比较 */
		if(pptp_key1->sip_side_call_id == pptp_key2->sip_side_call_id){
			return 0;
		}
		if(pptp_key1->dip_side_call_id == pptp_key2->dip_side_call_id){
			return 0;
		}
	}
	/* 反向比较 */
       else if((pptp_key1->sip == pptp_key2->dip) && (pptp_key1->dip == pptp_key2->sip)){
       	/* 数据连接只能获取单方向的callid, 所以此处只能做三元组比较 */
		if(pptp_key1->sip_side_call_id == pptp_key2->dip_side_call_id){
			return 0;
		}
		if(pptp_key1->dip_side_call_id == pptp_key2->sip_side_call_id){
			return 0;
		}
	}

	/* TODO 1, 判断嵌套地址链表, 目前仅判断了最外层的IP和call_id */

	return -1;
}

static uchar *pptp_stream_key_dup(const uchar *key, uint key_size)
{
	const struct pptp_stream_key *pptp_stack_key = (const struct pptp_stream_key *)key;
	struct pptp_stream_key *pptp_heap_key;

	/* TODO 1, 改为dictator_malloc(), 增加threadnum, free时也要用标准free() */
	pptp_heap_key = (struct pptp_stream_key *)malloc(sizeof(struct pptp_stream_key));
	memcpy(pptp_heap_key, pptp_stack_key, sizeof(struct pptp_stream_key));

	return (uchar *)pptp_heap_key;
}

static void pptp_stream_key_free(uchar *key, uint key_size)
{
	/* TODO 1, 改为dictator_malloc(), 需要增加threadnum */
	free(key);
}

/* 强制淘汰回调, 需要最后调用业务层插件 */
static void pptp_stream_data_free_passive(void *data)
{
	struct pptp_info_pri *pptp_pri = (struct pptp_info_pri *)data;
	unsigned char tid = pptp_pri->threadnum;

	pptp_pri->ssinfo.session_state = SESSION_STATE_CLOSE;
	PROT_PROCESS(&pptp_pri->ssinfo, &pptp_pri->biz_pme, tid, pptp_pri->my_stream, NULL);

	pptp_stream_free(pptp_pri->my_stream);
	
	dictator_free(tid, data);
}

/* 创建PPTP 流表, 用于存储data阶段的 struct pptp_info_pri结构 */
static MESA_htable_handle pptp_stream_hash_create(void)
{
	MESA_htable_handle htable;
	int opt_int;
	
	htable = MESA_htable_born();

	opt_int = 0;
	MESA_htable_set_opt(htable, MHO_THREAD_SAFE, &opt_int, sizeof(int));

	opt_int = 1048576;
	MESA_htable_set_opt(htable, MHO_HASH_SLOT_SIZE, &opt_int, sizeof(int));

	opt_int = 100;
	MESA_htable_set_opt(htable, MHO_EXPIRE_TIME, &opt_int, sizeof(int));

	opt_int = 10000;
	MESA_htable_set_opt(htable, MHO_HASH_MAX_ELEMENT_NUM, (void *)&opt_int, sizeof(int));

	MESA_htable_set_opt(htable, MHO_CBFUN_DATA_FREE, (void *)&pptp_stream_data_free_passive, sizeof(void *));
	
	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_TO_INDEX, (void *)&pptp_stream_key2index, sizeof(void *));

	MESA_htable_set_opt(htable, MHO_CBFUN_KEY_COMPARE, (void *)&pptp_stream_key_comp, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_DUP, (void *)&pptp_stream_key_dup, sizeof(void *));	

	MESA_htable_set_opt(htable, MHO_CBFUN_COMPLEX_KEY_FREE, (void *)&pptp_stream_key_free, sizeof(void *));

/* 从20161205版本开始, MESA_htable.h中有宏定义版本号, 可以控制编译代码 */
#ifdef MESA_HTABLE_VERSION_MACRO
	#if MESA_HTABLE_VERSION_MACRO >= 20161205
	opt_int = 0; /* 暂不写冲突日志 */
	MESA_htable_set_opt(htable, MHO_HASH_LIST_COLLIDE_THRESHOLD, (void *)&opt_int, sizeof(int));

	MESA_htable_set_opt(htable, MHO_HASH_LOG_FILE, (void *)"./log/pptp_hash_collide.log", strlen("./log/pptp_hash_collide.log"));
	
	#endif
#endif

	MESA_htable_mature(htable);

	return htable;
}

/* 
	PPTP控制连接解析层插件, 注册在TCP层, biz_plug的entry名为PPTP

*/
char pptp_control_protocol_entry(const struct streaminfo *a_tcp,  void **pme, int thread_seq,const void *ip_hdr)
{
	char pro_plug_ret = APP_STATE_GIVEME;
	struct pptp_info_pri *pptp_pri;

	switch(a_tcp->opstate){
		case OP_STATE_PENDING:
			if(pptp_control_protocol_identify(a_tcp) != 0){
				pro_plug_ret = pptp_control_protocol_process_pending(a_tcp, pme, (const struct mesa_ip4_hdr *)ip_hdr);
			}else{
				pro_plug_ret = APP_STATE_DROPME;
				break;
			}
		break;

		case OP_STATE_DATA:
			pptp_pri = (struct pptp_info_pri *)(*pme);
			pro_plug_ret = pptp_control_protocol_process_data(a_tcp, pptp_pri, (const struct mesa_ip4_hdr *)ip_hdr);
		break;

		case OP_STATE_CLOSE:
			pptp_pri = (struct pptp_info_pri *)(*pme);
			pptp_control_protocol_process_close(a_tcp, pptp_pri, (const struct mesa_ip4_hdr *)ip_hdr);
			pro_plug_ret = APP_STATE_DROPME;
		break;

		default:
			break;
	}

	if(APP_STATE_DROPME == pro_plug_ret){
		if(*pme){
			dictator_free(thread_seq, *pme);
		}
	}
	
	return pro_plug_ret;
}

int pptp_protocol_init(void)
{
	int thread_cnt = get_thread_count();
	int i;
	
	g_pptp_htable_array = (MESA_htable_handle *)malloc(sizeof(MESA_htable_handle) * thread_cnt);
	memset(g_pptp_htable_array, 0, sizeof(MESA_htable_handle) * thread_cnt);

	for(i = 0; i < thread_cnt; i++){
		g_pptp_htable_array[i] = pptp_stream_hash_create();
	}
	
	return g_pptp_plugid;
}

void pptp_protocol_destroy(void)
{
	;
}


#ifdef __cplusplus
}
#endif
