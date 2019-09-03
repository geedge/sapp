#ifdef __cplusplus
extern "C" {
#endif

#include "stream_internal.h"
#include "sendpacket.h"
#include "stream_manage.h"
#include "packet_io.h"	
#include "packet_io_internal.h"	
#include <linux/if_ether.h>

#define VLAN_ID_MAX		(4096) /* vlan id is 12bit, max is 4096 */

#if DEBUG
static inline void packet_io_vlan_status_update(int thread_seq, const struct layer_addr_vlan *addr, int raw_pkt_len);
#endif

static inline void set_vlanid(struct layer_addr_vlan *addr, unsigned short *vlan_tag)
{
	addr->vlan_id = ntohs(*vlan_tag) & VLAN_ID_MASK;
	return;
}

int vlan_8021q_entry(struct streaminfo_private *pfstream_pr,const void *this_layer_data,int thread_num, 
						unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	int ret = PASS;
	struct streamindex tmp_index;
	struct streamindex *ptmp=&tmp_index;
	struct streaminfo_private *pstream_pr = &ptmp->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;	
	struct layer_addr_vlan addr;
	u_short ether_type;
	char *next_layer_hdr = (char *)this_layer_data+ VLAN_TAG_LEN;
	int next_layer_offset = offset_to_raw_pkt_hdr + VLAN_TAG_LEN;

	if(unlikely(0 == G_SKIP_NOT_IP_LAYER)){
		memset(ptmp,0,sizeof(struct streamindex));
		set_vlanid(&addr, (unsigned short *)this_layer_data);
#if DEBUG
		packet_io_vlan_status_update(thread_num, &addr, raw_pkt->raw_pkt_len);
#endif
		pstream->addr.paddr=&addr;
		pstream->addr.addrtype = ADDR_TYPE_VLAN;
		pstream->addr.addrlen = sizeof(struct layer_addr_vlan);
		pstream_pr->addr_use_as_hash = 1;	
		//ptmp->stream.p_layer_header = this_layer_data;
		//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_layer_data - (char *)raw_pkt->raw_pkt_data;
		pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;
		pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */
		
		pstream->pfather=&pfstream_pr->stream_public;
		pstream->type=STREAM_TYPE_NON;
		pstream->routedir=routedir;
		pstream->threadnum=thread_num;
	}else{
		pstream_pr = pfstream_pr; /* 2015-07-03 lijia add, skip this layer */
	}

	ether_type=*((unsigned short *)((char *)this_layer_data + 2));
	ether_type = ntohs(ether_type);

	switch(ether_type)
	{
		case ETH_P_IP:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv4_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
			break;
		case ETH_P_IPV6:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=ipv6_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
			break;

		case ETH_P_8021Q:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=vlan_8021q_entry(pstream_pr, next_layer_hdr,thread_num, routedir,raw_pkt, next_layer_offset);
			break;
			
		case ETH_P_PPP_SES:
#if COMPAT_PAPP_FOR_BENCHMARK
			return PASS;
#endif		
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret=pppoe_session_entry(pstream_pr,next_layer_hdr,thread_num,routedir,raw_pkt, next_layer_offset);
		break;

		case ETH_P_MPLS_UC:
		case ETH_P_MPLS_MC:
			((raw_pkt_t *)raw_pkt)->offset_to_raw_pkt_hdr = next_layer_offset;
			ret = mpls_uc_entry(pstream_pr, (const void *)next_layer_hdr, thread_num, routedir, raw_pkt, next_layer_offset);
			break;

		default:
			/* unknown protocol */	
			g_SysInputInfo[thread_num][PKT_UNKNOWN]++;
			g_SysInputInfo[thread_num][PKT_UNKNOWN_LEN] += raw_pkt->raw_pkt_len;

			sapp_runtime_log(20, "VLAN unknown protocol: 0x%x\n", ether_type);
			
			if(NET_CONN_SERIAL_GDEV == g_topology_mode){
				/* GDEV模式下, 什么时候都不应该把不认识的包再转发出去, 在线发现把SPT生成树协议再注回去, 导致网络故障 */
				ret = DROP;
			}else{
				ret = PASS;
			}
			break;
	}

	return ret;
}

#if DEBUG
#include "iknow.h"

extern int g_packet_io_thread_num;
extern packet_io_status_t *g_packet_io_status_pool[MAX_THREAD_NUM];

/* 
	sysinfo之前是简单二维数组, 不能表示多线程、多协议、多协议的具体参数.
	
	新的架构中, 每类协议自身结构, 在packet_io_status_base_t基础上扩展,
	与之前的sysinfo的简单二维数组不同, 
	新结构每种协议存储的类型不同, 结构也不同, 
	逻辑清晰, 内存使用最优化.
*/
typedef struct{
	packet_io_status_base_t io_base_status; /* VLAN包总计数 */
	unsigned long long vlan_pkt_num[VLAN_ID_MAX]; /* 每个VLAN的包数 */
	unsigned long long vlan_pkt_byte[VLAN_ID_MAX]; /* 每个VLAN的字节数 */
}packet_io_status_vlan_t;

/* 例如: 上一秒:1000B, 当前:5000B, 可计算得最近一秒的实时流量:4000B/s */
static volatile packet_io_status_vlan_t g_io_vlan_last_status, g_io_vlan_cur_status, g_io_vlan_realtime_status;

static long ifuncb_show_vlan_id_summary(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg,const char *cmd_args)
{
	int i;
	/* 全局vlan-id总包数, 总字节数 */
	iprintf(ihandle, iconn, "vlan id summary:\n %7s %9s %10s\n", "VLAN-ID", "Total-pkt", "Total-byte");
	for(i = 0; i < VLAN_ID_MAX; i++){
		if(g_io_vlan_cur_status.vlan_pkt_num[i] > 0){
			iprintf(ihandle, iconn, "%7d %9llu %10llu\n", i, g_io_vlan_cur_status.vlan_pkt_num[i], g_io_vlan_cur_status.vlan_pkt_byte[i] );
		}
	}

	return 0;
}

static long ifuncb_show_vlan_summary(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	/* 全局总包数, 总字节数 */
	iprintf(ihandle, iconn,"NOTE: unit of byte for total is 'byte', for realtime is 'bps, bit per second'!\n");
	iprintf(ihandle, iconn, "%8s %8s %12s\n", " ", "packet", "byte");
	iprintf(ihandle, iconn, "%8s %8llu %12llu\n%8s %8llu %12llu\n", 
		  "total", g_io_vlan_cur_status.io_base_status.pkt_num, g_io_vlan_cur_status.io_base_status.pkt_byte,
	    	  "realtime", g_io_vlan_realtime_status.io_base_status.pkt_num, g_io_vlan_realtime_status.io_base_status.pkt_byte*8);

	return 0;
}

void iknow_register_vlan_cb(void *ihandle)
{
	int ret;

	ret = iknow_register_cmd(ihandle, "show vlan summary", "display vlan flow summary", ifuncb_show_vlan_summary, NULL, 0, NULL);
//	assert(0 == ret);

	ret = iknow_register_cmd(ihandle, "show vlan id summary", "display vlan flow summary by id", ifuncb_show_vlan_id_summary, NULL, 0, NULL);
//	assert(0 == ret);
}

void packet_io_status_vlan_time_cb(void)
{
	int i, j;
	packet_io_status_vlan_t *global_vlan_status;

 	memcpy((void *)&g_io_vlan_last_status, (void *)&g_io_vlan_cur_status, sizeof(packet_io_status_vlan_t)); /* 保存上一秒的值 */
 	memset((void *)&g_io_vlan_cur_status, 0, sizeof(packet_io_status_vlan_t)); /* 清零 */
	
	for(i = 0; i < g_packet_io_thread_num; i++){
		global_vlan_status = (packet_io_status_vlan_t *)(g_packet_io_status_pool[i]->packet_io_status[IO_STATUS_VLAN]);
		g_io_vlan_cur_status.io_base_status.pkt_num += global_vlan_status->io_base_status.pkt_num;
		g_io_vlan_cur_status.io_base_status.pkt_byte += global_vlan_status->io_base_status.pkt_byte;
		for(j = 0; j < VLAN_ID_MAX; j++){
			g_io_vlan_cur_status.vlan_pkt_num[j] += global_vlan_status->vlan_pkt_num[j];
			g_io_vlan_cur_status.vlan_pkt_byte[j] += global_vlan_status->vlan_pkt_byte[j];
		}
	}

	g_io_vlan_realtime_status.io_base_status.pkt_num = g_io_vlan_cur_status.io_base_status.pkt_num - g_io_vlan_last_status.io_base_status.pkt_num;
	g_io_vlan_realtime_status.io_base_status.pkt_byte = g_io_vlan_cur_status.io_base_status.pkt_byte - g_io_vlan_last_status.io_base_status.pkt_byte;
}

void *packet_io_status_vlan_mem_init(void)
{
	void *vlan_mem;
	
	vlan_mem = malloc(sizeof(packet_io_status_vlan_t));
	memset(vlan_mem, 0, sizeof(packet_io_status_vlan_t));

	return vlan_mem;
}

static inline void packet_io_vlan_status_update(int thread_seq, const struct layer_addr_vlan *addr, int raw_pkt_len)
{
	packet_io_status_vlan_t *io_vlan_status = (packet_io_status_vlan_t *)(g_packet_io_status_pool[thread_seq]->packet_io_status[IO_STATUS_VLAN]);

	io_vlan_status->io_base_status.pkt_num++;
	io_vlan_status->io_base_status.pkt_byte += raw_pkt_len;

	io_vlan_status->vlan_pkt_num[addr->vlan_id]++;
	io_vlan_status->vlan_pkt_byte[addr->vlan_id] += raw_pkt_len;
}
#else
int packet_io_status_vlan_init(void)
{
	return 0;
}
#endif


#ifdef __cplusplus
}
#endif

