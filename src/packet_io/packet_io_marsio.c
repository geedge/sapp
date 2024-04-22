#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include <assert.h>

#include "marsio.h"
#include "mrtunnat.h"
/*
	netconnection_mode:
		1: 多网卡纯收不发 
		2: 一共两块卡, 双进双出
		3: 一共一块卡, 单进单出


	TODO 1:
	    从send_raw_pkt.conf解析的数据存储于G_SND_RAW_PKT_INFO,
	    本模块虽不一定从这些网卡收包, 但肯定会从这些网卡发包, 用于注入数据包给从应用的虚拟网卡,
	    仍然要在初始化时打开这些设备, 创建send_path.
*/
typedef struct{
	int thread_seq; 
	void *send_mbuf_mtod_ptr;
	marsio_buff_t *send_mbuf[1];
	struct mr_vdev *dev_up, *dev_down; /* GDEV模式下, 直接使用dev_up[0]; 同时兼容双网卡串联模式 */
	struct mr_sendpath *sendpath_up, *sendpath_down; /* 并联模式下, 直接使用sendpath_up; 同时兼容双网卡串联模式 */
}marsio4_io_handle;


extern int marsio_buff_get_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data);
extern int marsio_buff_set_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data);
extern int marsio_buff_unset_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type);
/* 
	发包的同时, 给tcpdump_mesa一份, 便于捕包分析,
	回注的包无需tcpdump_mesa捕获, 直接在驱动底层捕获即可.
*/
extern void cycle_pkt_dump_by_classify(int thread_seq, const raw_pkt_t *p_raw_pkt, enum _pkt_classify class_val);
extern int G_PKT_DUMP_SW;


int g_marsio4_version_VERSION_20190907;
int g_marsio4_version_VERSION = 20190907;
static PACKET_IO_CB_T g_marsio4_work_fun;
static int g_marsio4_work_thread_num = 1;
static int g_marsio4_cap_level = CAP_LEVEL_MAC;
static int g_marsio4_topology_mode = NET_CONN_PARALLEL;
static int marsio4_work_thread_seq[MAX_THREAD_NUM];
static pthread_t marsio4_work_tid[MAX_THREAD_NUM];
extern int g_use_MESA_sleep_sw;
struct mr_instance * sapp_marsio4_instance = NULL; /* 暂时对外开放,不能设为static */
static int g_mr4_device_num = 0;
static char **g_mr4_up_device_name; /* 设备名称集合, meth0, meth1, meth2... */
static char **g_mr4_down_device_name; /* 设备名称集合, meth0, meth1, meth2... */
static struct mr_vdev **g_mr4_dev_up_handle_set, **g_mr4_dev_down_handle_set; /* 设备句柄集合 */
static struct mr_sendpath **g_mr4_sendpath_up_set, **g_mr4_sendpath_down_set; /* 发包路径(句柄)集合 */
static marsio4_io_handle *g_mario4_io_handle;
static void *marsio_so_handle;

#define MARSIO_BURST_PKT_MAX		(256)
static int marsio4_burst_process_pkt_num = 32; /* 批处理包数量, 从pag.conf中获取 */
//static long marsio4_thread_bind_mask = 0;
#define TIME_DELAY_MONITOR	(0) /* 单包处理延时监测 */

extern void timestamp_region_update_driver(int tid, long long cpu_cycle);
extern int stream_process_polling(int thread_seq);

/* dlopen funtion pointer */
static int (*ptr_marsio_option_set)(struct mr_instance * instance, marsio_opt_type_t opt_type, void * opt, size_t sz_opt);
static void (*ptr_marsio_send_burst_flush)(struct mr_sendpath * sendpath, queue_id_t sid);
static int (*ptr_marsio_init)(struct mr_instance * instance, const char * appsym);
static struct mr_vdev * (*ptr_marsio_open_device)(struct mr_instance * instance,
    					const char * devsym, unsigned int nr_rxstream, unsigned int nr_txstream);
static void (*ptr_marsio_close_device)(struct mr_vdev *vdev);    					
static struct mr_sendpath * (*ptr_marsio_sendpath_create_by_vdev)(struct mr_vdev * dest_device);    
static void (*ptr_marsio_sendpath_destory)(struct mr_sendpath * sendpath);
static struct mr_instance * (*ptr_marsio_create)(void);
static int (*ptr_marsio_destory)(struct mr_instance *instance);
static int (*ptr_marsio_thread_init)(struct mr_instance * instance);
static int (*ptr_marsio_recv_burst)(struct mr_vdev * vdev, queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs);
int (*ptr_marsio_send_burst)(struct mr_sendpath * sendpath,  queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs);
static int (*ptr_marsio_send_burst_with_options)(struct mr_sendpath * sendpath, queue_id_t sid, marsio_buff_t * mbufs[], int nr_mbufs, uint16_t options);
void (*ptr_marsio_buff_free)(struct mr_instance * instance, marsio_buff_t *marsio_buff[],unsigned int nr_mbufs, int socket_id, int thread_id);
int (*ptr_marsio_buff_malloc_global)(struct mr_instance * instance, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs, int socket_id, int thread_id);
char * (*ptr_marsio_buff_append)(marsio_buff_t *m, uint16_t len);
void * (*ptr_marsio_buff_ctrlzone)(marsio_buff_t *m, uint8_t id);
void (*ptr_marsio_buff_ctrlzone_set)(marsio_buff_t *m, uint8_t id, void* ptr_data, uint8_t size);
void (*ptr_marsio_buff_set_rehash_index)(marsio_buff_t *m, uint32_t hash);
char * (*ptr_marsio_buff_mtod)(marsio_buff_t *m);
uint32_t (*ptr_marsio_buff_datalen)(marsio_buff_t *m);
uint32_t (*ptr_marsio_buff_buflen)(marsio_buff_t *m);
marsio_buff_t * (*ptr_marsio_buff_clone_with_options)(struct mr_instance * instance, marsio_buff_t * md, int socket_id, int thread_id, uint16_t options);
int (*ptr_marsio_buff_get_metadata)(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data);
int (*ptr_marsio_buff_set_metadata)(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data);
int (*ptr_marsio_buff_unset_metadata)(marsio_buff_t *m, enum mr_buff_metadata_type type);
marsio_buff_t *(*ptr_marsio_buff_malloc_smartoffload)(struct mr_vdev *vdev, const char * pkt, unsigned int pkt_len);

int (*ptr_marsio_buff_get_sid_list)(marsio_buff_t * m, uint16_t * out_slist, uint8_t sz_out_slist);
int (*ptr_marsio_buff_set_sid_list)(marsio_buff_t * m, uint16_t * slist, uint8_t sz_slist);
int (*ptr_marsio_buff_append_sid_list)(marsio_buff_t * m, uint16_t * slist, uint8_t sz_slist);
int (*ptr_marsio_buff_prepend_sid_list)(marsio_buff_t * m, uint16_t * slist, uint8_t sz_slist);

void (*ptr_marsio_buff_set_ctrlbuf)(marsio_buff_t * m);
int (*ptr_marsio_poll_wait)(struct mr_instance * instance, struct mr_vdev * vdevs[], unsigned int nr_vdevs, unsigned int tid, int timeout);

int (*ptr_marsio_buff_is_ctrlbuf)(marsio_buff_t * m);

static struct bpf_program MARSIO_BPF_FILTER[MAX_THREAD_NUM];
static int g_marsio_have_bpf;

struct __marsio_bpf_counter_t
{
	long  count;
} __attribute__((aligned(64))); /*   for multi-thread, must 64byte alignment */
struct __marsio_bpf_counter_t g_marsio_bpf_counter[MAX_THREAD_NUM]; 

/************************  funcitons for dynamic link *************************/

int marsio_dl_io_set_cap_level(int cap_level)
{
	g_marsio4_cap_level = cap_level;
	
	return 0;
}

int marsio_dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode;
	return 0;
}

int marsio_dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_GDEV:
		case NET_CONN_SERIAL_2CARD:
			g_marsio4_topology_mode = topology_mode;
		break;


		default:
			printf("\033[1;31;40m[Error]Invalid net_connection_mode!\033[0m\n");
			return -1;
	}

	return 0;
}

int marsio_dl_io_set_capdev_parallel(const char *cap_dev)
{
	char *save_ptr, *tmp_cap_dev_name;
	const char *delim = ", ";
	char cfg_name_from_conf[1024]; 
	char *single_device;
	
	 /* marsio4模式捕包网卡可能有多个, 复用原有的pcapdevice配置, 靠逗号分隔 */
	if(NULL == cap_dev){
		printf("\033[1;31;40m[Error]Invalid pcapdevice!\033[0m\n");
		return -1;
	}

	/* marsio模式支持多网卡, 逗号分隔模式 */
	strncpy(cfg_name_from_conf, sapp_global_val->config.packet_io.internal.interface.name, sizeof(cfg_name_from_conf));
	tmp_cap_dev_name = cfg_name_from_conf;

	while((single_device = strtok_r(tmp_cap_dev_name, delim, &save_ptr)) != NULL){
		if(NULL == g_mr4_up_device_name){
			g_mr4_up_device_name = (char **)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID, sizeof(void *) * (g_mr4_device_num + 1));
		}else{
			g_mr4_up_device_name = (char **)sapp_mem_realloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID, g_mr4_up_device_name, sizeof(void *) * (g_mr4_device_num + 1));
		}

		g_mr4_up_device_name[g_mr4_device_num] = sapp_strdup(single_device);

		g_mr4_device_num++;
		tmp_cap_dev_name = NULL;
	}

	return 0;
}

int marsio_dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	char *save_ptr;
	const char *delim = ", ";
	char *tmp_cap_dev_name, *save_mem_ptr;
	char *single_device;
	int local_mr4_serial_device_num = 0;
	
	 /* marsio4模式捕包网卡可能有多个, 复用原有的pcapdevice配置, 靠逗号分隔 */
	if(NULL == down_dev){
		printf("\033[1;31;40m[Error]Invalid pcapdevice!\033[0m\n");
		return -1;
	}

	tmp_cap_dev_name = sapp_strdup(down_dev);
	save_mem_ptr = tmp_cap_dev_name;

	while((single_device = strtok_r(tmp_cap_dev_name, delim, &save_ptr)) != NULL){
		if(NULL == g_mr4_down_device_name){
			g_mr4_down_device_name = (char **)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,sizeof(void *) * (local_mr4_serial_device_num + 1));
		}else{
			g_mr4_down_device_name = (char **)sapp_mem_realloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,g_mr4_down_device_name, sizeof(void *) * (local_mr4_serial_device_num + 1));
		}

		g_mr4_down_device_name[local_mr4_serial_device_num] = sapp_strdup(single_device);

		local_mr4_serial_device_num++;
		tmp_cap_dev_name = NULL;
	}

	if(local_mr4_serial_device_num != g_mr4_device_num){
		printf("\033[1;31;40m[Error]capture device up and down number is not match!\033[0m\n");
		return -1;
	}

	SAPP_GLOBAL_FREE(save_mem_ptr);

	return 0;
}

int marsio_dl_io_set_capture_filter(const char *filter_rule)
{
	memset(&g_marsio_bpf_counter, 0, sizeof(g_marsio_bpf_counter));
	g_marsio_have_bpf=0;

	if(strlen(filter_rule) == 0)return -1;
	int i,j;

	int pcap_link_type = DLT_EN10MB;
	for (i = 0; i < g_packet_io_thread_num; i++)
	{
			if (pcap_compile_nopcap(65535, pcap_link_type, &MARSIO_BPF_FILTER[i], filter_rule, 100, 0) < 0)
			{
				printf("Compile pcap filter '%s' error\n", filter_rule);
					for(j = 0; j <  g_packet_io_thread_num; j++)
					{
						pcap_freecode(&MARSIO_BPF_FILTER[j]);
					}
					return -1;
			}
	}
	g_marsio_have_bpf=1;
	return 0;
}

int marsio_dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* 驱动设置 */
	return 0;
}
	
int marsio_dl_io_set_work_thread_num(int thread_num_max)
{
	g_marsio4_work_thread_num = thread_num_max;
	return 0;
}


long marsio_dl_io_get_app_drop_num(int thread_num)
{
	/* pag模式查看丢包有专用工具, 程序目前不提供此功能 */
	(void)thread_num;
	return 0;
}

long marsio_dl_io_get_lib_drop_num(void)
{
	long total_drop = 0;
	int i;
	for(i = 0; i < g_marsio4_work_thread_num; i++)
	{
		total_drop +=g_marsio_bpf_counter[i].count;
	}
	return total_drop;
}


unsigned char *marsio_dl_io_get_sendbuf(void *phandle, int thread_seq)
{

	marsio4_io_handle *mr4_handle = (marsio4_io_handle *)phandle;
	mr4_handle->send_mbuf_mtod_ptr = malloc(SENDPACKET_PACKET_SIZE);
	return (unsigned char *)mr4_handle->send_mbuf_mtod_ptr;
}

void marsio_dl_io_free_sendbuf(void *phandle, int thread_seq)
{
	marsio4_io_handle *mr4_handle = (marsio4_io_handle *)phandle;
	free(mr4_handle->send_mbuf_mtod_ptr);
	return;
}

/* 2020-10-30 lijia add, in/forward/inject的包给tcpdump_mesa, 用于debug. */
static void marsio_pkt_dump(int thread_seq, const marsio_buff_t *send_mbuf, enum _pkt_classify classify)
{
	raw_pkt_t to_tcpdump_mesa;

	if(0 == G_PKT_DUMP_SW){
		return;
	}	
	
	to_tcpdump_mesa.low_layer_type = ADDR_TYPE_MAC;
	to_tcpdump_mesa.raw_pkt_data = ptr_marsio_buff_mtod((marsio_buff_t *)send_mbuf);
	to_tcpdump_mesa.raw_pkt_len = ptr_marsio_buff_buflen((marsio_buff_t *)send_mbuf);
	cycle_pkt_dump_by_classify(thread_seq, &to_tcpdump_mesa, classify);

}

static void marsio_update_trace_id(const raw_pkt_t *raw_pkt, void *send_pkt_io_reference)
{
	if(ptr_marsio_buff_set_metadata!=NULL && raw_pkt->stream_trace_id>0)
	{
		ptr_marsio_buff_set_metadata((marsio_buff_t *)send_pkt_io_reference, MR_BUFF_SESSION_ID, (void *)&(raw_pkt->stream_trace_id), sizeof(unsigned long));
	}
}

static void marsio_update_sid_list(const raw_pkt_t *raw_pkt, void *send_pkt_io_reference)
{
	if(raw_pkt->append_list && ptr_marsio_buff_append_sid_list!= NULL)
	{
		ptr_marsio_buff_append_sid_list((marsio_buff_t *)send_pkt_io_reference, raw_pkt->append_list->sid_list, raw_pkt->append_list->sz_sidlist);
	}
	if(raw_pkt->prepend_list && ptr_marsio_buff_prepend_sid_list != NULL)
	{
		ptr_marsio_buff_prepend_sid_list((marsio_buff_t *)send_pkt_io_reference, raw_pkt->prepend_list->sid_list, raw_pkt->prepend_list->sz_sidlist);
	}
	return;
}

static void marsio_update_payload_offset(unsigned short offset, void *send_pkt_io_reference)
{
	if(ptr_marsio_buff_set_metadata!=NULL)
	{
		ptr_marsio_buff_set_metadata((marsio_buff_t *)send_pkt_io_reference, MR_BUFF_PAYLOAD_OFFSET, (void *)&(offset), sizeof(unsigned short));
	}
}

int marsio_dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, 
			int thread_seq, unsigned char route_dir, const raw_pkt_t *raw_pkt)
{
	int ret;
	marsio_buff_t *send_mbuf[1];
	char *real_buf;
	uint16_t send_option = MARSIO_SEND_OPT_REHASH;

	ret = ptr_marsio_buff_malloc_global(sapp_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
	if((ret < 0) || (NULL == send_mbuf[0])){
		return -1;
	}
	

	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	real_buf = ptr_marsio_buff_append(send_mbuf[0], datalen);
	if(NULL == real_buf){
		ptr_marsio_buff_free(sapp_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
		return -1;
	}
	
	memcpy(real_buf, data, datalen);

	if(raw_pkt)
	{
		packet_io_hook_sendto(raw_pkt, route_dir, real_buf, (void *)send_mbuf[0]);
	}



	marsio_pkt_dump(thread_seq, send_mbuf[0], PKT_CLASSIFY_INJECT);

	ret = ptr_marsio_send_burst_with_options((struct mr_sendpath *)arg, thread_seq, send_mbuf, 1, send_option);
	if(ret < 0){
		return -1;
	}
	return datalen;
}

int marsio_dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num,const raw_pkt_t *raw_pkt)
{
	int ret;
	//struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)data;
	//在双网卡透明模式(transparent)下, 根据dir选择up or down device发出.
	if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){
		assert((dir >= 0) && (dir <= 1));
		ret = marsio_dl_io_raw_pkt_send(phandle, data, datalen, g_packet_device_alias[dir].dl_io_param, thread_num, dir, raw_pkt);
	}else{
		/* 可支持多块网卡, 原始包从哪收到就从哪出去 */
		ret = marsio_dl_io_raw_pkt_send(phandle, data, datalen, g_mr4_sendpath_up_set[raw_pkt->device_index], thread_num,dir, raw_pkt);
	}
	
	return ret;
}

int marsio_dl_io_smart_offload(int device_index, unsigned char *pkt_ptr, int pkt_len, unsigned char dir, int thread_num)
{
	if(ptr_marsio_buff_malloc_smartoffload!=NULL && ptr_marsio_send_burst_with_options!=NULL)
	{
		/* for all vxlan pkts, create an offload request */
		marsio_buff_t * offload_request_buf = ptr_marsio_buff_malloc_smartoffload(g_mr4_dev_up_handle_set[device_index], (const char *)pkt_ptr, pkt_len);
		if(offload_request_buf==NULL)
		{
			return 0;
		}
		/* inject the offload request */
		ptr_marsio_send_burst_with_options(g_mr4_sendpath_up_set[device_index], thread_num, &offload_request_buf, 1, MARSIO_SEND_OPT_CTRL);
		return 1;
	}
	return 0;
}

static int marsio4_pkt_forward(int tid, struct mr_sendpath * sendpath, marsio_buff_t * mbufs);

int marsio_dl_io_forward_rawpkt(const raw_pkt_t *raw_pkt, int thread_seq)
{
	if(raw_pkt == NULL && (thread_seq < 0 || thread_seq > get_thread_count()))
		return -1;
	int ret = 0;
	if(raw_pkt->io_lib_pkt_reference != NULL)
	{
		marsio_update_trace_id(raw_pkt, (void *)(raw_pkt->io_lib_pkt_reference));
		marsio_update_sid_list(raw_pkt, (void *)(raw_pkt->io_lib_pkt_reference));
		ret = marsio4_pkt_forward(thread_seq, g_mr4_sendpath_up_set[raw_pkt->device_index], (marsio_buff_t *)(raw_pkt->io_lib_pkt_reference));
	}
	return ret;
}

void marsio_dl_io_free_rawpkt(const raw_pkt_t *raw_pkt, int thread_seq)
{
	if(raw_pkt == NULL && (thread_seq < 0 || thread_seq > get_thread_count()))
		return;
	ptr_marsio_buff_free(sapp_marsio4_instance, (marsio_buff_t **)&raw_pkt->io_lib_pkt_reference, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
	return;
}


struct rawpkt_metadata *marsio_dl_io_get1_rawpkt_meta(const raw_pkt_t *raw_pkt, int thread_seq)
{
	struct rawpkt_metadata *meta = NULL;
	int ret = 0;
	if(raw_pkt->io_lib_pkt_reference != NULL)
	{
        if (ptr_marsio_buff_get_sid_list != NULL || ptr_marsio_buff_get_metadata != NULL)
        {
            meta = (struct rawpkt_metadata *)sapp_mem_calloc(SAPP_MEM_DYN_SID_LIST, thread_seq,sizeof(struct rawpkt_metadata));
            if (ptr_marsio_buff_get_metadata)
            {
                        ret = ptr_marsio_buff_get_metadata((marsio_buff_t *)raw_pkt->io_lib_pkt_reference,
                                                           MR_BUFF_ROUTE_CTX, meta->data, MAX_METADATA_LEN);
                        if (ret <= 0)
                        {
                            sapp_mem_free(SAPP_MEM_DYN_SID_LIST, thread_seq,meta);
                            return NULL;
                        }
                        else
                        {
                            meta->sz_data = ret;
                        }
						ret = ptr_marsio_buff_get_metadata((marsio_buff_t *)raw_pkt->io_lib_pkt_reference,
                                MR_BUFF_LINK_ID, &meta->link_id, sizeof(meta->link_id));

            }
            if (ptr_marsio_buff_get_sid_list)
            {
                        ret = ptr_marsio_buff_get_sid_list((marsio_buff_t *)raw_pkt->io_lib_pkt_reference,
                                                           meta->raw_sid_list.sid_list, MAX_SID_NUM);
                        if (ret <= 0)
                        {
                            meta->raw_sid_list.sz_sidlist = 0;
                        }
                        else
                        {
                            meta->raw_sid_list.sz_sidlist = ret;
                        }
            }
            if (meta->sz_data == 0 && meta->raw_sid_list.sz_sidlist == 0)
            {
                        sapp_mem_free(SAPP_MEM_DYN_SID_LIST, thread_seq,meta);
                        meta = NULL;
            }
        }
    }

	return  meta;
}

int marsio_send_ctrl_data(unsigned char *data,int datalen, struct segment_id_list *sids, int thread_seq)
{
	if(data == NULL || datalen <= 0 || sids == NULL) return -1;

	if(!ptr_marsio_buff_free || !ptr_marsio_buff_malloc_global || 
		!ptr_marsio_buff_set_ctrlbuf || !ptr_marsio_buff_set_metadata || 
		!ptr_marsio_buff_set_sid_list || !ptr_marsio_buff_append || !ptr_marsio_send_burst_with_options)return -1;

	int ret;
	marsio_buff_t *send_mbuf[1];
	uint16_t send_option = MARSIO_SEND_OPT_REHASH;
	ret = ptr_marsio_buff_malloc_global(sapp_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
	if((ret < 0) || (NULL == send_mbuf[0]))return -1;
		
	/* 此处使用append而不是mtod, append内部实际包括了set datalen的操作 */
	char *real_buf = ptr_marsio_buff_append(send_mbuf[0], datalen);
	if(NULL == real_buf){
		ptr_marsio_buff_free(sapp_marsio4_instance, send_mbuf, 1, MARSIO_SOCKET_ID_ANY, thread_seq);
		return -1;
	}
	memcpy(real_buf, data, datalen);
	unsigned long long zero=0;
	ptr_marsio_buff_set_ctrlbuf(send_mbuf[0]);
	ptr_marsio_buff_set_metadata(send_mbuf[0], MR_BUFF_PAYLOAD_OFFSET, (void *)&(zero), sizeof(unsigned short));
	ptr_marsio_buff_set_metadata(send_mbuf[0], MR_BUFF_SESSION_ID, (void *)&(zero), sizeof(unsigned long));
	ptr_marsio_buff_set_sid_list(send_mbuf[0], sids->sid_list, sids->sz_sidlist);

	for(int i = 0; i < g_mr4_device_num; i++)
	{
		marsio_pkt_dump(thread_seq, send_mbuf[0], PKT_CLASSIFY_INJECT);
		ret = ptr_marsio_send_burst_with_options(g_mr4_sendpath_up_set[i], thread_seq, send_mbuf, 1, send_option);
	}
	return ret;
}

void marsio_dl_io_set_rawpkt_meta(const raw_pkt_t *raw_pkt, void *send_pkt_io_reference, unsigned char route_dir)
{
	if(raw_pkt->meta_route_dir[0]== NULL && (raw_pkt->meta_route_dir[1]== NULL))
	{
		return ;
	}
	
	struct rawpkt_metadata *snd_meta = NULL;
	if(raw_pkt->meta_route_dir[route_dir]!=NULL)
	{
		snd_meta=raw_pkt->meta_route_dir[route_dir];
	}
	else // failover 
	{
		snd_meta=raw_pkt->meta_route_dir[route_dir^1];
	}
	if(ptr_marsio_buff_set_metadata)
	{
		ptr_marsio_buff_set_metadata((marsio_buff_t *)send_pkt_io_reference, MR_BUFF_ROUTE_CTX, (void *)snd_meta->data, snd_meta->sz_data);
	}

	marsio_update_trace_id(raw_pkt, send_pkt_io_reference);
	
	if(ptr_marsio_buff_set_sid_list==NULL)
	{
		return ;
	}

	if (raw_pkt->is_ctrl_pkt == 1)
	{
		if (ptr_marsio_buff_set_ctrlbuf != NULL)
		{
			ptr_marsio_buff_set_ctrlbuf(send_pkt_io_reference);
			unsigned short offset = (unsigned short)(ptr_marsio_buff_datalen(send_pkt_io_reference) - raw_pkt->payload_len);
			marsio_update_payload_offset(offset, (void *)send_pkt_io_reference);
		}
		if (raw_pkt->prepend_list)
		{
			ptr_marsio_buff_set_sid_list((marsio_buff_t *)send_pkt_io_reference, raw_pkt->prepend_list->sid_list, raw_pkt->prepend_list->sz_sidlist);
			if (raw_pkt->append_list)
			{
				ptr_marsio_buff_append_sid_list((marsio_buff_t *)send_pkt_io_reference, raw_pkt->append_list->sid_list, raw_pkt->append_list->sz_sidlist);
			}
		}
		else
		{
			if (raw_pkt->append_list)
			{
				ptr_marsio_buff_set_sid_list((marsio_buff_t *)send_pkt_io_reference, raw_pkt->append_list->sid_list, raw_pkt->append_list->sz_sidlist);
			}
		}
	}
	else
	{
		ptr_marsio_buff_set_sid_list((marsio_buff_t *)send_pkt_io_reference, snd_meta->raw_sid_list.sid_list, snd_meta->raw_sid_list.sz_sidlist);
		marsio_update_sid_list(raw_pkt, send_pkt_io_reference);
	}
	return;
}

void marsio_dl_io_free_rawpkt_meta(struct rawpkt_metadata * meta, int thread_seq)
{
	if(meta != NULL)
	{
		sapp_mem_free(SAPP_MEM_DYN_SID_LIST, thread_seq,meta);
		meta=NULL;
	}
	return;
}


void *marsio_dl_io_get_send_handle(int thread_seq)
{
	return (void *)&g_mario4_io_handle[thread_seq];
}


int marsio_dl_io_get_version(void)
{
	return g_marsio4_version_VERSION;
}

int marsio_dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_marsio4_work_fun = fun;
	return 0;
}

int marsio_dl_io_send_only_thread_init(void)
{
	if(sapp_global_val->config.cpu.bind_mask_array_num > 0){
		ptr_marsio_thread_init(sapp_marsio4_instance);
	}

	return 0;
}

#ifndef MAX
#define MAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif
static int tmp_vdevice_num;
static char **tmp_vdevice_name; /* 虚拟设备名称列表, 非pag.conf中的捕包设备, 用于主从应用模式回注 */
static struct mr_sendpath **tmp_vdevice_sendpath;
void * marsio_dl_io_device_alias(unsigned int target_id, char *device_args)
{
	int i;
	int len1, len2;

	len1 = strlen(device_args);

	for(i = 0; i < g_mr4_device_num; i++){
		len2 = strlen(g_mr4_up_device_name[i]);
		/* 使用最长的字符比较, 防止"eth12", "eth1"比较但相等的BUG */
		if(strncasecmp(device_args, g_mr4_up_device_name[i], MAX(len1, len2)) == 0){
			return (void *)g_mr4_sendpath_up_set[i];
		}
	}	

	if(NULL != g_mr4_down_device_name){
		for(i = 0; i < g_mr4_device_num; i++){
			len2 = strlen(g_mr4_down_device_name[i]);
			/* 使用最长的字符比较, 防止"eth12", "eth1"比较但相等的BUG */
			if(strncasecmp(device_args, g_mr4_down_device_name[i], MAX(len1, len2)) == 0){
				return (void *)g_mr4_sendpath_down_set[i];
			}
		}	
	}

	/* 此卡未在pag.conf中注册, 可能是虚拟设备网卡, 现场打开发送句柄 */
	struct mr_vdev *t_vdev;
	struct mr_sendpath *t_sendpath;

	for(i = 0; i < tmp_vdevice_num; i++){
		len2 = strlen(tmp_vdevice_name[i]);
		/* 使用最长的字符比较, 防止"eth12", "eth1"比较但相等的BUG */
		if(strncasecmp(device_args, tmp_vdevice_name[i], MAX(len1, len2)) == 0){
			return (void *)tmp_vdevice_sendpath[i];
		}		
	}
	/* 没找到, 打开设备, 并存储发送句柄 */
	if(0 == tmp_vdevice_num){
		tmp_vdevice_name = (char **)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,sizeof(void *));
		tmp_vdevice_sendpath = (struct mr_sendpath **)sapp_mem_calloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,sizeof(void *));
	}else{
		tmp_vdevice_name = (char **)sapp_mem_realloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,tmp_vdevice_name, sizeof(void *) * (tmp_vdevice_num + 1));
		tmp_vdevice_sendpath = (struct mr_sendpath **)sapp_mem_realloc(SAPP_MEM_FIX_GLOBAL_VAL, MEM_STAT_GLOBAL_THREAD_ID,tmp_vdevice_sendpath, sizeof(void *) * (tmp_vdevice_num + 1));
	}
	tmp_vdevice_name[tmp_vdevice_num] = sapp_strdup(device_args);
	
	t_vdev = ptr_marsio_open_device(sapp_marsio4_instance, device_args, 
								0, 
								g_marsio4_work_thread_num);	
	if(NULL == t_vdev){
		printf("\033[41m[Error]Can't open device '%s'!\033[0m\n", device_args);
		return NULL;
	}
	t_sendpath = ptr_marsio_sendpath_create_by_vdev(t_vdev);
	tmp_vdevice_sendpath[tmp_vdevice_num] = t_sendpath;
	tmp_vdevice_num++; /* 最后更新计算器 */
	
	return t_sendpath;
}

/************************  funcitons for dynamic link *************************/

/*
	计算一个整型数包含了多少个bit是1的.
*/
static inline int calc_integer_bit_num(unsigned long long num)
{
	int i = 0;
	int bit_num = 0;
	
	for(i = 0; i < (int)sizeof(long long) * 8; i++){
		if(num & 1){
			bit_num++;
		}
		num = num >> 1;
		if(0 == num){ /* num已经是0了, 就没必要再判断后续bit位了 */
			break;
		}
	}

	return bit_num;
}

static int marsio4_pkt_forward_for_gdev_mode(int tid, struct mr_sendpath * sendpath, marsio_buff_t * mbuf)
{
	char tmp_mac[6];
	struct mesa_ethernet_hdr *eth_hdr = (struct mesa_ethernet_hdr *)ptr_marsio_buff_mtod(mbuf);
	
	/* 交换源、目的MAC地址, 再把原始包再注入GDEV */
	memcpy(tmp_mac, eth_hdr->ether_shost, 6);
	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
	memcpy(eth_hdr->ether_dhost, tmp_mac, 6);

	return ptr_marsio_send_burst(sendpath, tid, &mbuf, 1);
}

static int marsio4_pkt_forward(int tid, struct mr_sendpath * sendpath, marsio_buff_t * mbufs)
{
	int ret = 0;

	/* 批量获取, 但考虑特殊情况下, vxlan和其他封装模式混杂使用, 要对每个mbuf判断底层封装模式 */

	/* 20201010 lijia modify, 开启overlay无mrtunnat的模式下, ctrl_zone是空, 默认都回注 */
	/* 20190409 lijia modify, tunnel mode, 非隧道封装的包不能回注 */
	/* vxlan封装内层数据转发不必做任何操作, 直接调用marsio_send_burst, 由marsio驱动负责 */

	marsio_pkt_dump(tid, mbufs, PKT_CLASSIFY_FORWARD);
	ret = ptr_marsio_send_burst(sendpath, tid, &mbufs, 1);
	return ret;
}


static inline int marsio4_pkt_hand(int tid, marsio_buff_t *rx_buff, raw_pkt_t *raw_pkt, unsigned char dir)
{
	int ret;

	raw_pkt->__lib_raw_pkt_data = ptr_marsio_buff_mtod(rx_buff);
	raw_pkt->raw_pkt_data = raw_pkt->__lib_raw_pkt_data;
	raw_pkt->__lib_raw_pkt_len = ptr_marsio_buff_datalen(rx_buff);
	raw_pkt->raw_pkt_len = raw_pkt->__lib_raw_pkt_len;
	raw_pkt->io_lib_pkt_reference = rx_buff;
	if(ptr_marsio_buff_is_ctrlbuf)
	{
		raw_pkt->is_ctrl_pkt=ptr_marsio_buff_is_ctrlbuf(rx_buff);
	}
	else
	{
		raw_pkt->is_ctrl_pkt=0;
	}
	/* 双臂模式dir根据网卡internal, external决定, 
	   inline模式此时的dir无意义, 最终会在 packet_io_hook_input_vxlan() ,通过vxlan header更新routedir .
	*/
	raw_pkt->route_dir = dir;

	if(unlikely(g_marsio_have_bpf == 1))
	{
		if (0 == bpf_filter(MARSIO_BPF_FILTER[tid].bf_insns,
							(const unsigned char *)raw_pkt->raw_pkt_data,
							raw_pkt->raw_pkt_len, raw_pkt->raw_pkt_len))
		{
			g_marsio_bpf_counter[tid].count++;
			return PASS;
		}
	}

	if (OVERLAY_MODE_NF == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin)
	{
		raw_pkt->is_overlay_pkt = 1;
	}
	else
	{
		raw_pkt->is_overlay_pkt = 0; /* 无mrtunnat时, 刚收到包还不确定, 靠packet_io_hook决定是否是overlay的包 */
	}

	/* clear pkt status */
	raw_pkt->diagnose_error_to_dump = 0;
	raw_pkt->vlan_flipping_couple[0] = 0;
	raw_pkt->vlan_flipping_couple[1] = 0;
	raw_pkt->overlay_layer_bytes = 0;
	raw_pkt->drop_current_pkt_flag = 0;
	raw_pkt->d_pkt = NULL;
	raw_pkt->payload_len=0;
	raw_pkt->stream_trace_id=0;
	raw_pkt->prepend_list=NULL;
	raw_pkt->append_list=NULL;
	raw_pkt->meta_route_dir[0]=NULL;
	raw_pkt->meta_route_dir[1]=NULL;

	ret = (*g_marsio4_work_fun)((const raw_pkt_t *)raw_pkt, dir, tid);
	
	return ret;
}

static int marsio4_process_packet(int tid, raw_pkt_t *raw_pkt)
{
	int i,j,k, pkt_num = 0;
	marsio_buff_t * rx_buff[MARSIO_BURST_PKT_MAX]; /* 多个设备之间是串行获取, 太少则性能低, 太多则相对延时高 */
	int rcv_res, hand_res;

	if((__NET_CONN_PARALLEL & g_marsio4_topology_mode) != 0){
		for(i = 0; i < g_mr4_device_num; i++){
			rcv_res = ptr_marsio_recv_burst(g_mr4_dev_up_handle_set[i], tid, rx_buff, marsio4_burst_process_pkt_num);
			if(rcv_res > 0){
				raw_pkt->device_index = i;
				__builtin_prefetch(ptr_marsio_buff_mtod(rx_buff[0]));

				for(j = 0, k = 1; j < rcv_res; j++, k++){
					if(k < rcv_res) {
						__builtin_prefetch(ptr_marsio_buff_mtod(rx_buff[k]));
					}
					
					marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_UP); /* 并联模式不关心返回值 */
				}
				pkt_num += rcv_res;
				ptr_marsio_buff_free(sapp_marsio4_instance, rx_buff, rcv_res, MARSIO_SOCKET_ID_ANY, tid); /* 并联不涉及发送, 调用完业务插件后批量free */
			}
		}
	}else if(NET_CONN_SERIAL_GDEV == g_marsio4_topology_mode){
		for(i = 0; i < g_mr4_device_num; i++){
			rcv_res = ptr_marsio_recv_burst(g_mr4_dev_up_handle_set[i], tid, rx_buff, 16);
			if(rcv_res > 0){
				raw_pkt->device_index = i;
				__builtin_prefetch((rx_buff[0]));
				__builtin_prefetch(((char *)(rx_buff[0])+128));
				
				for(j = 0, k = 1; j < rcv_res; j++, k++)
				{
					if(k < rcv_res)
					{
						__builtin_prefetch((rx_buff[k]));
						__builtin_prefetch(((char *)(rx_buff[k])+128));
					}
					hand_res = marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_UP); /* 在marsio4_pkt_hand()更新dir */
                    if ((g_marsio4_topology_mode & __NET_CONN_SERIAL) && (PASS == hand_res))
                    {
                        /* NOTE:
                            MARSIO主从模式独特性, 从虚拟网卡收包, 但要通过物理网卡回注包,
                        */
					   	marsio_update_sid_list(raw_pkt, (void *)rx_buff[j]);
						marsio_update_trace_id(raw_pkt, (void *)rx_buff[j]);
                        int ret = marsio4_pkt_forward(tid, g_mr4_sendpath_up_set[i], rx_buff[j]);
                        if (ret < 0)
                        {
                            ptr_marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
                        }
                    }
                    else if (hand_res == DROP)
                    {
                        /* 串联模式下只能单包free, 有可能batch收的N各包里, 某个包需要回注, 某个包不需要 */
                        ptr_marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
                    }
                    else
                    ;
                }
				pkt_num += rcv_res;
			}
		}
	}else if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){
		for(i = 0; i < g_mr4_device_num; i++){
			rcv_res = ptr_marsio_recv_burst(g_mr4_dev_up_handle_set[i], tid, rx_buff, marsio4_burst_process_pkt_num);
			if(rcv_res > 0){
				for(j = 0; j < rcv_res; j++){
					hand_res = marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_UP);
					if((g_marsio4_topology_mode & __NET_CONN_SERIAL) && (PASS == hand_res)){
						//marsio4_pkt_forward(tid, rx_buff[j]);
						ptr_marsio_send_burst(g_mr4_sendpath_down_set[i], tid, &rx_buff[j], 1);
					}else{
						/* 串联模式下单包free, 有可能需要回注/发送 */
						ptr_marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
					}
				}
				pkt_num += rcv_res;
			}
			rcv_res = ptr_marsio_recv_burst(g_mr4_dev_down_handle_set[i], tid, rx_buff, marsio4_burst_process_pkt_num);
			if(rcv_res > 0){
				for(j = 0; j < rcv_res; j++){
					hand_res = marsio4_pkt_hand(tid, rx_buff[j], raw_pkt, DIR_ROUTE_DOWN);
					if((g_marsio4_topology_mode & __NET_CONN_SERIAL) && (PASS == hand_res)){
						//marsio4_pkt_forward(tid, rx_buff[j]);
						ptr_marsio_send_burst(g_mr4_sendpath_up_set[i], tid, &rx_buff[j], 1);
					}else{
						/* 串联模式下单包free, 有可能需要回注/发送 */
						ptr_marsio_buff_free(sapp_marsio4_instance, &rx_buff[j], 1, MARSIO_SOCKET_ID_ANY, tid);
					}
				}
				pkt_num += rcv_res;
			}
		}
	}
	
	return pkt_num;
}

static int marsio4_sleep_time_table[100] = 
{
	 5,  5,   5,   5,   5,   3,   3,   3,   3,   3,     
	 2,  2,   2,   2,   2,    1,   1,  1,   1,    1, 
	 1,  1,   1,   1,   1,    1,   1,  1,   1,    1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 1,   1,   1,   1,   1,   1,   1,   1,   1,   1, 
	 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  	
	 0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  	 
};

static inline void marsio4_sleep(int tid, int work_percent)
{
	if(work_percent > 100 || work_percent < 0)
	{
		return;
	}
	
	//if ((marsio4_sleep_time_table[(int)work_percent] > 0) && (work_percent < 100))
	{
		if (ptr_marsio_poll_wait != NULL)
		{
			ptr_marsio_poll_wait(sapp_marsio4_instance, g_mr4_dev_up_handle_set, g_mr4_device_num, tid, 900); // sapp内部定时器最小精度为秒，此处设置超时为为900毫秒，用于多进程模式下让出CPU时间
		}
		else
		{
			sapp_usleep(marsio4_sleep_time_table[(int)work_percent]);
		}
	}
	return;
}

/* 高性能模式下, marsio队列有缓存, 无新包到来时需要定期刷新队列中的数据 */
static inline void marsio4_flush_queue_buf(int tid)
{
	int i;

	if(NULL == ptr_marsio_send_burst_flush){
		return;
	}

	for(i = 0; i < g_mr4_device_num; i++){
		ptr_marsio_send_burst_flush(g_mr4_sendpath_up_set[i], tid);
		
		if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){		
			ptr_marsio_send_burst_flush(g_mr4_sendpath_down_set[i], tid);
		}
	}
}
extern int g_PollingFunNum;
extern void sapp_fs2_set_work_percent(int thead_seq, long long work_percent);
static void *marsio4_worker(void *arg)
{
	int tseq = *((int *)arg);
	raw_pkt_t raw_pkt;
	int total_call_times = 0, rcv_pkt_tims = 0, polling_work_times = 0;
	float work_percent;
	int sleep_check_interval = sapp_global_val->config.packet_io.polling_priority;
	int work_percent_threshold = sapp_global_val->config.packet_io.work_percent;
	char  thread_name[32] = "";
	sprintf(thread_name, "sapp_marsio_%d", tseq);
	prctl(PR_SET_NAME, thread_name);

	if(sapp_global_val->config.cpu.bind_mask_array_num > 0){
		ptr_marsio_thread_init(sapp_marsio4_instance);
		sapp_global_val->individual_fixed.cpu_bind_core_id_per_thread[tseq] = get_current_thread_cpu_affinity_id();	
	}
	sapp_global_val->individual_fixed.thread_tid[tseq] = syscall(SYS_gettid);
	
	sapp_runtime_log(RLOG_LV_FATAL, "pid:%d, thread_index:%d, TID(LWP):%ld, PSR:%d", 
					getpid(),  tseq, 
					sapp_global_val->individual_fixed.thread_tid[tseq],
					sapp_global_val->individual_fixed.cpu_bind_core_id_per_thread[tseq]);
					
	memset(&raw_pkt, 0, sizeof(raw_pkt_t));

	/* 固定不变的参数预先设置 */
	raw_pkt.low_layer_type = (enum addr_type_t)g_marsio4_cap_level;
	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	raw_pkt.offset_to_raw_pkt_hdr = 0;

	while(SAPP_STATE_PROCESSING != sapp_get_current_state())
	{
		sapp_usleep(1000);
	}

	/* for perf optimize
	   频繁调用stream_process_polling()等函数, 此处先在函数外部判断一下是否需要调用.
	*/
	int polling_enabled = sapp_global_val->config.packet_io.polling_priority;
	int infinite_loop_enabled = sapp_global_val->config.packet_io.infinite_loop_enabled;
	int polling_timeout_ret=POLLING_STATE_WORK;
	while(SAPP_STATE_PROCESSING == sapp_global_val->individual_volatile->current_state)
	{	
		if(marsio4_process_packet(tseq, &raw_pkt) > 0)
		{
			rcv_pkt_tims++;
		}else{
			marsio4_flush_queue_buf(tseq);
			/* 无包时要调用polling接口 */
			if (likely(polling_enabled))
			{
				if ((g_PollingFunNum > 0))
				{
					if ((stream_process_polling(tseq) & POLLING_STATE_WORK) != 0)
					{
						polling_work_times++;
					}
				}
				if (polling_timeout_ret & POLLING_STATE_WORK)
				{
					polling_timeout_ret=polling_stream_timeout(tseq);
					if ((polling_timeout_ret&POLLING_STATE_WORK))
					{
						polling_work_times++;
					}
				}
			}
		}

		sapp_global_val->mthread_volatile[tseq]->sys_stat.count[SAPP_STAT_FETCH_PKT]++;
		total_call_times++;

		if((rcv_pkt_tims % sleep_check_interval) == 0 && polling_enabled)
		{
			/* 如果流量巨大, 一直有包时, 每隔sleep_check_interval次调用也要调用polling接口 */
			if(g_PollingFunNum > 0)
			{
				if((stream_process_polling(tseq) & POLLING_STATE_WORK) != 0)
				{
					polling_work_times++;
				}
			}
			total_call_times++;
		}
		
		if(total_call_times >= sleep_check_interval)
		{
			if(likely(infinite_loop_enabled == 0))
			{
				work_percent = ((float)(rcv_pkt_tims + polling_work_times )/(float)total_call_times) * 100.0;
				sapp_fs2_set_work_percent(tseq, (long long)work_percent);
				if((int)work_percent < work_percent_threshold)
				{
					marsio4_sleep(tseq, work_percent);
				}
			}
			total_call_times = 0;
			rcv_pkt_tims = 0;
			polling_work_times = 0;
			polling_timeout_ret=POLLING_STATE_WORK;
		}
	}
	return NULL;
}

static void fake_marsio_buff_set_rehash_index(marsio_buff_t *m, uint32_t hash)
{
	return ;
}

static int marsio_dl_get_function_entry(void)
{
	marsio_so_handle = dlopen(ABBR_MARSIO_LIBRARY_FILE, RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
	if(NULL == marsio_so_handle){
		printf("\033[1;31;40m[Error]dlopen '%s' failed, %s\033[0m\n", ABBR_MARSIO_LIBRARY_FILE, dlerror());
		return -1;
	}

	ptr_marsio_option_set = (int (*)(struct mr_instance * instance, marsio_opt_type_t opt_type, void * opt, size_t sz_opt))dlsym(marsio_so_handle, "marsio_option_set");
	if(NULL == ptr_marsio_option_set){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_option_set", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_create = (struct mr_instance * (*)(void))dlsym(marsio_so_handle, "marsio_create");
	if(NULL == ptr_marsio_create){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_create", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_close_device = (void (*)(struct mr_vdev *vdev))dlsym(marsio_so_handle, "marsio_close_device");
	if(NULL == ptr_marsio_close_device){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_close_device", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_init = (int (*)(struct mr_instance * instance, const char * appsym))dlsym(marsio_so_handle, "marsio_init");
	if(NULL == ptr_marsio_init){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_init", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_open_device = (struct mr_vdev * (*)(struct mr_instance * instance, const char * devsym, unsigned int nr_rxstream, unsigned int nr_txstream))dlsym(marsio_so_handle, "marsio_open_device");
	if(NULL == ptr_marsio_open_device){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_open_device", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_sendpath_create_by_vdev = (struct mr_sendpath * (*)(struct mr_vdev * dest_device))dlsym(marsio_so_handle, "marsio_sendpath_create_by_vdev");
	if(NULL == ptr_marsio_sendpath_create_by_vdev){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_sendpath_create_by_vdev", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_sendpath_destory = (void (*)(struct mr_sendpath * sendpath))dlsym(marsio_so_handle, "marsio_sendpath_destory");
	if(NULL == ptr_marsio_sendpath_create_by_vdev){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_sendpath_destory", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}
	
	ptr_marsio_thread_init = (int (*)(struct mr_instance * instance))dlsym(marsio_so_handle, "marsio_thread_init");
	if(NULL == ptr_marsio_thread_init){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_thread_init", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_recv_burst = (int (*)(struct mr_vdev * vdev, queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs))dlsym(marsio_so_handle, "marsio_recv_burst");
	if(NULL == ptr_marsio_recv_burst){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_recv_burst", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_send_burst = (int (*)(struct mr_sendpath * sendpath,  queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs))dlsym(marsio_so_handle, "marsio_send_burst");
	if(NULL == ptr_marsio_send_burst){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_send_burst", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_send_burst_with_options = (int (*)(struct mr_sendpath * sendpath, queue_id_t sid, marsio_buff_t * mbufs[], int nr_mbufs, uint16_t options))dlsym(marsio_so_handle, "marsio_send_burst_with_options");
	if(NULL == ptr_marsio_send_burst_with_options){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_send_burst_with_options", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_free = (void (*)(struct mr_instance * instance, marsio_buff_t *marsio_buff[],unsigned int nr_mbufs, int socket_id, int thread_id))dlsym(marsio_so_handle, "marsio_buff_free");
	if(NULL == ptr_marsio_buff_free){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_free", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_malloc_global = (int (*)(struct mr_instance * instance, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs, int socket_id, int thread_id))dlsym(marsio_so_handle, "marsio_buff_malloc_global");
	if(NULL == ptr_marsio_buff_malloc_global){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_malloc_global", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_append = (char * (*)(marsio_buff_t *m, uint16_t len))dlsym(marsio_so_handle, "marsio_buff_append");
	if(NULL == ptr_marsio_buff_append){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_append", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_ctrlzone = (void * (*)(marsio_buff_t *m, uint8_t id))dlsym(marsio_so_handle, "marsio_buff_ctrlzone");
	if(NULL == ptr_marsio_buff_ctrlzone){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_ctrlzone", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_ctrlzone_set = (void (*)(marsio_buff_t *m, uint8_t id, void* ptr_data, uint8_t size))dlsym(marsio_so_handle, "marsio_buff_ctrlzone_set");
	if(NULL == ptr_marsio_buff_ctrlzone_set){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_ctrlzone_set", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_set_rehash_index = (void (*)(marsio_buff_t *m, uint32_t hash))dlsym(marsio_so_handle, "marsio_buff_set_rehash_index");
	if(NULL == ptr_marsio_buff_set_rehash_index){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_set_rehash_index", ABBR_MARSIO_LIBRARY_FILE);
		ptr_marsio_buff_set_rehash_index = fake_marsio_buff_set_rehash_index;
		//return -1;
	}

	ptr_marsio_buff_mtod = (char * (*)(marsio_buff_t *m))dlsym(marsio_so_handle, "marsio_buff_mtod");
	if(NULL == ptr_marsio_buff_mtod){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_mtod", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_datalen = (uint32_t (*)(marsio_buff_t *m))dlsym(marsio_so_handle, "marsio_buff_datalen");
	if(NULL == ptr_marsio_buff_datalen){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_datalen", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_buflen = (uint32_t (*)(marsio_buff_t *m))dlsym(marsio_so_handle, "marsio_buff_buflen");
	if(NULL == ptr_marsio_buff_buflen){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_buflen", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	ptr_marsio_buff_clone_with_options = (marsio_buff_t * (*)(struct mr_instance * instance, marsio_buff_t * md, int socket_id, int thread_id, uint16_t options))dlsym(marsio_so_handle, "marsio_buff_clone_with_options");
	if(NULL == ptr_marsio_buff_clone_with_options){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_clone_with_options", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}

	/*************   note: 没有marsio_send_burst_flush()函数不算错误, 向后兼容! *****************/
	ptr_marsio_send_burst_flush = (void (*)(struct mr_sendpath * sendpath, queue_id_t sid))dlsym(marsio_so_handle, "marsio_send_burst_flush");
	if(NULL == ptr_marsio_send_burst_flush){
		printf("\033[33m[Warning]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_send_burst_flush", ABBR_MARSIO_LIBRARY_FILE);
		//go on
	}

	ptr_marsio_buff_malloc_smartoffload = (marsio_buff_t * (*)(struct mr_vdev *vdev, const char *pkt, unsigned int pkt_len))dlsym(marsio_so_handle, "marsio_buff_malloc_smartoffload");
	if(NULL == ptr_marsio_buff_malloc_smartoffload){
		printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_malloc_smartoffload", ABBR_MARSIO_LIBRARY_FILE);
		sleep(1);
	}

	/* for vlan flipping */
	if(DEPLOYMENT_MODE_INLINE == sapp_global_val->config.packet_io.deployment_mode_bin){
		ptr_marsio_buff_get_metadata = (int (*)(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data))dlsym(marsio_so_handle, "marsio_buff_get_metadata");
		if(NULL == ptr_marsio_buff_get_metadata){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_get_metadata", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误*/
			sleep(1);
		}

		ptr_marsio_buff_set_metadata = (int (*)(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data))dlsym(marsio_so_handle, "marsio_buff_set_metadata");
		if(NULL == ptr_marsio_buff_set_metadata){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_set_metadata", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误*/
			sleep(1);
		}

		ptr_marsio_buff_get_sid_list = (int (*)(marsio_buff_t *m, uint16_t * out_slist, uint8_t sz_out_slist))dlsym(marsio_so_handle, "marsio_buff_get_sid_list");
		if(NULL == ptr_marsio_buff_set_metadata){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_get_sid_list", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误*/
			sleep(1);
		}
		ptr_marsio_buff_set_sid_list = (int (*)(marsio_buff_t *m, uint16_t * slist, uint8_t sz_slist))dlsym(marsio_so_handle, "marsio_buff_set_sid_list");
		if(NULL == ptr_marsio_buff_set_metadata){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_set_sid_list", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误*/
			sleep(1);
		}

		ptr_marsio_buff_append_sid_list = (int (*)(marsio_buff_t *m, uint16_t * slist, uint8_t sz_slist))dlsym(marsio_so_handle, "marsio_buff_append_sid_list");
		if(NULL == ptr_marsio_buff_append_sid_list){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_append_sid_list", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误 */
			sleep(1);
		}

		ptr_marsio_buff_prepend_sid_list = (int (*)(marsio_buff_t *m, uint16_t * slist, uint8_t sz_slist))dlsym(marsio_so_handle, "marsio_buff_prepend_sid_list");
		if(NULL == ptr_marsio_buff_prepend_sid_list){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_prepend_sid_list", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误*/
			sleep(1);
		}

		ptr_marsio_buff_unset_metadata = (int (*)(marsio_buff_t *m, enum mr_buff_metadata_type type))dlsym(marsio_so_handle, "marsio_buff_unset_metadata");
		if(NULL == ptr_marsio_buff_unset_metadata){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_unset_metadata", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误*/
			sleep(1);
		}

		ptr_marsio_buff_set_ctrlbuf = (void (*)(marsio_buff_t *m))dlsym(marsio_so_handle, "marsio_buff_set_ctrlbuf");
		if(NULL == ptr_marsio_buff_set_ctrlbuf){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_set_ctrlbuf", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误*/
			sleep(1);
		}
		ptr_marsio_poll_wait = (int (*)(struct mr_instance * instance, struct mr_vdev * vdevs[], unsigned int nr_vdevs, unsigned int tid, int timeout))dlsym(marsio_so_handle, "marsio_poll_wait");
		if(NULL == ptr_marsio_poll_wait){
			printf("\033[33m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_poll_wait", ABBR_MARSIO_LIBRARY_FILE);
			//return -1; /* 为了向前兼容mrzcpd旧版, 此处先不返回错误 */
			sleep(1);
		}
		ptr_marsio_buff_is_ctrlbuf = (int(*)(marsio_buff_t * m))dlsym(marsio_so_handle, "marsio_buff_is_ctrlbuf");
		if (NULL == ptr_marsio_buff_ctrlzone)
		{
			printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_buff_is_ctrlbuf", ABBR_MARSIO_LIBRARY_FILE);
			return -1;
		}
	}

	ptr_marsio_destory = (int (*)(struct mr_instance *instance))dlsym(marsio_so_handle, "marsio_destory");
	if(NULL == ptr_marsio_destory){
		printf("\033[1;31;40m[Error]dlsym function '%s' from '%s' failed!\033[0m\n", "marsio_destory", ABBR_MARSIO_LIBRARY_FILE);
		return -1;
	}
	
	return 0;
}

int marsio_send_burst_with_options_for_tcpdumpmesa(struct mr_sendpath * sendpath, queue_id_t sid, marsio_buff_t * mbufs[],
    int nr_mbufs, uint16_t options)
{
	raw_pkt_t rawpkt;
	char *rawpkt_data;
	uint32_t rawpkt_len;

	if(G_PKT_DUMP_SW != 0){
		rawpkt_data = ptr_marsio_buff_mtod(mbufs[0]);
		rawpkt_len = ptr_marsio_buff_buflen(mbufs[0]);
		rawpkt.magic_num = RAW_PKT_MAGIC_NUM;
		rawpkt.low_layer_type = ADDR_TYPE_MAC;
		rawpkt.raw_pkt_data = rawpkt_data;
		rawpkt.raw_pkt_len = rawpkt_len;
		rawpkt.__lib_raw_pkt_data = rawpkt_data;
		rawpkt.__lib_raw_pkt_len = rawpkt_len;

		cycle_pkt_dump_by_classify(sid, &rawpkt, PKT_CLASSIFY_INJECT);
	}

	return ptr_marsio_send_burst_with_options(sendpath, sid, mbufs, nr_mbufs, options);	
}


unsigned int marsio_get_vlan_id_from_mbuff(void *pkt_reference)
{
	unsigned int vlan_id = 0;
	
	if(ptr_marsio_buff_get_metadata){
		ptr_marsio_buff_get_metadata((marsio_buff_t *)pkt_reference, MR_BUFF_METADATA_VLAN_TCI, &vlan_id, sizeof(int));
	}
	
	return vlan_id;
}

int marsio_get_route_dir_from_mbuff(void *pkt_reference)
{
	int dir = -1;
	
	if(ptr_marsio_buff_get_metadata && pkt_reference){
		ptr_marsio_buff_get_metadata((marsio_buff_t *)pkt_reference, MR_BUFF_DIR, &dir, sizeof(int));
	}
	
	return dir;
}

int marsio_get_link_id_from_mbuff(void *pkt_reference)
{
	int link_id = -1;
	
	if(ptr_marsio_buff_get_metadata && pkt_reference){
		ptr_marsio_buff_get_metadata((marsio_buff_t *)pkt_reference, MR_BUFF_LINK_ID, &link_id, sizeof(int));
	}
	
	return link_id;
}

int marsio_set_vlan_id_to_mbuff(void *pkt_reference, unsigned int vlan_id_host_order)
{
	int ret = 0;
	if(ptr_marsio_buff_set_metadata){
		ret = ptr_marsio_buff_set_metadata((marsio_buff_t *)pkt_reference, MR_BUFF_METADATA_VLAN_TCI, &vlan_id_host_order, sizeof(int));
	}

	return ret;
}

#include <sched.h>

int marsio_dl_io_init(int argc, char *argv[])
{
	int i, ret;
	//char app_name[32];
	int max_send_queue_num;

	if(marsio_dl_get_function_entry() < 0){
		printf("\033[1;31;40m[Error]dlopen marsio.so symbol failed!\033[0m\n");
		return -1;
	}

	sapp_marsio4_instance = ptr_marsio_create();
	if(NULL == sapp_marsio4_instance) {
		fprintf(stderr,"%s\n","marsio_create error!\n");
		return -1;
	}

	if(NET_CONN_SERIAL_GDEV == g_marsio4_topology_mode){
		if(g_mr4_device_num != 1){
			printf("\033[1;31;40m[Error] in inline mode, capture device num is %d!\033[0m\n", g_mr4_device_num);			
			return -1;
		}
	}else if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){
		if(g_mr4_device_num != 1){
			printf("\033[1;31;40m[Error] in transparent mode, capture device num is %d!\033[0m\n", g_mr4_device_num);			
			return -1;
		}
	}

	g_mario4_io_handle = (marsio4_io_handle *)SAPP_GLOBAL_ALLOC(sizeof(marsio4_io_handle) * g_marsio4_work_thread_num);
	ptr_marsio_option_set(sapp_marsio4_instance, MARSIO_OPT_THREAD_NUM, &g_marsio4_work_thread_num, sizeof(int));

	if(sapp_global_val->config.cpu.bind_mask_array_num > 0){
		cpu_set_t cpu_mask;
		CPU_ZERO(&cpu_mask);
		for (i = 0; i < sapp_global_val->config.cpu.bind_mask_array_num; i++)
		{
			CPU_SET(sapp_global_val->config.cpu.bind_mask_array[i], &cpu_mask);
		}
		ret = ptr_marsio_option_set(sapp_marsio4_instance, MARSIO_OPT_THREAD_MASK_IN_CPUSET, &cpu_mask, sizeof(cpu_mask));
		if (ret < 0)
		{
			printf("\033[1;31;40m[Error] marsio set CPU->bind_mask failed!\033[0m\n");
			return -1;
		}
	}

	ptr_marsio_init(sapp_marsio4_instance, sapp_global_val->config.system.instance_name);

	g_mr4_dev_up_handle_set = (struct mr_vdev **)SAPP_GLOBAL_ALLOC(sizeof(void *) * g_mr4_device_num);
	g_mr4_dev_down_handle_set = (struct mr_vdev **)SAPP_GLOBAL_ALLOC(sizeof(void *) * g_mr4_device_num);	
	g_mr4_sendpath_up_set = (struct mr_sendpath **)SAPP_GLOBAL_ALLOC(sizeof(void *) * g_mr4_device_num);	
	g_mr4_sendpath_down_set = (struct mr_sendpath **)SAPP_GLOBAL_ALLOC(sizeof(void *) * g_mr4_device_num);	

	max_send_queue_num = sapp_global_val->config.cpu.worker_threads + sapp_global_val->config.cpu.send_only_threads_max_num;
	
	for(i = 0; i < g_mr4_device_num; i++){
		g_mr4_dev_up_handle_set[i] = ptr_marsio_open_device(sapp_marsio4_instance, g_mr4_up_device_name[i], 
											g_marsio4_work_thread_num, 
											max_send_queue_num);
		if(NULL == g_mr4_dev_up_handle_set[i]){
			printf("\033[1;31;40m[Error]Open device '%s' error, please check sapp.toml->packet_io.interface!\033[0m\n", 
				g_mr4_up_device_name[i]);
			return -1;
		}
		g_mr4_sendpath_up_set[i] = ptr_marsio_sendpath_create_by_vdev(g_mr4_dev_up_handle_set[i]);
		
		if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){								
			g_mr4_dev_down_handle_set[i] = ptr_marsio_open_device(sapp_marsio4_instance, g_mr4_down_device_name[i], 
												g_marsio4_work_thread_num, 
												max_send_queue_num);
			if(NULL == g_mr4_dev_down_handle_set[i]){
				printf("\033[1;31;40m[Error]Open device '%s' error, please check sapp.toml->packet_io.interface!\033[0m\n", 
					g_mr4_up_device_name[i]);
				return -1;
			}
			g_mr4_sendpath_down_set[i] = ptr_marsio_sendpath_create_by_vdev(g_mr4_dev_down_handle_set[i]);
		}									
	}

	return 0;
}

void marsio_dl_io_run(void)
{
	int i = 0, ret;
	
	for(i = 0; i < g_marsio4_work_thread_num; i++)
	{
		marsio4_work_thread_seq[i] = i;
		ret = pthread_create(&(marsio4_work_tid[i]), NULL, marsio4_worker, (void *) &(marsio4_work_thread_seq[i]));
		assert(0 == ret);
		sapp_global_val->individual_fixed.thread_obtain_id[i] = marsio4_work_tid[i];
	}
}

void marsio_dl_io_destroy(void)
{
	int i;

	for(i = 0; i < g_mr4_device_num; i++){	
		ptr_marsio_close_device(g_mr4_dev_up_handle_set[i]);
		ptr_marsio_sendpath_destory(g_mr4_sendpath_up_set[i]);
		if(NET_CONN_SERIAL_2CARD == g_marsio4_topology_mode){	
			ptr_marsio_close_device(g_mr4_dev_down_handle_set[i]);
			ptr_marsio_sendpath_destory(g_mr4_sendpath_down_set[i]);
		}
	}

	SAPP_GLOBAL_FREE(g_mr4_dev_up_handle_set);
	SAPP_GLOBAL_FREE(g_mr4_sendpath_up_set);
	SAPP_GLOBAL_FREE(g_mr4_dev_down_handle_set);
	SAPP_GLOBAL_FREE(g_mr4_sendpath_down_set);

	SAPP_GLOBAL_FREE(g_mario4_io_handle);
	g_mr4_device_num = 0;

	ptr_marsio_destory(sapp_marsio4_instance);
}


#ifdef __cplusplus
}
#endif


