#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "pfring.h"
#include "pfring_zero.h"

int g_pfring_version_VERSION_20160505; /* 2014-12-01 lijia add */
static int g_pfring_version_VERSION = 20160505;
static int pfring_cluster_id = 0xCCC;
static pfring_dna_cluster *dna_cluster_handle;
static socket_mode pfring_mode = recv_only_mode;
static pfring *pf_dna_handle, *pf_dna_handle2; /* dna_cluster捕获包的硬件物理接口 */
static pfring *pf_thread_handle[MAX_THREAD_NUM]; /* 上层应用从dna_cluster获取包的逻辑接口 */
static int pd_index[MAX_THREAD_NUM];
static pthread_t pd_thread[MAX_THREAD_NUM];
static struct mesa_ethernet_hdr *pfring_raw_pkt_hdr[MAX_THREAD_NUM]; /* 记录原始包头指针, 用于发包获取MAC地址用 */
static unsigned char pfring_raw_pkt_route_dir[MAX_THREAD_NUM]; /* 记录原始包方向, 用于发送数据包 */
static int pfring_if_index_up, pfring_if_index_down;
static int enable_tx = 0;
static u_int cpu_num = 1;
static int pfring_run_flag = 1;
static int rx_bind_core = 1, tx_bind_core = 2; /* core 0 free if possible */

static char g_pfring_up_dev_name[DEV_NAME_STR_LEN];
static char g_pfring_down_dev_name[DEV_NAME_STR_LEN];
static char g_pfring_cap_filter[CAP_FILTER_STR_LEN];
static PACKET_IO_CB_T g_pfring_work_fun;
static int g_pfring_work_thread_num = 1;
static int g_pfring_cap_level = CAP_LEVEL_MAC;
static int g_pfring_topology_mode = NET_CONN_PARALLEL;
static int pfring_work_thread_seq[MAX_THREAD_NUM];
static pthread_t pfring_work_tid[MAX_THREAD_NUM];

typedef struct{
	struct mesa_ethernet_hdr *pfring_raw_pkt_hdr; /* 记录原始包头指针, 用于发包获取MAC地址用 */
	unsigned char pfring_raw_pkt_route_dir; /* 记录原始包方向, 用于发送数据包 */
	char __pad_for_alignment[55]; /* 整体结构64字节cache对齐 */
}pfring_low_level_send_para_t;

static pfring_low_level_send_para_t pfring_low_level_send_para[MAX_THREAD_NUM];

extern int g_skip_ethernet_layer_sw;
/* signal handler */
#ifndef SIG_HANDLE_T
typedef void(*SIG_HANDLE_T)(int);
#endif

typedef struct{
	int thread_num;
	pfring_pkt_buff *pkt_handle;
}pfring_send_handle;

static void pfring_sig_handle(int signo)
{
	int i;
	switch(signo)
	{
		case SIGINT:
		case SIGTERM:
		case SIGFPE:
			dna_cluster_disable(dna_cluster_handle);

			for(i = 0; i < g_pfring_work_thread_num; i++) 
			{
			    pfring_shutdown(pf_thread_handle[i]);
			}
			
			pfring_run_flag = 0;
		break;

		case SIGPIPE:	
		break;
		
		default:
		break;
	}
	
	return;
}

static int register_sig_handle(int signo, SIG_HANDLE_T fun)
{
    struct sigaction newact;

    /* call the function "fun" when receive a signal of "signum" */
    newact.sa_handler = fun; 
    sigemptyset(&newact.sa_mask);
    newact.sa_flags = 0;
    
    if(sigaction(signo, &newact, NULL) != 0)
    {
        printf("sigaction error!\n");
        return -1;
    }

    return 0;
}

static void pfring_bind_thread_to_cpuid(int thread_id)
{
	cpu_set_t cpuset;
	u_long core_id;
	int res;

	/* Bind this thread to a specific core */
	if(cpu_num > 1) {
		core_id = ((!enable_tx ? rx_bind_core : tx_bind_core) + 1 + thread_id) % cpu_num; 

		CPU_ZERO(&cpuset);
		CPU_SET(core_id, &cpuset);
		res = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
		if (res != 0){
			fprintf(stderr, "Error while binding thread %d to core %ld: errno=%i\n", 
	     			thread_id, core_id, res);
	    } 
	}

	return;
}

#if 0 // to do,  发包模式
void pfring_set_ifindex(sendpacketTool *pTool, u_char dir)
{
	/* 只有双网卡串联模式，才需要设定发送接口ID */
	if(NET_CONN_SERIAL_2CARD == G_NET_CONNECTION_MODE)
	{
		if(0x0 == dir)
		{
			pfring_set_pkt_buff_ifindex(pTool->pf_handle, pTool->pkt_handle, pfring_if_index);
		}
		else
		{
			pfring_set_pkt_buff_ifindex(pTool->pf_handle, pTool->pkt_handle, pfring_if_index2);
		}
	}
	
	return;
}
#endif

/* 转发时，没有显式的获取包长度，可以直接发送，
   如果想使用通用的forwarding_packet()函数，
   最终会调用sendpacket_write_link_layer()，需要每次都设置pfring_set_pkt_buff_len()，
   所以，为了简单高效，又单独写了一个pfring_forwarding_packet()函数.
*/
static void pfring_forwarding_packet(pfring *pf_handle, 
			pfring_pkt_buff *pkt_handle, struct pfring_pkthdr *hdr, u_char *buffer)
{
	char tmp_mac[6];
	struct mesa_ethernet_hdr *eth_hdr;
	
	if(NET_CONN_SERIAL_2CARD == g_pfring_topology_mode) 
	{
		/* 交换网卡ID */
		if(hdr->extended_hdr.if_index == pfring_if_index_up)
		{
			pfring_set_pkt_buff_ifindex(pf_handle, pkt_handle, pfring_if_index_down);
		}
		else
		{
			pfring_set_pkt_buff_ifindex(pf_handle, pkt_handle, pfring_if_index_up);
		}
	}
	else if(NET_CONN_SERIAL_GDEV == g_pfring_topology_mode)
	{
		/* 如果基于特殊设备模式的话，
	       从哪块网卡收的，就从那块网卡发，无需设置发送网卡Index，
	       但需要交换源、目的MAC地址.
	    */
		eth_hdr = (struct mesa_ethernet_hdr *)buffer;
		
		/* 交换源、目的MAC地址，把原始包再注入特殊设备 */
		memcpy(tmp_mac, eth_hdr->ether_shost, 6);
		memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, 6);
		memcpy(eth_hdr->ether_dhost, tmp_mac, 6);
	}

	pfring_send_pkt_buff(pf_handle, pkt_handle, 1);

	return;
}

static int pfring_pkt_hand(unsigned char *data, struct pfring_pkthdr *hdr, int thread_num, raw_pkt_t *raw_pkt)
{
	unsigned char dir;
	int ret = PASS;

	if(unlikely(NET_CONN_SERIAL_2CARD == g_pfring_topology_mode))
	{
		if(hdr->extended_hdr.if_index == pfring_if_index_up){
			dir = IO_DIR_UP; /* 第一块网卡收到的包，方向编号为UP */
		}else{
			dir = IO_DIR_DOWN; /* 第二块网卡收到的包，方向编号为DOWN */
		}
	}
	else
	{
		if(0 == (data[11] & 0x01)){ /* 源MAC的最后一位表示方向 */
			dir = IO_DIR_UP; 
		}else{
			dir = IO_DIR_DOWN;
		}
	}

#if 0	 /* to do */
	if(g_pfring_topology_mode & __NET_CONN_SENPACKET){
		G_PKT_MAC_TABLE[thread_num].rcv_dir = dir; /* 记录本次收包的方向 */
	}

	if(g_pfring_topology_mode & __NET_CONN_LINK_LAYER){
		memcpy(G_PKT_MAC_TABLE[thread_num].src_mac, data+6, 6);
		if(NET_CONN_SERIAL_2CARD == g_pfring_topology_mode){ /* 双网卡串联模式才需要记录目标MAC, 其他模式的目标MAC即本机MAC */
			memcpy(G_PKT_MAC_TABLE[thread_num].dst_mac, data, 6);
		}
	}
#endif

	pfring_low_level_send_para[thread_num].pfring_raw_pkt_route_dir = dir;
	pfring_low_level_send_para[thread_num].pfring_raw_pkt_hdr = (struct mesa_ethernet_hdr *)data;

	raw_pkt->__lib_raw_pkt_data = (const void *)data;
	raw_pkt->raw_pkt_data = (const void *)data;
	raw_pkt->__lib_raw_pkt_len = hdr->len;
	raw_pkt->raw_pkt_len = hdr->len;
	raw_pkt->low_layer_type = (enum addr_type_t)g_pfring_cap_level;
	//memcpy(&(raw_pkt->raw_pkt_ts),  &(hdr->ts), sizeof(struct timeval));

	ret = (*g_pfring_work_fun)((const raw_pkt_t *)raw_pkt, dir, thread_num);
	
	return ret;
}


static void *pfring_worker(void *pd_index)
{
	struct pfring_pkthdr hdr;
	pfring_pkt_buff *pkt_rcv_handle, *pkt_snd_handle;
	int thread_num = *((int *)pd_index);
	pfring *pf_handle = pf_thread_handle[thread_num];
	int rc;
	u_char *buffer;
	raw_pkt_t raw_pkt;

	pfring_bind_thread_to_cpuid(thread_num);

	memset(&hdr, 0, sizeof(hdr));

	if(g_pfring_topology_mode & __NET_CONN_SERIAL){
		pkt_rcv_handle = pfring_alloc_pkt_buff(pf_handle);
		if(NULL == pkt_rcv_handle){
			printf("Error allocating pkt buff\n");
			return NULL;
		}
	}

	if(g_pfring_topology_mode & __NET_CONN_SENPACKET){
		pkt_snd_handle = pfring_alloc_pkt_buff(pf_handle);
		if(NULL == pkt_snd_handle){
			printf("Error allocating pkt buff\n");
			return NULL;
		}

		/* 设置PTOOLS中的发包相关变量 */
#if 0		
		pfring_init_ptools(pf_handle, pkt_snd_handle, thread_num);
#endif		
	}

	memset(&raw_pkt, 0, sizeof(raw_pkt));
	/* 固定不变的值初始化时设定, 避免每个包都赋值一次 */
	raw_pkt.low_layer_type = (enum addr_type_t)g_pfring_cap_level;
	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM; 
	while(pfring_run_flag){
		if(!enable_tx) {
	      		rc = pfring_recv(pf_handle, &buffer, 0, &hdr, 1);
	      		if(rc < 0){
	      			continue;
	      		}
	    	}else{
	    		rc = pfring_recv_pkt_buff(pf_handle, pkt_rcv_handle, &hdr, 1);
	    		if(rc < 0){
					continue;
	    		}
	    		buffer = pfring_get_pkt_buff_data(pf_handle, pkt_rcv_handle);
		}
		
		rc = pfring_pkt_hand(buffer, &hdr, thread_num, &raw_pkt);
		
		if((g_pfring_topology_mode & __NET_CONN_SERIAL) && (PASS == rc))
		{
			pfring_forwarding_packet(pf_handle, pkt_rcv_handle, &hdr, buffer);
		}
	}

	return NULL;
}

static int pfring_init(void)
{
	int ret;
	cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
	
	/* Create the DNA cluster */
	if((dna_cluster_handle = dna_cluster_create(pfring_cluster_id, g_pfring_work_thread_num, 0)) == NULL) {
		printf("PF_RING:Error creating DNA Cluster\n");
		return(-1);
	}

	if(dna_cluster_set_mode(dna_cluster_handle, pfring_mode) < 0) {
		printf("dna_cluster_set_mode error\n");
		return(-1);
	}

	if(g_pfring_topology_mode & __NET_CONN_SENPACKET){
		pfring_mode = send_and_recv_mode;
		enable_tx = 1;
	}

	if (dna_cluster_set_mode(dna_cluster_handle, pfring_mode) < 0) {
		printf("dna_cluster_set_mode error\n");
		goto err_1;
	}

	if(strncasecmp(g_pfring_up_dev_name, "dna", 3) != 0){
		printf("In PF_RING mode, pleuse use 'dnax' as capture device!\n");
		goto err_1;
	}

	pf_dna_handle = pfring_open(g_pfring_up_dev_name, MTU_MAX, PF_RING_PROMISC);
	if(NULL == pf_dna_handle){
		printf("pfring_open %s error [%s]\n", g_pfring_up_dev_name, strerror(errno));
		goto err_1;
	}

	if(g_pfring_cap_filter[0] != '\0'){
		if(NULL == pf_dna_handle->set_bpf_filter){
			printf("Warning, pfring_set_bpf_filter is not support !\n");
		}else{
		ret = pf_dna_handle->set_bpf_filter(pf_dna_handle, g_pfring_cap_filter);
		if(ret < 0){
				printf("pfring_set_bpf_filter '%s' error!\n", g_pfring_cap_filter);
				goto err_1;
			}
		}
	}
	
	if(NET_CONN_SERIAL_2CARD == g_pfring_topology_mode){
		if(strncmp(g_pfring_up_dev_name, g_pfring_down_dev_name, DEV_NAME_STR_LEN) == 0){
			printf("pcapdevice can't same as pcapdevice2!\n");
			goto err_2;
		}
		if(strncasecmp(g_pfring_down_dev_name, "dna", 3) != 0){
			printf("In PF_RING mode, pleuse use 'dnax' as capture device!\n");
			goto err_2;
		}	
		pf_dna_handle2 = pfring_open(g_pfring_down_dev_name, MTU_MAX, PF_RING_PROMISC);
		if(NULL == pf_dna_handle2){
			printf("pfring_open %s error [%s]\n", g_pfring_down_dev_name, strerror(errno));
			goto err_2;
		}
		if(g_pfring_cap_filter[0] != '\0'){
			if(NULL == pf_dna_handle->set_bpf_filter){
				printf("Warning, pfring_set_bpf_filter is not support !\n");
			}else{		
			ret = pf_dna_handle2->set_bpf_filter(pf_dna_handle2, g_pfring_cap_filter);
			if(ret < 0){
				goto err_2;
				}
			}
		}
	}

	if(g_pfring_topology_mode & __NET_CONN_SENPACKET){
		if(pfring_get_bound_device_ifindex(pf_dna_handle, &pfring_if_index_up) < 0){
			printf("Error reading interface id\n");
			goto err_3;
		}	
		
		if((NET_CONN_SERIAL_2CARD == g_pfring_topology_mode)
		&& (pfring_get_bound_device_ifindex(pf_dna_handle2, &pfring_if_index_down) < 0)){
			printf("Error reading interface id\n");
			goto err_3;
		}
	}

	if(dna_cluster_register_ring(dna_cluster_handle, pf_dna_handle) < 0){
		printf("Error registering rx socket\n");
		goto err_3;
	}
	if((NET_CONN_SERIAL_2CARD == g_pfring_topology_mode)
	  && (dna_cluster_register_ring(dna_cluster_handle, pf_dna_handle2) < 0)){
		printf("Error registering rx socket\n");
		goto err_3;
	}
	
	dna_cluster_set_cpu_affinity(dna_cluster_handle, rx_bind_core, tx_bind_core);

#if 0
	if(g_pfring_topology_mode & __NET_CONN_SENPACKET){
		dna_cluster_low_level_settings(dna_cluster_handle, 1000000, 100000, 10240);
	}else{
		dna_cluster_low_level_settings(dna_cluster_handle, 1000000, 10000, 10240);
	}
#endif

	/* Now enable the cluster */
	if(dna_cluster_enable(dna_cluster_handle) < 0) {
		fprintf(stderr, "Error enabling the engine; dna NICs already in use?\n");
		goto err_3;
	}

	printf("PF_RING:Capturing from %s\n", g_pfring_up_dev_name);
	printf("PF_RING:DNA cluster [id: %u][num consumer threads: %u] is running...\n", 
			pfring_cluster_id, g_pfring_work_thread_num);

 	register_sig_handle(SIGINT, pfring_sig_handle);
 	register_sig_handle(SIGTERM, pfring_sig_handle);
 	register_sig_handle(SIGPIPE, pfring_sig_handle);
	register_sig_handle(SIGFPE, pfring_sig_handle);
 	
	return 0;

err_3:
	if(NET_CONN_SERIAL_2CARD == g_pfring_topology_mode)
	{
		pfring_close(pf_dna_handle2);
	}
	
err_2:
	pfring_close(pf_dna_handle);
	
err_1:
	dna_cluster_destroy(dna_cluster_handle);
	
	return -1;
}

int dl_io_set_cap_level(int cap_level)
{
	/* pfring暂不支持设置此模式 */
	(void)cap_level;
	
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_pfring_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	/* pfring模式无需设置 */
	(void)cap_mode;
	
	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{
	int len;

	len = snprintf(g_pfring_up_dev_name, DEV_NAME_STR_LEN, "%s", cap_dev);
	if(len >= DEV_NAME_STR_LEN){
		return -1;
	}

	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	int len;

	len = snprintf(g_pfring_up_dev_name, DEV_NAME_STR_LEN, "%s", up_dev);
	if(len >= DEV_NAME_STR_LEN){
		return -1;
	}
	
	len = snprintf(g_pfring_down_dev_name, DEV_NAME_STR_LEN, "%s", down_dev);
	if(len >= DEV_NAME_STR_LEN){
		return -1;
	}
	
	return 0;
	
}

int dl_io_set_capture_filter(const char *filter_rule)
{	
	int len;
	
	len = snprintf(g_pfring_cap_filter, CAP_FILTER_STR_LEN, "%s", filter_rule);
	if(len >= CAP_FILTER_STR_LEN){
		return -1;
	}
	
	return 0;	
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* pfring模式无缓冲队列 */
	return 0;
}

int dl_io_set_work_thread_num(int thread_num_max)
{
	g_pfring_work_thread_num = thread_num_max;
	return 0;
}

long dl_io_get_app_drop_num(int thread_num)
{
	/* pfring模式目前不提供此功能 */
	(void)thread_num;
	return 0;
}

long dl_io_get_lib_drop_num(void)
{
	long lost = 0;
	pfring_stat pf_stat = {0,0};
	
	pfring_stats(pf_dna_handle, &pf_stat);
	lost = pf_stat.drop;

	//lost += pf_dna_handle->dna.tot_dna_lost_pkts;
	if(NET_CONN_SERIAL_2CARD == g_pfring_topology_mode){
		pfring_stats(pf_dna_handle, &pf_stat);
		//lost += pf_dna_handle2->dna.tot_dna_lost_pkts;
		lost += pf_stat.drop;
	}
	
	return lost;
}

unsigned char *dl_io_get_sendbuf(void *phandle, int thread_num)
{
	unsigned char *buf;
	pfring_send_handle *real_handle = (pfring_send_handle *)phandle;

	real_handle->pkt_handle = pfring_alloc_pkt_buff(pf_thread_handle[thread_num]);
	if(NULL == real_handle->pkt_handle){
		return NULL;
	}

	buf = pfring_get_pkt_buff_data(pf_thread_handle[thread_num], real_handle->pkt_handle);
	if(NULL == buf){
		goto err_exit;
	}

	return buf;

err_exit:
	pfring_release_pkt_buff(pf_thread_handle[thread_num], real_handle->pkt_handle);
	return NULL;
}


void dl_io_free_sendbuf(void *phandle, int thread_num)
{
	pfring_send_handle *real_handle = (pfring_send_handle *)phandle;
	
	pfring_release_pkt_buff(pf_thread_handle[thread_num], real_handle->pkt_handle);
}

int dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num)
{
	int ret;
	int reverse = 0;
	pfring_send_handle *real_handle = (pfring_send_handle *)phandle;

	if(pfring_low_level_send_para[thread_num].pfring_raw_pkt_route_dir != dir){
		reverse = 1;
	}

	net_common_build_send_mac(data, pfring_low_level_send_para[thread_num].pfring_raw_pkt_hdr, eth_carry_layer_addr_type, reverse,g_pfring_topology_mode);
	/* delete by lijia 2014-12-10, datalen已经包含了mac地址长度 */
	//datalen += sizeof(struct mesa_ethernet_hdr);
	
	ret = pfring_send_pkt_buff(pf_thread_handle[thread_num], real_handle->pkt_handle, 1);

	return ret;
}

void *dl_io_get_send_handle(int thread_num)
{	
	pfring_send_handle *real_handle;

	real_handle = (pfring_send_handle *)calloc(1, sizeof(pfring_send_handle));

	real_handle->thread_num = thread_num;

	return (void *)real_handle;
}

int dl_io_get_version(void)
{
	return g_pfring_version_VERSION;
}

int dl_io_init(int argc, char *argv[])
{
	if(pfring_init() < 0) {
		fprintf(stderr,"%s\n","Pfring init error!\n");
		return -1;
	}

	return 0;
}

void dl_io_run(void)
{
	char cluster_device[DEV_NAME_STR_LEN];
	int i;
	
	for (i = 0; i < g_pfring_work_thread_num; i++) {
		snprintf(cluster_device, sizeof(cluster_device), "dnacluster:%d@%d", pfring_cluster_id, i);
		pf_thread_handle[i] = pfring_open(cluster_device, MTU_MAX, PF_RING_PROMISC);
		if (NULL == pf_thread_handle[i]) {
			printf("pfring_open %s error [%s]\n", cluster_device, strerror(errno));
			return;
		}

		pfring_set_socket_mode(pf_thread_handle[i], pfring_mode);
		pfring_enable_ring(pf_thread_handle[i]);
		pd_index[i] = i;
		pthread_create(&pd_thread[i], NULL, pfring_worker, (void *)&pd_index[i]);
	}

	while(1){
		pause();
	}
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_pfring_work_fun = fun;
	return 0;
}

#ifdef __cplusplus
}
#endif

