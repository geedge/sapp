/*
	2016-04-26, 应张鹏某项目需求, 对方将原始IP报文写到一个文件, 依次读取出来并解析. 
*/
#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

int g_ipfile_version_VERSION_20160426;
int g_ipfile_version_VERSION = 20160426;
static PACKET_IO_CB_T g_ipfile_work_fun;
static int g_ipfile_work_thread_num = 1;
static int g_ipfile_cap_level = CAP_LEVEL_IPV4;
//static int g_ipfile_topology_mode = NET_CONN_PARALLEL;
static int ipfile_work_thread_seq[MAX_THREAD_NUM];
static pthread_t ipfile_work_tid[MAX_THREAD_NUM];
static char g_ipfile_input_name[DEV_NAME_STR_LEN] = "dumpfile"; 
static FILE *input_fp = NULL;
static char read_file_buf[65536];

int dl_io_set_cap_level(int cap_level)
{
	g_ipfile_cap_level = cap_level;
	
	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode;
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	(void)topology_mode;
	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{
//	strncpy(g_ipfile_input_name, cap_dev, DEV_NAME_STR_LEN);
	strncpy(g_ipfile_input_name, "dumpfile", DEV_NAME_STR_LEN);
	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	(void)up_dev;
	(void)down_dev;

	return 0;
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule; /* ipfile模式不支持过滤规则 */
	return 0;
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max;
	return 0;
}
	
int dl_io_set_work_thread_num(int thread_num_max)
{
	g_ipfile_work_thread_num = 1; /* ipfile只支持一个线程 */
	return 0;
}


long dl_io_get_app_drop_num(int thread_num)
{
	(void)thread_num;
	return 0;
}

long dl_io_get_lib_drop_num(void)
{
	return 0;
}


unsigned char *dl_io_get_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	return (unsigned char * )0xffffffff;
}

void dl_io_free_sendbuf(void *phandle, int thread_num)
{
	(void)phandle;
	(void)thread_num;
	
	return;
}

int dl_io_low_level_send(void *phandle, UINT8 *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num)
{
	return -1;
}

void *dl_io_get_send_handle(int thread_num)
{
	return (void *)0xffffffff;
}


int dl_io_get_version(void)
{
	return g_ipfile_version_VERSION;
}

int dl_io_init(int argc, char *argv[])
{
	input_fp = fopen(g_ipfile_input_name, "r");
	if(NULL == input_fp) {
		fprintf(stderr, "open file '%s' error!\n", g_ipfile_input_name);
		return -1;
	}

	return 0;
}


static void *ipfile_worker(void *arg)
{
	int tid = *((int *)arg);
	raw_pkt_t raw_pkt;
	size_t ret;
	const struct mesa_ip4_hdr *ip4_hdr;
	int tot_ip_pkt_len;
	long long tot_ip_pkt_num = 0;

	memset(&raw_pkt, 0, sizeof(raw_pkt_t));

	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	raw_pkt.offset_to_raw_pkt_hdr = 0;
	raw_pkt.low_layer_type = (enum addr_type_t)g_ipfile_cap_level;

	ip4_hdr = (const struct mesa_ip4_hdr *)read_file_buf;
	
	while(1){
		ret = fread(read_file_buf, sizeof(struct mesa_ip4_hdr), 1, input_fp);
		if(ret <= 0){
			fclose(input_fp);
			goto done;
		}
		tot_ip_pkt_len = ntohs(ip4_hdr->ip_len);

		ret = fread(read_file_buf + sizeof(struct mesa_ip4_hdr), tot_ip_pkt_len - sizeof(struct mesa_ip4_hdr), 1, input_fp);
		if(ret <= 0){
			fclose(input_fp);
			goto done;
		}

		raw_pkt.raw_pkt_data = read_file_buf;
		raw_pkt.raw_pkt_len = tot_ip_pkt_len;
		
		(*g_ipfile_work_fun)((const raw_pkt_t *)&raw_pkt, 0, tid);
		tot_ip_pkt_num++;
	}

done:
	printf("total ip packet number: %lld\n", tot_ip_pkt_num);
        fflush(stdout);
        _exit(1); /* 不能调用exit, 会被接管 */
	return NULL;
}


void dl_io_run(void)
{
	int i=0;
	
	for(i = 0; i < g_ipfile_work_thread_num; i++)
	{
		ipfile_work_thread_seq[i] = i;
		pthread_create(&(ipfile_work_tid[i]), NULL, ipfile_worker, (void *) &(ipfile_work_thread_seq[i]));
	}
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_ipfile_work_fun = fun;
	return 0;
}


#ifdef __cplusplus
}
#endif


