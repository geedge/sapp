#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include "packet_io.h"
#include "packet_io_internal.h"
#include "mesa_net.h"
#include "qnfapi.h"

#define QNF_RECORD_HDR_SIZE	(16)
#define QNF_MAX_CAP_LEN		(0x5F)	/* unit 16byte, 0x5f = 1520byte */

static PACKET_IO_CB_T g_qnf_work_fun;
static char g_qnf_up_dev_name[DEV_NAME_STR_LEN] = "qnf0"; /* if in parallel mode, use this arg */
static int g_qnf_work_thread_num = 1;
static int g_qnf_global_handle = -1;
static int g_qnf_cap_level = CAP_LEVEL_MAC;
static int g_qnf_topology_mode = NET_CONN_PARALLEL;
static int qnf_work_thread_seq[MAX_THREAD_NUM];
static pthread_t qnf_work_tid[MAX_THREAD_NUM];


int dl_io_set_cap_level(int cap_level)
{
	g_qnf_cap_level = cap_level;
	
	return 0;
}

int dl_io_set_cap_mode(int cap_mode)
{
	(void)cap_mode; /* qnf模式无需设置 */
	return 0;
}

int dl_io_set_topology_mode(int topology_mode)
{
	switch(topology_mode){
		case NET_CONN_PARA_NOSEND:
		case NET_CONN_PARALLEL:
		case NET_CONN_SERIAL_2CARD:
		case NET_CONN_SERIAL_GDEV:
			g_qnf_topology_mode = topology_mode;
		break;

		default:
			return -1;
	}

	return 0;
}

int dl_io_set_capdev_parallel(const char *cap_dev)
{

	int len;

	len = snprintf(g_qnf_up_dev_name, DEV_NAME_STR_LEN, "%s", cap_dev);
	if(len >= DEV_NAME_STR_LEN){
		return -1;
	}

	return 0;
}

int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev)
{
	 /* qnf模式暂不支持串联模式 */
	(void)up_dev;
	(void)down_dev;

	return -1;
}

int dl_io_set_capture_filter(const char *filter_rule)
{
	(void)filter_rule; /* qnf模式暂不支持过滤规则 */
	return 0;
}

int dl_io_set_cap_buf_queue(int queue_num_max)
{
	(void)queue_num_max; /* qnf模式无缓冲队列 */
	return 0;
}
	
int dl_io_set_work_thread_num(int thread_num_max)
{
	g_qnf_work_thread_num = thread_num_max;
	return 0;
}


long dl_io_get_app_drop_num(int thread_num)
{
	
	return qnf_get_drop_cnt(g_qnf_global_handle, thread_num);
}

long dl_io_get_lib_drop_num(void)
{
	/* qnf模式目前不提供此功能 */
	return 0;
}

int dl_io_init(int argc, char *argv[])
{
	g_qnf_global_handle = qnf_open(g_qnf_up_dev_name);
	if(g_qnf_global_handle < 0) {
		fprintf(stderr,"%s\n","qnf open err!\n");
		return -1;
	}
	
	// set snap length to 0x5f * 16 bytes = 1520 bytes
	if(qnf_configure(g_qnf_global_handle, g_qnf_work_thread_num, QNF_MAX_CAP_LEN) < 0){
		printf("qnf_configure failed\n");
		return -1;
	}
	
	qnf_cam_init(g_qnf_global_handle);
	qnf_tag_map_int(g_qnf_global_handle);
	qnf_10ge_wanmode_set(g_qnf_global_handle,0);
	qnf_set_hashmode(g_qnf_global_handle, 0x3);
	
	return 0;
}

static void *qnf_worker(void *arg)
{
	int tid = *((int *)arg);
	erf_record_t *erfhdr;
	struct timeval maxwait;
	struct timeval poll;
	unsigned int mindata = 1024 * 8;
	unsigned char* top;
	unsigned char* bottom;
	unsigned short rlen, wlen;
	raw_pkt_t raw_pkt;

	maxwait.tv_usec = 100;
	poll.tv_usec = 10;
	
	// map stream to buffers
	if(qnf_attach_stream(g_qnf_global_handle, tid, 0, 0) < 0){
		printf("qnf configure failed, not attached\n");
		assert(0);
		return(NULL);
	}
	
	// set polling parameters
	if(qnf_set_stream_poll(g_qnf_global_handle, tid, mindata, &maxwait, &poll) < 0){
		printf("set stream poll parameter failed\n");
		assert(0);
		return(NULL);
	}

	// start capturing data
	if(qnf_start_stream(g_qnf_global_handle, tid) < 0){
		printf("qnf_start_stream failed\n");
		assert(0);
		return(NULL);
	}

	bottom = NULL;
	while(1){
		top = qnf_advance_stream(g_qnf_global_handle, tid, &bottom);
   		if(NULL == top){
			printf("Error, qnf_advance_stream %d return NULL pointer.\n", tid);
			assert(0);
   		}

	    	if (top == bottom){
			continue;
		}	

		while(((top-bottom) > QNF_RECORD_HDR_SIZE)){
	    		erfhdr = (erf_record_t *)bottom;
			rlen = ntohs(erfhdr->rlen);
			wlen = ntohs(erfhdr->wlen);
			
			if((top-bottom) < rlen){
				    break;
			}

			raw_pkt.low_layer_type = (enum addr_type_t)g_qnf_cap_level;
			raw_pkt.raw_pkt_data = (const void *)bottom;
			raw_pkt.raw_pkt_len = wlen;
			raw_pkt.raw_pkt_ts.tv_sec = 0;
			raw_pkt.raw_pkt_ts.tv_usec = 0;
		
			(*g_qnf_work_fun)((const raw_pkt_t *)&raw_pkt, 0, tid);

			bottom += rlen;
		}
	}

	return NULL;
}


void dl_io_run(void)
{
	int i=0;
	
	for(i = 0; i < g_qnf_work_thread_num; i++)
	{
		qnf_work_thread_seq[i] = i;
		pthread_create(&(qnf_work_tid[i]), NULL, qnf_worker, (void *) &(qnf_work_thread_seq[i]));
	}

    	sleep(4);
    	
    	capture_start(g_qnf_global_handle, QNF_MAX_CAP_LEN, 0x1);
}

int dl_io_register_cb(PACKET_IO_CB_T fun)
{
	g_qnf_work_fun = fun;
	return 0;
}


#ifdef __cplusplus
}
#endif


