#ifdef __cplusplus
extern "C" {
#endif

#if DEBUG
#include "sapp_api.h"
#include "sapp_private_api.h"

extern int g_packet_io_thread_num;
extern iknow_handle PLATFORM_IHANDLE;
void iknow_register_eth_cb(void *ihandle);
void *packet_io_status_eth_mem_init(void);
void iknow_register_eth_cb(void *ihandle);
void packet_io_status_eth_time_cb(void);
void *packet_io_status_vlan_mem_init(void);
void packet_io_status_vlan_time_cb(void);
void iknow_register_vlan_cb(void *ihandle);
void *packet_io_status_stream_hash_mem_init(void);
void iknow_register_stream_hash_cb(void *ihandle);
void packet_io_status_stream_hash_time_cb(void);
void *packet_io_status_tcp_pkt_mem_init(void);
void packet_io_status_tcp_pkt_time_cb(void);
void iknow_register_tcp_pkt_cb(void *ihandle);
void *packet_io_status_tcp_stream_mem_init(void);
void iknow_register_tcp_stream_cb(void *ihandle);
void packet_io_status_tcp_stream_time_cb(void);

packet_io_status_t *g_packet_io_status_pool[MAX_THREAD_NUM];

typedef struct{
	void (*time_cb)(void);
	void *(*mem_init)(void);
	void (*iknow_register)(void *);
}packet_io_status_individual_t;


static packet_io_status_individual_t packet_io_status_individual_fun[IO_STATUS_MAX] = 
{
	{packet_io_status_eth_time_cb,	packet_io_status_eth_mem_init, 	iknow_register_eth_cb}, /* 0 */
	{NULL,	NULL,	NULL},
	{NULL,	NULL,	NULL},
	{packet_io_status_vlan_time_cb,	packet_io_status_vlan_mem_init, iknow_register_vlan_cb},
	{NULL,	NULL,	NULL},
	{NULL,	NULL, 	NULL}, /* 5 */
	{NULL,	NULL, 	NULL},
	{NULL,	NULL, 	NULL},
	{packet_io_status_tcp_pkt_time_cb,	packet_io_status_tcp_pkt_mem_init, 	iknow_register_tcp_pkt_cb},
	{NULL,	NULL, 	NULL},
	{NULL,	NULL, 	NULL}, /* 10 */
	{NULL,	NULL, 	NULL},
	{packet_io_status_tcp_stream_time_cb,	packet_io_status_tcp_stream_mem_init, 	iknow_register_tcp_stream_cb},
	{NULL,	NULL, 	NULL},
	{packet_io_status_stream_hash_time_cb,	packet_io_status_stream_hash_mem_init, 	iknow_register_stream_hash_cb}, 	
};

static void *packet_io_status_time_thread(void *arg)
{
	time_t last_time = time(NULL);
	time_t cur_time;
	int i;

#if(__GNUC__ * 100 + __GNUC_MINOR__ * 10 + __GNUC_PATCHLEVEL__ >= 480) /* 版本判断, 很多旧系统无法编译 */
#ifdef _GNU_SOURCE
	pthread_setname_np(pthread_self(), "sapp_io_log");
#endif
#endif

	while(1){
		cur_time = time(NULL);
		if(cur_time - last_time >= 1){
			last_time = cur_time;
			for(i = 0; i < IO_STATUS_MAX; i++){
				if(packet_io_status_individual_fun[i].time_cb != NULL){
					(*packet_io_status_individual_fun[i].time_cb)();
				}
			}
		}

		usleep(10000);
	}

	return NULL;
}

int packet_io_status_init(void)
{
	int i, j;
	pthread_t pid;

	for(i = 0; i < g_packet_io_thread_num; i++){
		g_packet_io_status_pool[i] = (packet_io_status_t *)malloc(sizeof(void *) * IO_STATUS_MAX);
		for(j = 0; j < IO_STATUS_MAX; j++){
			if(packet_io_status_individual_fun[j].mem_init != NULL){
				g_packet_io_status_pool[i]->packet_io_status[j] = (packet_io_status_base_t *)packet_io_status_individual_fun[j].mem_init();
			}
		}
	}

	for(i = 0; i < IO_STATUS_MAX; i++){
		if(packet_io_status_individual_fun[i].iknow_register != NULL){
			packet_io_status_individual_fun[i].iknow_register(PLATFORM_IHANDLE);
		}
	}

	pthread_create(&pid, NULL, packet_io_status_time_thread, NULL);

	return 0;
}
#else
int packet_io_status_init(void)
{
	return 0;	
}
#endif

#ifdef __cplusplus
}
#endif
