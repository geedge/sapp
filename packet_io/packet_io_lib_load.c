#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <dlfcn.h>
#include <unistd.h>
#include <linux/limits.h>
#include "packet_io.h"
#include "packet_io_internal.h"

#define DL_IO_LIB_PATH					"./platform_lib"

extern int sapp_packet_io_v;
extern int g_packet_io_cap_mode;
extern dl_io_fun_list_t dl_io_fun_list;

struct dl_io_lib_name g_dl_io_lib_info[] = 
{
	{CAP_MODEL_PAG				,	(char *)"packet_io_pag.so" },
	{CAP_MODEL_PCAP_ONLINE 		,	(char *)"packet_io_pcap.so" },
	{CAP_MODEL_PCAP_DUMPFILE 	,	(char *)"packet_io_pcap.so" },
	{CAP_MODEL_PFRING			,	(char *)"packet_io_pfring.so" },
	{CAP_MODEL_DPDK				,	(char *)"packet_io_dpdk.so" },
	{CAP_MODEL_PPF				,	(char *)"packet_io_ppf.so" },
	{CAP_MODEL_NPACKET			,	(char *)"packet_io_npacket.so" },
	{CAP_MODEL_QNF				,	(char *)"packet_io_qnf.so" },
	{CAP_MODEL_N95				,	(char *)"packet_io_n95.so" },	
	{CAP_MODEL_PCAP_DUMPLIST	,	(char *)"packet_io_pcap.so"},
	{CAP_MODEL_TOPSEC			,	(char *)"packet_io_topsec.so"},
	{CAP_MODEL_IPFILE				,	(char *)"packet_io_ipfile.so"},
	{CAP_MODEL_MARSIOV4			,	(char *)"packet_io_marsio.so"},
	{CAP_MODEL_AGENT_SMITH		,	(char *)"packet_io_agent_smith.so"},	
	{CAP_MODEL_DPDK_VXLAN		,	(char *)"packet_io_dpdk_vxlan.so"},
	{CAP_MODEL_MARSIOV4_VXLAN	,	(char *)"packet_io_marsio_vxlan.so"},
	{CAP_MODEL_PAG_MARSIO		,	(char *)"packet_io_pag_marsio.so"},
};

static inline void __print_err_msg(void *fun_ptr, const char *libname, const char *fun_name)
{
	if(NULL == fun_ptr){
		printf("Warning! %s not support %s\n", libname, fun_name);
	}
}

static inline void __print_critical_msg(void *fun_ptr, const char *libname, const char *fun_name)
{
	if(NULL == fun_ptr){
		printf("Critical! %s not support %s\n", libname, fun_name);
	}
}

#if LINK_MODE_DYNAMIC
static int packet_io_lib_load_by_mode(int cap_mode, const char *full_lib_path)
{
	void *io_lib_handle;

	io_lib_handle = dlopen(full_lib_path, RTLD_LAZY | RTLD_GLOBAL);
	if(NULL == io_lib_handle){
		printf("\033[1;31;40m[Error]dlopen %s error, %s!\033[0m\n", full_lib_path, dlerror());
		return -1;
	}

	dl_io_fun_list.dl_io_set_cap_level = (int (*)(int cap_level))dlsym(io_lib_handle, "dl_io_set_cap_level");
	dl_io_fun_list.dl_io_set_cap_mode = (int (*)(int cap_mode))dlsym(io_lib_handle, "dl_io_set_cap_mode");
	dl_io_fun_list.dl_io_set_topology_mode = (int (*)(int topology_mode))dlsym(io_lib_handle, "dl_io_set_topology_mode");
	dl_io_fun_list.dl_io_set_capdev_parallel = (int (*)(const char *cap_dev))dlsym(io_lib_handle, "dl_io_set_capdev_parallel");
	dl_io_fun_list.dl_io_set_capdev_serial = (int (*)(const char *up_dev, const char *down_dev))dlsym(io_lib_handle, "dl_io_set_capdev_serial");
	dl_io_fun_list.dl_io_set_capture_filter = (int (*)(const char *filter_rule))dlsym(io_lib_handle, "dl_io_set_capture_filter");
	dl_io_fun_list.dl_io_set_cap_buf_queue = (int (*)(int queue_num_max))dlsym(io_lib_handle, "dl_io_set_cap_buf_queue");
	dl_io_fun_list.dl_io_set_work_thread_num = (int (*)(int thread_num_max))dlsym(io_lib_handle, "dl_io_set_work_thread_num");
	dl_io_fun_list.dl_io_get_app_drop_num = (long (*)(int thread_num))dlsym(io_lib_handle, "dl_io_get_app_drop_num");
	dl_io_fun_list.dl_io_get_lib_drop_num = (long (*)(void))dlsym(io_lib_handle, "dl_io_get_lib_drop_num");
	dl_io_fun_list.dl_io_get_sendbuf = (unsigned char *  (*)(void *, int thread_num))dlsym(io_lib_handle, "dl_io_get_sendbuf");
	dl_io_fun_list.dl_io_free_sendbuf = (void (*)(void *, int thread_num))dlsym(io_lib_handle, "dl_io_free_sendbuf");
	dl_io_fun_list.dl_io_get_send_handle = (void * (*)(int thread_num))dlsym(io_lib_handle, "dl_io_get_send_handle");
	dl_io_fun_list.dl_io_low_level_send = (int (*)(void *, unsigned char *,int ,int , int ,int ))dlsym(io_lib_handle, "dl_io_low_level_send");
	dl_io_fun_list.dl_io_raw_pkt_send = (int (*)(void *, unsigned char *,int , void *,int ))dlsym(io_lib_handle, "dl_io_raw_pkt_send");	
	dl_io_fun_list.dl_io_init = (int (*)(int argc, char *argv[]))dlsym(io_lib_handle, "dl_io_init");
	dl_io_fun_list.dl_io_run = (void (*)(void))dlsym(io_lib_handle, "dl_io_run");
	dl_io_fun_list.dl_io_register_cb = (int (*)(PACKET_IO_CB_T fun))dlsym(io_lib_handle, "dl_io_register_cb");
	dl_io_fun_list.dl_io_register_exit_cb = (int (*)(PACKET_IO_EXIT_CB_T exit_fun))dlsym(io_lib_handle, "dl_io_register_exit_cb");
	dl_io_fun_list.dl_io_get_version = (int (*)(void))dlsym(io_lib_handle, "dl_io_get_version");
	dl_io_fun_list.dl_io_device_alias = (void * (*)(unsigned int , char *))dlsym(io_lib_handle, "dl_io_device_alias");

}
#else

extern int dl_io_set_cap_level(int cap_level);
extern int dl_io_set_cap_mode(int cap_mode);
extern int dl_io_set_topology_mode(int topology_mode);
extern int dl_io_set_capdev_parallel(const char *cap_dev);
extern int dl_io_set_capdev_serial(const char *up_dev, const char *down_dev);
extern int dl_io_set_capture_filter(const char *filter_rule);
extern int dl_io_set_cap_buf_queue(int queue_num_max);
extern int dl_io_set_work_thread_num(int thread_num_max);
extern long dl_io_get_app_drop_num(int thread_num);
extern long dl_io_get_lib_drop_num(void);
extern unsigned char * dl_io_get_sendbuf(void *, int );
extern void dl_io_free_sendbuf(void *, int thread_num);
extern void * dl_io_get_send_handle(int  thread_num);
extern int dl_io_low_level_send(void *phandle, unsigned char *data,int datalen,
						int eth_carry_layer_addr_type, int dir,int thread_num); /* 不含ethernet层 */
extern int dl_io_raw_pkt_send(void *phandle, unsigned char *data,int datalen, void *arg, int thread_num); /* 全部原始包 */
extern int dl_io_init(int argc, char *argv[]);
extern void dl_io_run(void);
extern int dl_io_register_cb(PACKET_IO_CB_T fun);
extern int dl_io_register_exit_cb(PACKET_IO_EXIT_CB_T exit_fun); 
extern int dl_io_get_version(void);
extern void * dl_io_device_alias(unsigned int target_id, char *device_args);


static int packet_io_lib_load_by_mode(int no_use, const char *full_lib_path)
{
	dl_io_fun_list.dl_io_set_cap_level = (int (*)(int cap_level))dl_io_set_cap_level;
	dl_io_fun_list.dl_io_set_cap_mode = (int (*)(int cap_mode))dl_io_set_cap_mode;
	dl_io_fun_list.dl_io_set_topology_mode = (int (*)(int topology_mode))dl_io_set_topology_mode;
	dl_io_fun_list.dl_io_set_capdev_parallel = (int (*)(const char *cap_dev))dl_io_set_capdev_parallel;
	dl_io_fun_list.dl_io_set_capdev_serial = (int (*)(const char *up_dev, const char *down_dev))dl_io_set_capdev_serial;
	dl_io_fun_list.dl_io_set_capture_filter = (int (*)(const char *filter_rule))dl_io_set_capture_filter;
	dl_io_fun_list.dl_io_set_cap_buf_queue = (int (*)(int queue_num_max))dl_io_set_cap_buf_queue;
	dl_io_fun_list.dl_io_set_work_thread_num = (int (*)(int thread_num_max))dl_io_set_work_thread_num;
	dl_io_fun_list.dl_io_get_app_drop_num = (long (*)(int thread_num))dl_io_get_app_drop_num;
	dl_io_fun_list.dl_io_get_lib_drop_num = (long (*)(void))dl_io_get_lib_drop_num;
	dl_io_fun_list.dl_io_get_sendbuf = (unsigned char *  (*)(void *, int thread_num))dl_io_get_sendbuf;
	dl_io_fun_list.dl_io_free_sendbuf = (void (*)(void *, int thread_num))dl_io_free_sendbuf;
	dl_io_fun_list.dl_io_get_send_handle = (void * (*)(int thread_num))dl_io_get_send_handle;
	dl_io_fun_list.dl_io_low_level_send = (int (*)(void *, unsigned char *,int ,int , int ,int ))dl_io_low_level_send;
	dl_io_fun_list.dl_io_raw_pkt_send = (int (*)(void *, unsigned char *,int , void *,int ))dl_io_raw_pkt_send;	
	dl_io_fun_list.dl_io_init = (int (*)(int argc, char *argv[]))dl_io_init;
	dl_io_fun_list.dl_io_run = (void (*)(void))dl_io_run;
	dl_io_fun_list.dl_io_register_cb = (int (*)(PACKET_IO_CB_T fun))dl_io_register_cb;
	//dl_io_fun_list.dl_io_register_exit_cb = (int (*)(PACKET_IO_EXIT_CB_T exit_fun))dl_io_register_exit_cb;
	dl_io_fun_list.dl_io_get_version = (int (*)(void))dl_io_get_version;
	dl_io_fun_list.dl_io_device_alias = (void * (*)(unsigned int , char *))dl_io_device_alias;

	return 0;
}
#endif


/* 
	(0:pag,1:pcap,2:dumpfile,3:pfring,4:DPDK,5:ppf,6:NPacket,7:qnf,8:N95,9:pcap-dumpfile-list,10:topsec,
	(11:ipfile, 12:marsio4, 13:agent_smith, 14:dpdk_vxlan, 15:marsio_vxlan.  
*/
int packet_io_lib_load(int cap_mode)
{
#if LINK_MODE_DYNAMIC
	int dl_io_lib_ver;
#endif

	char *lib_name;
	char full_lib_path[PATH_MAX];
	
	if(cap_mode < 0 || cap_mode > __CAP_MODEL_MAX){
		printf("\033[1;31;40m[Error]Unknown capture_mode:%d\033[0m\n", cap_mode);
		return -1;
	}
	
	lib_name = g_dl_io_lib_info[cap_mode].lib_name;
	snprintf(full_lib_path, PATH_MAX, "%s/%s", DL_IO_LIB_PATH, lib_name);
	

	if(packet_io_lib_load_by_mode(cap_mode, full_lib_path) < 0){
		return -1;
	}

	__print_err_msg((void *)dl_io_fun_list.dl_io_set_cap_level, full_lib_path, "dl_io_set_cap_level");
	__print_err_msg((void *)dl_io_fun_list.dl_io_set_cap_mode, full_lib_path, "dl_io_set_cap_mode");
	__print_err_msg((void *)dl_io_fun_list.dl_io_set_topology_mode, full_lib_path, "dl_io_set_topology_mode");
	__print_err_msg((void *)dl_io_fun_list.dl_io_set_capdev_parallel, full_lib_path, "dl_io_set_capdev_parallel");
	__print_err_msg((void *)dl_io_fun_list.dl_io_set_capdev_serial, full_lib_path, "dl_io_set_capdev_serial");
	__print_err_msg((void *)dl_io_fun_list.dl_io_set_capture_filter, full_lib_path, "dl_io_set_capture_filter");
	__print_err_msg((void *)dl_io_fun_list.dl_io_set_cap_buf_queue, full_lib_path, "dl_io_set_cap_buf_queue");
	__print_critical_msg((void *)dl_io_fun_list.dl_io_set_work_thread_num, full_lib_path, "dl_io_set_work_thread_num");
	__print_err_msg((void *)dl_io_fun_list.dl_io_get_app_drop_num, full_lib_path, "dl_io_get_app_drop_num");
	__print_err_msg((void *)dl_io_fun_list.dl_io_get_lib_drop_num, full_lib_path, "dl_io_get_lib_drop_num");
	__print_err_msg((void *)dl_io_fun_list.dl_io_get_sendbuf, full_lib_path, "dl_io_get_sendbuf");
	__print_err_msg((void *)dl_io_fun_list.dl_io_get_send_handle, full_lib_path, "dl_io_set_cap_level");
	__print_err_msg((void *)dl_io_fun_list.dl_io_low_level_send, full_lib_path, "dl_io_low_level_send");
	__print_err_msg((void *)dl_io_fun_list.dl_io_raw_pkt_send, full_lib_path, "dl_io_raw_pkt_send");
	__print_critical_msg((void *)dl_io_fun_list.dl_io_init, full_lib_path, "dl_io_init");
	__print_critical_msg((void *)dl_io_fun_list.dl_io_run, full_lib_path, "dl_io_run");
	__print_critical_msg((void *)dl_io_fun_list.dl_io_register_cb, full_lib_path, "dl_io_register_cb");
	__print_err_msg((void *)dl_io_fun_list.dl_io_register_exit_cb, full_lib_path, "dl_io_register_exit_cb");
	__print_err_msg((void *)dl_io_fun_list.dl_io_get_version, full_lib_path, "dl_io_get_version");
	__print_err_msg((void *)dl_io_fun_list.dl_io_device_alias, full_lib_path, "dl_io_device_alias");

#if LINK_MODE_DYNAMIC
	if(dl_io_fun_list.dl_io_get_version != NULL){
		dl_io_lib_ver = dl_io_fun_list.dl_io_get_version();
		if(dl_io_lib_ver != sapp_packet_io_v){
			printf("\033[33m[Warning]packet_io lib: '%s' version is different with platform!!\033[0m\n", full_lib_path);
			printf("\033[33mPlease copy newest packet_io library to './platform_lib/'\033[0m\n");
			/* 可能某些情况下需要新旧几个版本对比测试, 应该允许不一样的版本运行, 但要打印警告提示 */
			usleep(1000*100);
			printf("\033[33m[Warning]Run anyway, are you sure? \033[0m\n");
			usleep(1000*500);
			printf("\033[33m[Warning]Run anyway, are you sure??? \033[0m\n");	
			usleep(1000*1000);
			printf("\033[33m[Warning]Run anyway, are you sure????? \033[0m\n");
			usleep(1000*2000);	
			printf("\033[33m[Warning]Run anyway, platform action is unpredictable!\033[0m\n");			
		}
	}
#endif	

	g_packet_io_cap_mode = cap_mode;

	return 0;
}


#ifdef __cplusplus
}
#endif

