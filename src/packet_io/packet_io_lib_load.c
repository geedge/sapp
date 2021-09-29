#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"


#define DL_IO_LIB_PATH					"./platform_lib"

extern int sapp_packet_io_v;
extern dl_io_fun_list_t dl_io_fun_list;

const struct dl_io_lib_name g_dl_io_lib_info[__CAP_MODEL_MAX] = 
{
	{CAP_MODEL_PAG				,	"pag",			(char *)"packet_io_pag.so" },
	{CAP_MODEL_PCAP_ONLINE 		,	"pcap",			(char *)"packet_io_pcap.so" },
	{CAP_MODEL_PCAP_DUMPFILE 	,	"pcap",			(char *)"packet_io_pcap.so" },
	{CAP_MODEL_PFRING			,	"pfring",		(char *)"packet_io_pfring.so" },
	{CAP_MODEL_DPDK				,	"dpdk",			(char *)"packet_io_dpdk.so" },
	{CAP_MODEL_PPF				,	"ppf",			(char *)"packet_io_ppf.so" },
	{CAP_MODEL_NPACKET			,	"npkt",			(char *)"packet_io_npacket.so" },
	{CAP_MODEL_QNF				,	"qnf",			(char *)"packet_io_qnf.so" },
	{CAP_MODEL_N95				,	"n95",			(char *)"packet_io_n95.so" },	
	{CAP_MODEL_PCAP_DUMPLIST	,	"pcap",			(char *)"packet_io_pcap.so"},
	{CAP_MODEL_TOPSEC			,	"topsec",		(char *)"packet_io_topsec.so"},
	{CAP_MODEL_IPFILE			,	"ipfile",		(char *)"packet_io_ipfile.so"},
	{CAP_MODEL_MARSIOV4			,	"marsio",		(char *)"packet_io_marsio.so"},
	{CAP_MODEL_AGENT_SMITH		,	"asmith",		(char *)"packet_io_agent_smith.so"},	
	{CAP_MODEL_DPDK_VXLAN		,	"dpdkvxlan",	(char *)"packet_io_dpdk_vxlan.so"},
	{CAP_MODEL_MARSIOV4_VXLAN	,	"marsio_vxlan",	(char *)"packet_io_marsio_vxlan.so"},
	{CAP_MODEL_PAG_MARSIO		,	"marsio_pag",	(char *)"packet_io_pag_marsio.so"},
	{CAP_MODEL_TUN				,	"tun",			(char *)"packet_io_tun.so"},
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

static inline void *packet_io_symbol_load_by_mode(void *io_lib_handle, int cap_mode, const char *fun_sym)
{
	void *fun_pointer;
	char fun_sym_with_prefix[NAME_MAX];

	snprintf(fun_sym_with_prefix, NAME_MAX, "%s_%s", g_dl_io_lib_info[cap_mode].prefix, fun_sym);

	fun_pointer = dlsym(io_lib_handle, fun_sym_with_prefix);

	return fun_pointer;
}

static int packet_io_lib_load_by_mode(int cap_mode, const char *full_lib_path)
{
	void *io_lib_handle;

	io_lib_handle = dlopen(full_lib_path, RTLD_LAZY | RTLD_GLOBAL);
	if(NULL == io_lib_handle){
		printf("\033[1;31;40m[Error]dlopen %s error, %s!\033[0m\n", full_lib_path, dlerror());
		return -1;
	}

	dl_io_fun_list.dl_io_set_cap_level = (int (*)(int cap_level))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_cap_level");
	dl_io_fun_list.dl_io_set_cap_mode = (int (*)(int cap_mode))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_cap_mode");
	dl_io_fun_list.dl_io_set_topology_mode = (int (*)(int topology_mode))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_topology_mode");
	dl_io_fun_list.dl_io_set_capdev_parallel = (int (*)(const char *cap_dev))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_capdev_parallel");
	dl_io_fun_list.dl_io_set_capdev_serial = (int (*)(const char *up_dev, const char *down_dev))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_capdev_serial");
	dl_io_fun_list.dl_io_set_capture_filter = (int (*)(const char *filter_rule))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_capture_filter");
	dl_io_fun_list.dl_io_set_cap_buf_queue = (int (*)(int queue_num_max))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_cap_buf_queue");
	dl_io_fun_list.dl_io_set_work_thread_num = (int (*)(int thread_num_max))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_set_work_thread_num");
	dl_io_fun_list.dl_io_get_app_drop_num = (long (*)(int thread_num))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_get_app_drop_num");
	dl_io_fun_list.dl_io_get_lib_drop_num = (long (*)(void))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_get_lib_drop_num");
	dl_io_fun_list.dl_io_get_sendbuf = (unsigned char *  (*)(void *, int thread_num))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_get_sendbuf");
	dl_io_fun_list.dl_io_free_sendbuf = (void (*)(void *, int thread_num))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_free_sendbuf");
	dl_io_fun_list.dl_io_get_send_handle = (void * (*)(int thread_num))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_get_send_handle");
	dl_io_fun_list.dl_io_low_level_send = (int (*)(void *, unsigned char *,int ,int , int ,int ))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_low_level_send");
	dl_io_fun_list.dl_io_raw_pkt_send = (int (*)(void *, unsigned char *,int , void *,int ))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_raw_pkt_send");	
	dl_io_fun_list.dl_io_init = (int (*)(int argc, char *argv[]))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_init");
	dl_io_fun_list.dl_io_run = (void (*)(void))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_run");
	dl_io_fun_list.dl_io_register_cb = (int (*)(PACKET_IO_CB_T fun))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_register_cb");
	dl_io_fun_list.dl_io_register_exit_cb = (int (*)(PACKET_IO_EXIT_CB_T exit_fun))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_register_exit_cb");
	dl_io_fun_list.dl_io_get_version = (int (*)(void))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_get_version");
	dl_io_fun_list.dl_io_device_alias = (void * (*)(unsigned int , char *))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_device_alias");

	dl_io_fun_list.dl_io_free_send_handle = (void (*dl_io_free_send_handle)(int thread_seq, void *handle))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_free_send_handle");
	dl_io_fun_list.dl_io_destroy = (void (*dl_io_destroy)(void))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_destroy");
	dl_io_fun_list.dl_io_device_alias_free = (void (*)(unsigned int target_id, char *device_args))packet_io_symbol_load_by_mode(io_lib_handle, cap_mode, "dl_io_device_alias_free");
	return 0;
}
#else
static dl_io_fun_list_t dl_io_fun_list_static_link[__CAP_MODEL_MAX];

static int packet_io_lib_load_by_mode(int cap_mode, const char *no_use)
{
#ifdef IOMODE_PCAP
	if((CAP_MODEL_PCAP_ONLINE == cap_mode) || (CAP_MODEL_PCAP_DUMPFILE == cap_mode)){
		dl_io_fun_list_static_link[cap_mode].dl_io_set_cap_level = (int (*)(int cap_level))pcap_dl_io_set_cap_level;
		dl_io_fun_list_static_link[cap_mode].dl_io_set_cap_mode = (int (*)(int cap_mode))pcap_dl_io_set_cap_mode;
		dl_io_fun_list_static_link[cap_mode].dl_io_set_topology_mode = (int (*)(int topology_mode))pcap_dl_io_set_topology_mode;
		dl_io_fun_list_static_link[cap_mode].dl_io_set_capdev_parallel = (int (*)(const char *cap_dev))pcap_dl_io_set_capdev_parallel;
		dl_io_fun_list_static_link[cap_mode].dl_io_set_capdev_serial = (int (*)(const char *up_dev, const char *down_dev))pcap_dl_io_set_capdev_serial;
		dl_io_fun_list_static_link[cap_mode].dl_io_set_capture_filter = (int (*)(const char *filter_rule))pcap_dl_io_set_capture_filter;
		dl_io_fun_list_static_link[cap_mode].dl_io_set_cap_buf_queue = (int (*)(int queue_num_max))pcap_dl_io_set_cap_buf_queue;
		dl_io_fun_list_static_link[cap_mode].dl_io_set_work_thread_num = (int (*)(int thread_num_max))pcap_dl_io_set_work_thread_num;
		dl_io_fun_list_static_link[cap_mode].dl_io_get_app_drop_num = (long (*)(int thread_num))pcap_dl_io_get_app_drop_num;
		dl_io_fun_list_static_link[cap_mode].dl_io_get_lib_drop_num = (long (*)(void))pcap_dl_io_get_lib_drop_num;
		dl_io_fun_list_static_link[cap_mode].dl_io_get_sendbuf = (unsigned char *  (*)(void *, int thread_num))pcap_dl_io_get_sendbuf;
		dl_io_fun_list_static_link[cap_mode].dl_io_free_sendbuf = (void (*)(void *, int thread_num))pcap_dl_io_free_sendbuf;
		dl_io_fun_list_static_link[cap_mode].dl_io_get_send_handle = (void * (*)(int thread_num))pcap_dl_io_get_send_handle;
		dl_io_fun_list_static_link[cap_mode].dl_io_low_level_send = (int (*)(void *, unsigned char *,int ,int , int ,int ,const raw_pkt_t *))pcap_dl_io_low_level_send;
		dl_io_fun_list_static_link[cap_mode].dl_io_raw_pkt_send = (int (*)(void *, unsigned char *,int , void *,int,unsigned char, const raw_pkt_t * ))pcap_dl_io_raw_pkt_send;	
		dl_io_fun_list_static_link[cap_mode].dl_io_init = (int (*)(int argc, char *argv[]))pcap_dl_io_init;
		dl_io_fun_list_static_link[cap_mode].dl_io_run = (void (*)(void))pcap_dl_io_run;
		dl_io_fun_list_static_link[cap_mode].dl_io_register_cb = (int (*)(PACKET_IO_CB_T fun))pcap_dl_io_register_cb;
		dl_io_fun_list_static_link[cap_mode].dl_io_register_exit_cb = (int (*)(PACKET_IO_EXIT_CB_T exit_fun))pcap_dl_io_register_exit_cb;
		dl_io_fun_list_static_link[cap_mode].dl_io_get_version = (int (*)(void))pcap_dl_io_get_version;
		dl_io_fun_list_static_link[cap_mode].dl_io_device_alias = (void * (*)(unsigned int , char *))pcap_dl_io_device_alias;
		dl_io_fun_list_static_link[cap_mode].dl_io_send_only_thread_init = NULL;
		dl_io_fun_list_static_link[cap_mode].dl_io_free_send_handle = pcap_dl_io_free_send_handle;
		dl_io_fun_list_static_link[cap_mode].dl_io_destroy = pcap_dl_io_destroy;
		dl_io_fun_list_static_link[cap_mode].dl_io_device_alias_free = pcap_dl_io_device_alias_free;
	}
#endif

#ifdef IOMODE_MARSIO
	if(CAP_MODEL_MARSIOV4 == cap_mode){
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_cap_level = (int (*)(int cap_level))marsio_dl_io_set_cap_level;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_cap_mode = (int (*)(int cap_mode))marsio_dl_io_set_cap_mode;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_topology_mode = (int (*)(int topology_mode))marsio_dl_io_set_topology_mode;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_capdev_parallel = (int (*)(const char *cap_dev))marsio_dl_io_set_capdev_parallel;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_capdev_serial = (int (*)(const char *up_dev, const char *down_dev))marsio_dl_io_set_capdev_serial;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_capture_filter = (int (*)(const char *filter_rule))marsio_dl_io_set_capture_filter;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_cap_buf_queue = (int (*)(int queue_num_max))marsio_dl_io_set_cap_buf_queue;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_set_work_thread_num = (int (*)(int thread_num_max))marsio_dl_io_set_work_thread_num;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_get_app_drop_num = (long (*)(int thread_num))marsio_dl_io_get_app_drop_num;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_get_lib_drop_num = (long (*)(void))marsio_dl_io_get_lib_drop_num;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_get_sendbuf = (unsigned char *	(*)(void *, int thread_num))marsio_dl_io_get_sendbuf;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_free_sendbuf = (void (*)(void *, int thread_num))marsio_dl_io_free_sendbuf;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_get_send_handle = (void * (*)(int thread_num))marsio_dl_io_get_send_handle;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_low_level_send = (int (*)(void *, unsigned char *,int ,int , int ,int, const raw_pkt_t *))marsio_dl_io_low_level_send;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_raw_pkt_send = (int (*)(void *, unsigned char *,int , void *,int, unsigned char, const raw_pkt_t * ))marsio_dl_io_raw_pkt_send; 
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_init = (int (*)(int argc, char *argv[]))marsio_dl_io_init;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_run = (void (*)(void))marsio_dl_io_run;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_register_cb = (int (*)(PACKET_IO_CB_T fun))marsio_dl_io_register_cb;
		//dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_register_exit_cb = (int (*)(PACKET_IO_EXIT_CB_T exit_fun))marsio_dl_io_register_exit_cb;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_get_version = (int (*)(void))marsio_dl_io_get_version;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_device_alias = (void * (*)(unsigned int , char *))marsio_dl_io_device_alias;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_send_only_thread_init = (int (*)(void))marsio_dl_io_send_only_thread_init;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_free_send_handle = NULL;
		dl_io_fun_list_static_link[CAP_MODEL_MARSIOV4].dl_io_destroy = NULL;
	}
#endif 

#ifdef IOMODE_PAG
	if(CAP_MODEL_PAG == cap_mode){
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_cap_level = (int (*)(int cap_level))pag_dl_io_set_cap_level;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_cap_mode = (int (*)(int cap_mode))pag_dl_io_set_cap_mode;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_topology_mode = (int (*)(int topology_mode))pag_dl_io_set_topology_mode;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_capdev_parallel = (int (*)(const char *cap_dev))pag_dl_io_set_capdev_parallel;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_capdev_serial = (int (*)(const char *up_dev, const char *down_dev))pag_dl_io_set_capdev_serial;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_capture_filter = (int (*)(const char *filter_rule))pag_dl_io_set_capture_filter;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_cap_buf_queue = (int (*)(int queue_num_max))pag_dl_io_set_cap_buf_queue;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_set_work_thread_num = (int (*)(int thread_num_max))pag_dl_io_set_work_thread_num;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_get_app_drop_num = (long (*)(int thread_num))pag_dl_io_get_app_drop_num;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_get_lib_drop_num = (long (*)(void))pag_dl_io_get_lib_drop_num;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_get_sendbuf = (unsigned char * (*)(void *, int thread_num))pag_dl_io_get_sendbuf;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_free_sendbuf = (void (*)(void *, int thread_num))pag_dl_io_free_sendbuf;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_get_send_handle = (void * (*)(int thread_num))pag_dl_io_get_send_handle;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_low_level_send = (int (*)(void *, unsigned char *,int ,int , int ,int ))pag_dl_io_low_level_send;
		//dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_raw_pkt_send = (int (*)(void *, unsigned char *,int , void *,int ))pag_dl_io_raw_pkt_send; 
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_init = (int (*)(int argc, char *argv[]))pag_dl_io_init;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_run = (void (*)(void))pag_dl_io_run;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_register_cb = (int (*)(PACKET_IO_CB_T fun))pag_dl_io_register_cb;
		//dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_register_exit_cb = (int (*)(PACKET_IO_EXIT_CB_T exit_fun))pag_dl_io_register_exit_cb;
		dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_get_version = (int (*)(void))pag_dl_io_get_version;
		//dl_io_fun_list_static_link[CAP_MODEL_PAG].dl_io_device_alias = (void * (*)(unsigned int , char *))pag_dl_io_device_alias;
	}
#endif 

#ifdef IOMODE_TUN
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_cap_level = (int (*)(int cap_level))tun_dl_io_set_cap_level;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_cap_mode = (int (*)(int cap_mode))tun_dl_io_set_cap_mode;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_topology_mode = (int (*)(int topology_mode))tun_dl_io_set_topology_mode;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_capdev_parallel = (int (*)(const char *cap_dev))tun_dl_io_set_capdev_parallel;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_capdev_serial = (int (*)(const char *up_dev, const char *down_dev))tun_dl_io_set_capdev_serial;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_capture_filter = (int (*)(const char *filter_rule))tun_dl_io_set_capture_filter;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_cap_buf_queue = (int (*)(int queue_num_max))tun_dl_io_set_cap_buf_queue;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_set_work_thread_num = (int (*)(int thread_num_max))tun_dl_io_set_work_thread_num;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_get_app_drop_num = (long (*)(int thread_num))tun_dl_io_get_app_drop_num;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_get_lib_drop_num = (long (*)(void))tun_dl_io_get_lib_drop_num;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_get_sendbuf = (unsigned char * (*)(void *, int thread_num))tun_dl_io_get_sendbuf;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_free_sendbuf = (void (*)(void *, int thread_num))tun_dl_io_free_sendbuf;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_get_send_handle = (void * (*)(int thread_num))tun_dl_io_get_send_handle;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_low_level_send = (int (*)(void *, unsigned char *,int ,int , int ,int ))tun_dl_io_low_level_send;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_raw_pkt_send = (int (*)(void *, unsigned char *,int , void *,int ))0; 
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_init = (int (*)(int argc, char *argv[]))tun_dl_io_init;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_run = (void (*)(void))tun_dl_io_run;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_register_cb = (int (*)(PACKET_IO_CB_T fun))tun_dl_io_register_cb;
		//dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_register_exit_cb = (int (*)(PACKET_IO_EXIT_CB_T exit_fun))pag_dl_io_register_exit_cb;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_get_version = (int (*)(void))tun_dl_io_get_version;
		dl_io_fun_list_static_link[CAP_MODEL_TUN].dl_io_device_alias = (void * (*)(unsigned int , char *))tun_dl_io_device_alias;
#endif 


	if((cap_mode != CAP_MODEL_PCAP_ONLINE)
	  && (cap_mode != CAP_MODEL_PCAP_DUMPFILE)
	  && (cap_mode != CAP_MODEL_MARSIOV4)
	  && (cap_mode != CAP_MODEL_PAG)
	  && (cap_mode != CAP_MODEL_TUN)){
		abort(); /* only support these mode static link yet! */
	}

	memcpy(&dl_io_fun_list, &dl_io_fun_list_static_link[cap_mode], sizeof(dl_io_fun_list_t));

	return 0;
}
#endif

void * get_dl_io_device_alias_fun_symbol(void)
{
	void * (*tmp_device_alias_fun)(unsigned int target_id, char *device_args);
	
#if LINK_MODE_DYNAMIC
	void *dl_handle;
	char lib_path[256];

	snprintf(lib_path, 256, "%s/%s", "platform_lib", g_dl_io_lib_info[g_packet_io_cap_mode].lib_name);

	dl_handle = dlopen(lib_path, RTLD_NOW);
	if(NULL == dl_handle){
		printf("\033[41m[Error]dlopen %s error!\033[0m\n", lib_path);
		return NULL;
	}

	tmp_device_alias_fun = (void *(*)(unsigned int, char *))dlsym(dl_handle, "dl_io_device_alias");
	if(NULL == tmp_device_alias_fun){
		printf("\033[41m[Error]dlsym %s from %s error!\033[0m\n", "dl_io_device_alias", lib_path);
		return NULL;
	}
#else
	tmp_device_alias_fun = NULL;
#endif

	return (void *)tmp_device_alias_fun;
}


/* 
	(0:pag,1:pcap,2:dumpfile,3:pfring,4:DPDK,5:ppf,6:NPacket,7:qnf,8:N95,9:pcap-dumpfile-list,10:topsec,
	(11:ipfile, 12:marsio4, 13:agent_smith, 14:dpdk_vxlan, 15:marsio_vxlan.  
*/
int packet_io_lib_load(int cap_mode)
{
#if LINK_MODE_DYNAMIC
	int dl_io_lib_ver;
#endif

	const char *lib_name;
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
	__print_err_msg((void *)dl_io_fun_list.dl_io_free_send_handle, full_lib_path, "dl_io_free_send_handle");
	__print_err_msg((void *)dl_io_fun_list.dl_io_destroy, full_lib_path, "dl_io_destroy");

#if LINK_MODE_DYNAMIC
	if(dl_io_fun_list.dl_io_get_version != NULL){
		dl_io_lib_ver = dl_io_fun_list.dl_io_get_version();
		if(dl_io_lib_ver != sapp_packet_io_v){
			printf("\033[33m[Warning]packet_io lib: '%s' version is different with platform!!\033[0m\n", full_lib_path);
			printf("\033[33mPlease copy newest packet_io library to './platform_lib/'\033[0m\n");

			/* 可能某些情况下需要新旧几个版本对比测试, 应该允许不一样的版本运行, 但要打印警告提示 */
			sapp_usleep(1000*100);
			printf("\033[33m[Warning]Run anyway, are you sure? \033[0m\n");
			sapp_usleep(1000*500);
			printf("\033[33m[Warning]Run anyway, are you sure??? \033[0m\n");	
			sleep(1);
			printf("\033[33m[Warning]Run anyway, are you sure????? \033[0m\n");
			sleep(2);	
			printf("\033[33m[Warning]Run anyway, platform action is unpredictable!\033[0m\n");			
		}
	}
#endif	

	///g_packet_io_cap_mode = cap_mode;

	return 0;
}


#ifdef __cplusplus
}
#endif

