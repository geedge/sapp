#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"

#include "libping.h"

int wangyan_keepalive_plug_version_VERSION_20180428;

#define WANGYAN_PLUG_NUM_MAX			(64)

#define SELF_DEBUG 						(0) /* 无总控的条件下自测试 */

#if SELF_DEBUG
stPlugRuntimeInfo plugctrl_runtime_info;
int wy_steward_plugin_id_get(void)
{
	return 0;
}
stPlugBaseInfo wkp_g_plug_base_info[WANGYAN_PLUG_NUM_MAX];
#else
/* 依赖于其他插件的变量, 在master中使用, slave不用, 但slave中无法找到相关符号名, 也不想编译两个版本, 动态获取 */
extern stPlugRuntimeInfo plugctrl_runtime_info; /* 平台符号, 用于检测死锁和单包处理延时, 直接引用 */
extern int wy_steward_plugin_id_get(void); /* 总控返回插件id函数 */
static stPlugBaseInfo *wkp_g_plug_base_info; 
#endif

static ping_handle g_wkp_ping_handle;
static const int g_wkp_ping_pair = 0x77616e67; /* 'wang'的16进制编码 */

/*
	使用符号名检察的方式, dl_iterate_phdr(dl_iterate_callback, &ret);
	动态获取函数指针, 如果是从应用则不调用gdev_set_opt.
*/
static int (* wkp_gdev_keepalive_set_opt)(const SAPP_TLV_T *tlv_value);


/*
[main]
mode=master
begin_listen_port=60000       //起始端口为60000, 本地绑定源端口为60000, 如果2号插件, 则对方接收端口为60002.
slave_plug_id_list=1,2,23,34,45
*/

#define WANGYAN_KEEPALIVE_MODE_MASTER 		1
#define WANGYAN_KEEPALIVE_MODE_SLAVE 			2

#define WANGYAN_KEEPALIVE_MAGIC				(0x474E4157) /* "WANG"字符串的16进制 */


#ifndef WKP_MAX
#define WKPMAX(a, b)  	(((a) > (b)) ? (a) : (b))
#endif

enum plug_abnormal_t{
	PLUG_ABNORMAL_DEADLOCK = 1,
	PLUG_ABNORMAL_TIMEDELAY,
	PLUG_ABNORMAL_IOBUF_FULL,
};

typedef struct{
	unsigned int magic;
	unsigned char local_id; /* 用于标识本端的id, 对于WANGYAN项目来说, 即插件id */
	unsigned char msg_type; /* 0:reply; 8:echo, 复用ICMP协议字段号 */
	unsigned char version; /* 目前为1 */
	unsigned char seq_num; /* 从0开始, 累计 */
}wangyan_keepalive_comm_t; /* 保活通信接口 */

typedef struct{
	int plug_id;
	int plug_keepalive_state; /* 1:正常保活; 0:异常状态 */
	//struct sockaddr_in sock_addr;
	//unsigned long long last_rcv_reply_timestamp;
	//time_t last_recv_time_sec;
	//unsigned long long total_snd_keepalive_pkt_num;
	//unsigned long long total_rcv_keepalive_pkt_num;
	time_t last_log_time; /* 上一次记录日志的时间, 避免刷硬盘 */
	volatile int plug_exclusivity; /* 插件独占性开启, 如果此插件不保活, 整机不再和gdev保活, 会动态更新 */
	//unsigned char seq_num;
	//char __pad[59];
}wangyan_keepalive_state_t; /* 保活状态记录 */

static unsigned short g_begin_listen_port = 60000; /* 主机序, host order, 便于根据插件ID增减范围 */

static int g_wangyan_keepalive_mode = WANGYAN_KEEPALIVE_MODE_SLAVE; /* 默认从模式, 防止没有配置文件导致以主模式运行, 都发送主动探测包 */

static unsigned long long g_wkp_time_increase  = 1; /* 连续递增的时间戳, 用于探测保活超时, 从1开始大概每隔50ms递增1 */
static time_t g_wkp_cur_time; /* 当前绝对时间的秒数, master和slave在不同流程各自更新 */

static wangyan_keepalive_state_t g_wangyan_keepalive_state[WANGYAN_PLUG_NUM_MAX]; /* 从应用插件地址表 */

static volatile int g_wkp_slave_abnormal_flag = 0; /* 从应用异常标记, 比如死锁, 单包处理延时过长等 */

static int g_wkp_slave_local_plug_id = -1; /* 从应用运行的插件ID */

static void *g_wkp_log_handle;

extern time_t g_CurrentTime;
extern int get_thread_count(void);

static char *wkp_timet_to_str(time_t timet, char *time_str, int time_str_len)
{
    struct tm *now;

    if(NULL == time_str || time_str_len <= (int)strlen("YY-MM-DD HH:MM:SS"))
    {
        return (char *)"1970-01-01 error"; /* error! */
    }	

    now = localtime(&timet);
    strftime(time_str, time_str_len, "%Y-%m-%d %H:%M:%S", now);

    return time_str;
}


static int wkp_slave_check_plug_deadlock(void)
{
	int i, tot_thread_count;
	int call_times[MAX_THREAD_NUM];
	static int last_check_flag = 0; /* 单数记录当前的callentry值, 双数用记录值和当前值比较 */
	static int last_check_time;
	static int record_deadlock_flag = 0;

	/* NOTE: 外部线程还有实时更新时间戳, 不易在本函数中使用sleep()函数, 所以使用标志位记录+异步检测 */
	
	tot_thread_count = get_thread_count();

	if(0 == last_check_flag){
		for(i = 0; i < tot_thread_count; i++){
			call_times[i] = plugctrl_runtime_info.callentry_num[i];
		}
		last_check_flag = 1;
		last_check_time = g_wkp_time_increase;
	}else{
		if(g_wkp_time_increase - last_check_time > 20){/* 相隔1秒左右, 再次检测之前保存的值和plugctrl_runtime_info实时值是否一样 */		
			for(i = 0; i < tot_thread_count; i++){
				if((call_times[i] == plugctrl_runtime_info.callentry_num[i])
				 && (plugctrl_runtime_info.callentry_num[i] & 1)){ /* callentry是单数, 说明正在插件调用栈中, 长时间不变即是死锁 */
					last_check_flag = 0;
					record_deadlock_flag = 1;
					return record_deadlock_flag;
				}
			}
			record_deadlock_flag = 0; /* 恢复正常值 */
			last_check_flag = 0;
		}
	}
	
	return record_deadlock_flag;
}

static int wkp_slave_check_plug_timedelay(void)
{
	int i, tot_thread_count;
	tot_thread_count = get_thread_count();

	for(i = 0; i < tot_thread_count; i++){
		if(plugctrl_runtime_info.interval_num[i] > 30){ /* 插件管理记录最多60次超过1ms的调用记录 */
			return 1;
		}
	}

	return 0;
}

static int wkp_slave_check_plug_iobuf(void)
{
#if IOMODE_MARSIO
	/* TODO */
#endif

	return 0;
}


static const char *wkp_abnormal_state_to_string(int type)
{
	const char *res = "";
	
	switch(type){
		case PLUG_ABNORMAL_DEADLOCK:
			res = "deadlock";
		break;
		
		case PLUG_ABNORMAL_TIMEDELAY:
			res = "pkt process too slow";
		break;
		
		case PLUG_ABNORMAL_IOBUF_FULL:
			res = "I/O buf full";
		break;

		default:
		break;
	}

	return res;
}


/* 用于检查当前进程是否死锁, 包处理延时太长, IO缓存满等异常情况 */
static void *wkp_slave_check_plug_state_thread(void *arg)
{
	int res = 0;
	int res_type;
	static int log_last_slave_state = 0;
	
	while(1){
		res = 0;
		g_wkp_cur_time = time(NULL);

		res = wkp_slave_check_plug_deadlock();
		res_type = PLUG_ABNORMAL_DEADLOCK;
		if(res != 0){            
			goto do_log; /* 一票否决制, 只要有一项检测错误, 就可以写日志了, 无需检测其他错误 */
		}
	
		res = wkp_slave_check_plug_timedelay();
		res_type = PLUG_ABNORMAL_TIMEDELAY;
		if(res != 0){
			goto do_log; /* 一票否决制, 只要有一项检测错误, 就可以写日志了, 无需检测其他错误 */
		}
		
		res = wkp_slave_check_plug_iobuf();
		res_type = PLUG_ABNORMAL_IOBUF_FULL;

do_log:
		if(res != 0){
			g_wkp_slave_abnormal_flag = 1;
			if(log_last_slave_state != g_wkp_slave_abnormal_flag){/* 有状态切换时才写日志, 否则会写无数条错误日志 */
				MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "plug_id %d, because %s into abnormal status!",
										g_wkp_slave_local_plug_id, 
										wkp_abnormal_state_to_string(res_type)); 
			}
		}else{
			g_wkp_slave_abnormal_flag = 0;
			if(log_last_slave_state != g_wkp_slave_abnormal_flag){/* 有状态切换时才写日志, 否则会写无数条错误日志 */
				MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "plug_id %d, into normal status!",
										g_wkp_slave_local_plug_id);
			}
		}

		log_last_slave_state = g_wkp_slave_abnormal_flag;
	
		usleep(1000 * 50);
		g_wkp_time_increase++;
	}

	return NULL;
}



/* 插件的排他独占性属性可能会随时变化, 需要实时读取总控的变量更新 */
static void wkp_master_get_plug_exclusivity_stat(void)
{
	int i;

	for(i = 0; i < WANGYAN_PLUG_NUM_MAX; i++){
		g_wangyan_keepalive_state[i].plug_exclusivity = wkp_g_plug_base_info[g_wangyan_keepalive_state[i].plug_id].keepalive_flag;
	}
}

/* 告之总控, 每个从应用的保活状态 */
static int wkp_master_update_plug_state(int plug_id, int keepalive_state)
{
	assert(plug_id < WY_MAX_PLUG_NUM);

	wkp_g_plug_base_info[plug_id].keepalive_state =  keepalive_state; /* 更新总控插件的状态 */
	g_wangyan_keepalive_state[plug_id].plug_keepalive_state = keepalive_state; /* 更新本模块内插件状态 */

	return g_wangyan_keepalive_state[plug_id].plug_keepalive_state;
}


static void wkp_master_keepalive_status_log(void)
{
	static time_t last_log_time = 0;
	int ret, i, tot_alive_slave_num = 0;
	FILE *fp;
	char tmp_time_str[64];
	node_status_t node_stat;
	int node_stat_len = sizeof(node_stat);
	
	if(last_log_time < g_wkp_cur_time){
		fp = fopen("./log/wangyan_keepalive_status.log", "w+");
		if(NULL == fp){
			return;
		}

		fprintf(fp, "%8s %12s %10s %10s %6s %24s\n", "plug-id", "exclusivity", "tot-snd", "tot-rcv", "alive", "last_pkt_time");
		for(i = 0; i < WANGYAN_PLUG_NUM_MAX; i++){
			if(0 == g_wangyan_keepalive_state[i].plug_id){ /* 0 is master */
				continue;
			}
			wkp_timet_to_str(time(NULL), tmp_time_str, 64);

			node_stat.slave_id = g_wangyan_keepalive_state[i].plug_id;
			ret = libping_get_opt(g_wkp_ping_handle, PO_NODE_STATUS, &node_stat, &node_stat_len);
			if((ret < 0) || (LIBPING_STATE_KEEPALIVE_SUCC != node_stat.state)){
				continue;
			}
			
			fprintf(fp, 
					"%8d %12d %10u %10u %6d %24s\n",
					g_wangyan_keepalive_state[i].plug_id,
					g_wangyan_keepalive_state[i].plug_exclusivity,
					node_stat.send_req_pkt,
					node_stat.send_req_pkt,
					g_wangyan_keepalive_state[i].plug_keepalive_state,
					tmp_time_str);
			tot_alive_slave_num++;
		}

		if(0 == tot_alive_slave_num){
			fprintf(fp, "All slave plug are not alive!\n");
		}	
		fclose(fp);
		last_log_time = g_wkp_cur_time;
	}
}


static void wkp_master_update_gdev_keepalive_flag(void)
{
	int plug_id;
	int gdev_global_switch = 1; /* 初始为1, 如果有fd类插件, 必须全保活才激活GDEV保活;  如果无fd类插件, 有任意一个插件保活, 都激活GDEV保活 */
	SAPP_TLV_T keepalive_opt;
	int alive_plug_num = 0;
	static time_t last_log_time = 0;

	for(plug_id = 1; plug_id < WANGYAN_PLUG_NUM_MAX; plug_id++){
		if((1 == g_wangyan_keepalive_state[plug_id].plug_exclusivity) 
		  && (0 == g_wangyan_keepalive_state[plug_id].plug_keepalive_state)){
			gdev_global_switch = 0; /* 一票否决 */
			if(g_wangyan_keepalive_state[plug_id].last_log_time < g_CurrentTime){
				MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "plug id=%d is not alive, is exclusive, so disable gdev global keepalive!", plug_id);
				g_wangyan_keepalive_state[plug_id].last_log_time = g_CurrentTime;
			}
			break;
		}
		if(1 == g_wangyan_keepalive_state[plug_id].plug_keepalive_state){
			alive_plug_num++;
		}
	}

	if(0 == alive_plug_num){
		gdev_global_switch = 0;
		if(last_log_time + 5 < g_CurrentTime){
			MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "All plug is not alive, disable gdev global keepalive!");
			last_log_time = g_CurrentTime;
		}
	}

	keepalive_opt.type = GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH;
	keepalive_opt.length = sizeof(int);
	keepalive_opt.int_value = gdev_global_switch;
	if(wkp_gdev_keepalive_set_opt){
		wkp_gdev_keepalive_set_opt(&keepalive_opt);
	}

	return;
}


static void *wkp_master_check_keepalive_state_thread(void *arg)
{
	int i, ret;
	int plug_state_sum = 0;
	node_status_t node_stat;
	int node_stat_len = sizeof(node_stat);
	
	while(1){
		plug_state_sum = 0;
		for(i = 0; i < WANGYAN_PLUG_NUM_MAX; i++){
			if(g_wangyan_keepalive_state[i].plug_id == 0){
				continue;
			}

			node_stat.slave_id = g_wangyan_keepalive_state[i].plug_id;
			ret = libping_get_opt(g_wkp_ping_handle, PO_NODE_STATUS, &node_stat, &node_stat_len);
			if((ret >= 0) && (LIBPING_STATE_KEEPALIVE_SUCC == node_stat.state)){
				g_wangyan_keepalive_state[i].plug_keepalive_state = 1;
			}else{
				g_wangyan_keepalive_state[i].plug_keepalive_state = 0;
			}
			
			/* 根据本地保活状态, 更新总控插件内部的状态 */
			plug_state_sum += wkp_master_update_plug_state(g_wangyan_keepalive_state[i].plug_id, g_wangyan_keepalive_state[i].plug_keepalive_state);
		}	

		wkp_master_update_gdev_keepalive_flag();

		wkp_master_get_plug_exclusivity_stat();

		wkp_master_keepalive_status_log();

		g_wkp_cur_time = time(NULL);
		usleep(1000 * 100);
	}

	return NULL;
}


struct wkp_check_dl{
	int exist_flag;
	const char *dl_name;
};
#if (0 == SELF_DEBUG)
static int wkp_dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *cb_arg)
{
	int len1, len2;
	struct wkp_check_dl *user_arg = (struct wkp_check_dl *)cb_arg;
	
	if((NULL == info->dlpi_name) || ('\0' == info->dlpi_name[0])){
		return 0;
	}

	len1 = strlen(basename(info->dlpi_name)); /* 一般都含路径, 要用basename() */
	len2 = strlen(user_arg->dl_name);
	if(strncasecmp(basename(info->dlpi_name), user_arg->dl_name, WKPMAX(len1, len2)) == 0){
		user_arg->exist_flag++; /* 在循环cb的栈内, 靠累计值表示有无 */
		return 1;
	}

	return 0;
}


static int wkp_search_dl(const char *name)
{
	struct wkp_check_dl user_arg;

	user_arg.dl_name = name;
	user_arg.exist_flag = 0;
	
	dl_iterate_phdr(wkp_dl_iterate_callback, &user_arg);

	return user_arg.exist_flag;
}
#endif

/* 本插件依赖的.so必须先挂载 */
static int wkp_plug_master_check_depend_plug(void)
{
#if (0 == SELF_DEBUG)
	if(wkp_search_dl("g_device_plug.so") <= 0){
		printf("\033[41m[wangyan_keepalive] error, in master mode, but no '%s' plug load!\033[0m\n", "g_device_plug.so");
		MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "error, in master mode, but no '%s' plug load!", "g_device_plug.so");		
		return -1;
	}

	if(wkp_search_dl("steward_wy.so") <= 0){
		printf("\033[41m[wangyan_keepalive] error, in master mode, but no '%s' plug load!\033[0m\n", "steward_wy.so");
		MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "error, in master mode, but no '%s' plug load!", "steward_wy.so");	
		return -1;
	}
#endif

	wy_steward_plugin_id_get(); 

	return 0;
}


static int wkp_plug_master_get_depend_plug_symbol(void)
{
#if (0 == SELF_DEBUG)
	void *dl_handle_gdev;
	void *dl_handle_wy_master;

	dl_handle_gdev = dlopen("./plug/platform/g_device_plug/g_device_plug.so", RTLD_NOW);
	if(NULL == dl_handle_gdev){
		printf("\033[41m[wangyan_keepalive] dlopen '%s' error!\033[0m\n", "./plug/platform/g_device_plug/g_device_plug.so");
		MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "dlopen '%s' error!", "./plug/platform/g_device_plug/g_device_plug.so");	
		return -1;
	}

	wkp_gdev_keepalive_set_opt = (int (* )(const SAPP_TLV_T *))dlsym(dl_handle_gdev, "gdev_keepalive_set_opt");
	if(NULL == wkp_gdev_keepalive_set_opt){
		printf("\033[41m[wangyan_keepalive] dlsym '%s' error!\033[0m\n", "gdev_keepalive_set_opt");
		MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "dlsym '%s' error!", "gdev_keepalive_set_opt");	
		return -1;
	}	

	dl_handle_wy_master = dlopen("./plug/platform/steward_wy/steward_wy.so", RTLD_NOW);
	if(NULL == dl_handle_wy_master){
		printf("\033[41m[wangyan_keepalive] dlopen '%s' error!\033[0m\n", "./plug/platform/steward_wy/steward_wy.so");
		MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "dlopen '%s' error!", "./plug/platform/steward_wy/steward_wy.so");	
		return -1;
	}

	wkp_g_plug_base_info = (stPlugBaseInfo *)dlsym(dl_handle_wy_master, "g_plug_base_info");
	if(NULL == wkp_g_plug_base_info){
		printf("\033[41m[wangyan_keepalive] dlsym '%s' error!\033[0m\n", "g_plug_base_info");
		MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "dlsym '%s' error!", "g_plug_base_info");	
		return -1;
	}		
#endif

	return 0;
}

static int wangyan_keepalive_plug_master_init(void)
{
	int tmp_plug_id;
	short opt_short;
	int master_ip_net = 0x0100007f;
	
	if(wkp_plug_master_check_depend_plug() < 0){
		return -1;
	}

	if(wkp_plug_master_get_depend_plug_symbol() < 0){
		return -1;
	}
	for(tmp_plug_id = 0; tmp_plug_id < WANGYAN_PLUG_NUM_MAX; tmp_plug_id++){
		g_wangyan_keepalive_state[tmp_plug_id].plug_id = tmp_plug_id;
		g_wangyan_keepalive_state[tmp_plug_id].plug_keepalive_state = 0; /* 初始状态不保活 */
		g_wangyan_keepalive_state[tmp_plug_id].plug_exclusivity = 0;
	}

	g_wkp_ping_handle = libping_create();
	libping_set_opt(g_wkp_ping_handle, PO_PAIR_TAG, (void *)&g_wkp_ping_pair, sizeof(int));	
	opt_short = LIBPING_WORK_MODE_MASTER;
	libping_set_opt(g_wkp_ping_handle, PO_WORK_MODE, &opt_short, sizeof(short));
	libping_set_opt(g_wkp_ping_handle, PO_SLAVE_ID, (void *)&g_wkp_slave_local_plug_id, sizeof(int));

	libping_set_opt(g_wkp_ping_handle, PO_MASTER_IP_NET_ORDER, (void *)&master_ip_net, sizeof(int));
	g_begin_listen_port = htons(g_begin_listen_port);
	libping_set_opt(g_wkp_ping_handle, PO_MASTER_PORT_NET_ORDER, (void *)&g_begin_listen_port, sizeof(short));
	
	
	libping_run(g_wkp_ping_handle);
	
	MESA_handle_runtime_log(g_wkp_log_handle, 10, "wangyan_keepalive", "master init SUCC");

	return 0;
}

static int wangyan_keepalive_slave_replay_cb_fun(ping_handle ph, unsigned int pair_tag, unsigned int slave_id)
{
	if(0 == g_wkp_slave_abnormal_flag){
		return 1;
	}

	return 0;
}

static int wangyan_keepalive_plug_slave_init(void)
{
	int master_ip_net = 0x0100007f;
	short opt_short;
	int tmp_plug_id;

	/* 不再每个从应用都配置各自的ID, 总控肯定已经知道当前插件id, 直接调用即可, 减少配置文件数量 */
	tmp_plug_id = wy_steward_plugin_id_get();
	g_wkp_slave_local_plug_id = tmp_plug_id;

	g_wkp_ping_handle = libping_create();
	libping_set_opt(g_wkp_ping_handle, PO_PAIR_TAG, (void *)&g_wkp_ping_pair, sizeof(int));	
	opt_short = LIBPING_WORK_MODE_SLAVE;
	libping_set_opt(g_wkp_ping_handle, PO_WORK_MODE, (void *)&opt_short, sizeof(short));
	libping_set_opt(g_wkp_ping_handle, PO_SLAVE_ID, (void *)&g_wkp_slave_local_plug_id, sizeof(int));

	libping_set_opt(g_wkp_ping_handle, PO_SLAVE_PRE_REPLAY_CB, (void *)&wangyan_keepalive_slave_replay_cb_fun, sizeof(void *));

	libping_set_opt(g_wkp_ping_handle, PO_MASTER_IP_NET_ORDER, (void *)&master_ip_net, sizeof(int));
	g_begin_listen_port = htons(g_begin_listen_port);
	libping_set_opt(g_wkp_ping_handle, PO_MASTER_PORT_NET_ORDER, (void *)&g_begin_listen_port, sizeof(short));
	
	libping_run(g_wkp_ping_handle);
	
	MESA_handle_runtime_log(g_wkp_log_handle, 10, "wangyan_keepalive", "slave init SUCC");
	
	return 0;
}


#if (0 == SELF_DEBUG)
static void wangyan_gdev_keepalive_depend_service_set(int service_num)
{
	SAPP_TLV_T keepalive_opt;
	
	keepalive_opt.type = GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH;
	keepalive_opt.length = sizeof(int);
	keepalive_opt.int_value = 0;
	wkp_gdev_keepalive_set_opt(&keepalive_opt);		

	struct gdev_keepalive_service_ctrl service_opt;
	service_opt.keepalive_switch = 1;
	service_opt.service_num = service_num;
	keepalive_opt.type = GDEV_KEEPALIVE_OPT_SERVICE_CTRL;
	keepalive_opt.length = sizeof(service_opt);
	keepalive_opt.ptr_value =  &service_opt;
	wkp_gdev_keepalive_set_opt(&keepalive_opt);	

	MESA_handle_runtime_log(g_wkp_log_handle, 10, "wangyan_keepalive", "set gdev keepalive service num: %d", service_num);

	return;
}
#endif

/*
	同时支持逗号分隔的多个业务号.
*/
#if (0 == SELF_DEBUG)
static int wangyan_gdev_keepalive_init(char *servie_num_list)
{
	const char *delim = "\t ,";
	char *saveptr = NULL;
	char *section;
	int tmp_int_num;
	char *parse_config_str = servie_num_list;

	while((section = strtok_r(parse_config_str, delim, &saveptr))){
		tmp_int_num = atoi(section);
		if((tmp_int_num > 0) && (tmp_int_num < 255)){
			wangyan_gdev_keepalive_depend_service_set(tmp_int_num);
		}
		parse_config_str = NULL;
	}

	return 0;
}
#endif

/* 便于dpdk驱动查看当前进程的流量信息, 需设置应用名, 
   因为先调用plug_proc(), 插件初始化时, packet_io还未初始化, 不能使用函数接口设置,
   packet_io_marsio.so默认从main.conf->sapp_instance_name获取,
   本模块直接修改main.conf->sapp_instance_name.
*/
static void wangyan_set_sapp_instance_name(void)
{
	char tmp_cmd_buf[256];

	/* 设置进程名 */
	if(0 == g_wkp_slave_local_plug_id){
		snprintf(tmp_cmd_buf, 256, "sed -r -i 's/app_instance_name=.*/app_instance_name=sapp_master/g' conf/main.conf ");
	}else{
		snprintf(tmp_cmd_buf, 256, "sed -r -i 's/app_instance_name=.*/app_instance_name=slave%d/g' conf/main.conf", g_wkp_slave_local_plug_id);
	}
	system(tmp_cmd_buf);

#if IOMODE_MARSIO
	/* 设置捕包网卡 */
	if(0 == g_wkp_slave_local_plug_id){
		snprintf(tmp_cmd_buf, 256, "sed -r -i 's/pcapdevice=.*/pcapdevice=vxlan_user/g' conf/main.conf");
	}else{
		snprintf(tmp_cmd_buf, 256, "sed -r -i 's/pcapdevice=.*/pcapdevice=loop%d/g' conf/main.conf", g_wkp_slave_local_plug_id);
	}
	
	system(tmp_cmd_buf);
#endif

}

int wangyan_keepalive_plug_init(void)
{
	int tmp_int, ret;
	pthread_t t_pid;
	char tmp_str[128];

#if SELF_DEBUG
	printf("\033[1;31;40m[wangyan_keepalive_plug] This is a debug version!\033[0m\n");
	sleep(3);
#endif

	/* read conf, get master, or slave */

	g_wkp_cur_time = time(NULL);

	g_wkp_log_handle = MESA_create_runtime_log_handle("./log/wangyan_keepalive.log", 0);

	g_wkp_slave_local_plug_id = wy_steward_plugin_id_get();
	if(0 == g_wkp_slave_local_plug_id){ /* 约定: id=0表示master, 其他slave从1开始编号 */
		g_wangyan_keepalive_mode = WANGYAN_KEEPALIVE_MODE_MASTER;
	}else{
		g_wangyan_keepalive_mode = WANGYAN_KEEPALIVE_MODE_SLAVE;
	}

	MESA_load_profile_int_def((char *)"./conf/wangyan_keepalive.conf", (char *)"main", (char *)"begin_listen_port", &tmp_int, 0);
	if((0 >= tmp_int) || (tmp_int > 65535)){
		printf("\033[41m[[wangyan_keepalive] error, read conf 'begin_listen_port' error!\033[0m[\n");
		MESA_handle_runtime_log(g_wkp_log_handle, 30, "wangyan_keepalive", "read conf 'begin_listen_port' error!");
		return -1;
	}
	g_begin_listen_port = (unsigned short)tmp_int;

	if(WANGYAN_KEEPALIVE_MODE_MASTER == g_wangyan_keepalive_mode){
		ret = wangyan_keepalive_plug_master_init();
		if(ret < 0){
			return -1;
		}
		pthread_create(&t_pid, NULL, wkp_master_check_keepalive_state_thread, NULL);
	}else{
		ret = wangyan_keepalive_plug_slave_init();
		if(ret < 0){
			return -1;
		}	
		pthread_create(&t_pid, NULL, wkp_slave_check_plug_state_thread, NULL);
	}

	/* 只有主应用才设置G保活相关参数, 从应用无需关心 */
	if(WANGYAN_KEEPALIVE_MODE_MASTER == g_wangyan_keepalive_mode){
		/* wangyan默认业务号: 12, 支持多个业务逗号分隔模式 */
		MESA_load_profile_string_def((char *)"./conf/wangyan_keepalive.conf", (char *)"gdev_service", (char *)"keepalive_service", tmp_str, 128, "12");

		/* NOTE: 此函数必须在wangyan_keepalive_plug_master_init之后, 因为涉及到读取g_keepalive_plug.so中的符号名 */
#if (0 == SELF_DEBUG)		
		wangyan_gdev_keepalive_init(tmp_str);	
#endif		
	}

	wangyan_set_sapp_instance_name();

	return ret;
}


#ifdef __cplusplus
}
#endif


