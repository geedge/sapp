#include "sapp_api.h"
#include "sapp_private_api.h"


#ifdef __cplusplus
extern "C" {
#endif

static const unsigned char MESA_art_log[] = 
{
	0x50, 0x72, 0x6F, 0x64, 0x75, 0x63, 0x65, 0x64, 0x20, 0x62, 0x79, 0x0D, 0x0A, 0x20, 0x20, 0x20,
	0x20, 0x5F, 0x5F, 0x20, 0x20, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 
	0x5F, 0x5F, 0x5F, 0x20, 0x5F, 0x5F, 0x5F, 0x0D, 0x0A, 0x20, 0x20, 0x20, 0x2F, 0x20, 0x20, 0x7C, 
	0x2F, 0x20, 0x20, 0x2F, 0x20, 0x5F, 0x5F, 0x5F, 0x5F, 0x2F, 0x20, 0x5F, 0x5F, 0x5F, 0x2F, 0x2F, 
	0x20, 0x20, 0x20, 0x7C, 0x0D, 0x0A, 0x20, 0x20, 0x2F, 0x20, 0x2F, 0x7C, 0x5F, 0x2F, 0x20, 0x2F, 
	0x20, 0x5F, 0x5F, 0x2F, 0x20, 0x20, 0x5C, 0x5F, 0x5F, 0x20, 0x5C, 0x2F, 0x20, 0x2F, 0x7C, 0x20, 
	0x7C, 0x0D, 0x0A, 0x20, 0x2F, 0x20, 0x2F, 0x20, 0x20, 0x2F, 0x20, 0x2F, 0x20, 0x2F, 0x5F, 0x5F, 
	0x5F, 0x20, 0x5F, 0x5F, 0x5F, 0x2F, 0x20, 0x2F, 0x20, 0x5F, 0x5F, 0x5F, 0x20, 0x7C, 0x0D, 0x0A, 
	0x2F, 0x5F, 0x2F, 0x20, 0x20, 0x2F, 0x5F, 0x2F, 0x5F, 0x5F, 0x5F, 0x5F, 0x5F, 0x2F ,0x2F, 0x5F, 
	0x5F, 0x5F, 0x5F, 0x2F, 0x5F, 0x2F, 0x20, 0x20, 0x7C, 0x5F, 0x7C, 0x0D, 0x0A, 0x00/* EOF */ 
};

int MESA_platform_init(int argc, char *argv[]);
void MESA_platform_run(void);
extern int sapp_args_v;
int dpdk_init(int argc, char **argv);

/*
	这些变量不能放在sapp_global_val, 用于判断destroy进度状态的, destroy本身就是要free sapp_global_val变量的!
	0:init or done; >= 1:just doing in any thread;
*/

volatile unsigned long g_sapp_destory_env_running_state;
volatile unsigned long g_sapp_destory_env_done_state;

static volatile unsigned long g_destory_env_per_thread_running_state[MAX_THREAD_NUM];


static void signal_hup_handler(int signo)
{
	printf("SIGHUP recviced!\n");
	MESA_handle_runtime_log_reconstruction(NULL);
}


static void signal_term_handler(int signo)
{
	printf("signal_term_handler, SIGTERM recviced!\n");
	sapp_global_val->individual_volatile->recv_signal_SIGTERM = 1;
}

static void signal_take_over(void)
{
	signal(SIGHUP, signal_hup_handler);
	signal(SIGTERM, signal_term_handler);
}


static void show_mesa_log(void)
{
	int i;

	for(i = 0; (i < sizeof(MESA_art_log)) && (MESA_art_log[i] != 0); i ++){
		//putchar(MESA_log[i]);
		sapp_printf("%c", MESA_art_log[i]);
	}
	sapp_printf("\n");
	sapp_runtime_log(30, "\n\n%s", MESA_art_log);	
}

/* 阻塞等待必要的线程启动完成 */
static void sapp_wait_for_required_thread_starting(void)
{
	int tseq;

	for(tseq = 0; tseq < g_packet_io_thread_num; tseq++){
		while(sapp_global_val->individual_fixed.thread_obtain_id[tseq] == 0){
			sapp_usleep(10);
		}
	}

	while(sapp_global_val->individual_fixed.thread_timer_event_id == 0){
		sapp_usleep(10);
	}
}

static unsigned long long sapp_calc_line_pps(void)
{
	int i;
	unsigned long long cur_count, pps_count;
	static unsigned long long history_count = 0;

	cur_count = 0;
	for(i=0;i<g_packet_io_thread_num;i++){
		cur_count += sapp_global_val->mthread_volatile[i]->sys_stat.count[SAPP_STAT_RCV_IPV4];
		cur_count += sapp_global_val->mthread_volatile[i]->sys_stat.count[SAPP_STAT_RCV_IPV6];
	}
	
	history_count = cur_count;
	sleep(2);

	cur_count = 0;
	for(i=0;i<g_packet_io_thread_num;i++){
		cur_count += sapp_global_val->mthread_volatile[i]->sys_stat.count[SAPP_STAT_RCV_IPV4];
		cur_count += sapp_global_val->mthread_volatile[i]->sys_stat.count[SAPP_STAT_RCV_IPV6];
	}

	pps_count = cur_count - history_count;

	return pps_count;
}

#include "stream_inc/gdev_keepalive.h"
static void sapp_graceful_exit(void)
{
	if(0 == sapp_global_val->individual_volatile->recv_signal_SIGTERM){
		return;
	}

	sapp_runtime_log(RLOG_LV_FATAL, "graceful_exit begin!");

	if((DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin)
	 && (OVERLAY_MODE_VXLAN == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin)){
		SAPP_TLV_T stop_keepalive_opt = {};
		stop_keepalive_opt.type = GDEV_KEEPALIVE_OPT_GLOBAL_SWITCH;
		stop_keepalive_opt.length = sizeof(int);
		stop_keepalive_opt.int_value = 0;
		gdev_keepalive_set_opt(&stop_keepalive_opt);
		sapp_runtime_log(RLOG_LV_FATAL, "graceful_exit, for inline and vxlan mode, stop keepalive and waiting for all packet have been processed!");
		
		/* 关闭了保活, 会有几十毫秒的延时, inline设备才会真正认为功能端不在线了, 
		   如果立刻结束进程, 很多流会丢包,
		   一直检测, 直到没有数据包为止. 
		*/
		while(sapp_calc_line_pps() != 0);
	}
	
	sapp_runtime_log(RLOG_LV_FATAL, "graceful_exit clear keepalive done, begin libsapp_destroy_env!");
	libsapp_destroy_env();
	printf("sapp_graceful_exit end, call exit() !\n");
	_exit(0);
}


static void *sapp_monitor_thread(void *args)
{
	while(sapp_get_current_state() <= SAPP_STATE_PROCESSING){
		sapp_graceful_exit();
		usleep(10000);
	}

	sapp_runtime_log(RLOG_LV_FATAL, "sapp_monitor_thread  begin libsapp_destroy_env!\n");
	libsapp_destroy_env();

	return NULL;
}


int libsapp_setup_env(int argc, char *argv[])
{
	int ret;

	MESA_ATOMIC_SET(g_sapp_destory_env_running_state, 0);
	MESA_ATOMIC_SET(g_sapp_destory_env_done_state, 0);
	memset((void *)g_destory_env_per_thread_running_state, 0, sizeof(g_destory_env_per_thread_running_state));
	
	sapp_gval_init();
	sapp_set_current_state(SAPP_STATE_JUST_START);
	sapp_set_current_state(SAPP_STATE_CONFIG_PARSE);
	
	if(argc >= 2){
		/* 如果有命令行参数, 先解析cla, 因为可能使用-h, -v等帮助信息		 */
		if(sapp_parse_cmd_args(argc, argv) < 0){
			return -1;
		}

		ret = sapp_parse_config();
	}else{
		/* 没有命令行参数, 使用默认值初始化相关路径 */
		sapp_update_main_config_file(NULL);
		sapp_get_secondary_file_path();
		sapp_update_config_root_dir(NULL);
		sapp_update_data_root_dir(NULL);
		ret = sapp_parse_config();
	}
	if(ret < 0){
		return -1;
	}

	sapp_cla_override_cfg_file();
	
	show_mesa_log();

#if SAPP_INSECTICIDE
	printf("\033[33m[Warning]This sapp is a temp version for solve confounded bug!\033[0m\n");
#endif
	
#if COMPAT_PAPP_FOR_BENCHMARK
	printf("\033[33m[Warning]This sapp is a emasculate version for compare with papp, in other word, it's papp!\033[0m\n");
	sleep(1);
#endif

	sapp_init_breakpad_mini();
	signal_take_over();
	
	if(MESA_platform_init(argc, argv) < 0){
		return -1;
	}

	MESA_platform_run();

	sapp_wait_for_required_thread_starting();

	/* 
	   所有初始化和工作线程都创建完了, 
	   让出cpu, 其他模块调用libsapp_setup_env()之后可以继续执行, 而不是被阻塞, 否则程序逻辑就很难处理.
	   dumpfile模式读包完后后自动退出, 否则一直运行,
	   或者在其他线程强行调用libsapp_destroy_env()
	 */

	pthread_t pid;
	pthread_create(&pid, NULL, sapp_monitor_thread, NULL);
	pthread_detach(pid);

	return 0;
}


static void wait_for_all_io_threads(void)
{
	int tseq;

	for(tseq = 0; tseq < g_packet_io_thread_num; tseq++){
		pthread_join(sapp_global_val->individual_fixed.thread_obtain_id[tseq], NULL);
	}

	sapp_timer_destroy(sapp_global_val->individual_fixed.sapp_standalone_timer);
}



void libsapp_destroy_env_per_thread(int tseq)
{
	if(MESA_ATOMIC_INC(g_destory_env_per_thread_running_state[tseq]) != 1){ 
		/* 初始化时是0, INC后不是1, 说明至少有另一个线程正在做destroy操作, 阻塞等待, 直到结束为止 */
		MESA_ATOMIC_DEC(g_destory_env_per_thread_running_state[tseq]);
		while(MESA_ATOMIC_READ(g_destory_env_per_thread_running_state[tseq]) != 0){
			sapp_usleep(1000);
		}
		return;
	}

	packet_io_clean_thread_context(tseq);
	MESA_ATOMIC_DEC(g_destory_env_per_thread_running_state[tseq]);
}




void libsapp_destroy_env(void)
{
	int exit_process = 0;

	/* 
		注意! 一种特殊情况: 
		sapp -d读包完毕后, 会自动调用libsapp_destroy_env(),
		但是插件也可能会在外部主动调用libsapp_destroy_env(),
		如果不做同步控制, 就double free了!!
		此处靠引用计数控制一下先后逻辑顺序.
	*/
	sapp_runtime_log(RLOG_LV_FATAL, "libsapp_destroy_env begin, try to sync exit state !");	
	if(MESA_ATOMIC_INC(g_sapp_destory_env_running_state) != 1){ 
		/* 初始化时是0, INC后不是1, 说明至少有另一个线程正在做destroy操作, 阻塞等待, 直到结束为止 */
		MESA_ATOMIC_DEC(g_sapp_destory_env_running_state);
		while(MESA_ATOMIC_READ(g_sapp_destory_env_running_state) != 0){
			sapp_usleep(1000);
		}
		return;
	}

	if(NULL == sapp_global_val){
		/* 可能已经调用过libsapp_destroy_env(), 或者libsapp_setup_env()失败了 */
		return;
	}

	if((CAP_MODEL_PCAP_DUMPFILE == g_packet_io_cap_mode)
	 && (0 == sapp_global_val->config.packet_io.not_exit_for_dumpfile_mode)){
		exit_process = 1;
	}

	sapp_runtime_log(RLOG_LV_INFO, "libsapp_destroy_env excuting, set SAPP_STATE_READY_TO_EXIT !");	
	sapp_set_current_state(SAPP_STATE_READY_TO_EXIT);

	sapp_runtime_log(RLOG_LV_INFO, "libsapp_destroy_env excuting, call packet_io_stop() !");	
	packet_io_stop();
	
	sapp_runtime_log(RLOG_LV_INFO, "libsapp_destroy_env excuting, call wait_for_all_io_threads() !");	
	wait_for_all_io_threads();
	sapp_runtime_log(RLOG_LV_INFO, "libsapp_destroy_env excuting, call packet_io_exit() !");	
	packet_io_exit();

	/* 所有资源都free了, 减去引用计数 */
	MESA_ATOMIC_DEC(g_sapp_destory_env_running_state);

	MESA_ATOMIC_SET(g_sapp_destory_env_done_state, SAPP_DESTROY_DONE_FLAG);	
	if(exit_process){
		printf("libsapp_destroy_env end, call exit() !\n");	
		exit(0);
	}	
}


#ifdef __cplusplus
}
#endif

