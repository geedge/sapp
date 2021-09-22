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

static volatile long g_destory_env_done;
static volatile long g_destory_env_per_thread_done[MAX_THREAD_NUM];


static void signal_user_handler(int signo)
{
	//time_t last_time = time(NULL);
	//while(time(NULL) < last_time + 10); /* wait 10 second, for DPDK IO module detect this process is not running */
	signal(signo, SIG_DFL);
	kill(getpid(), signo);
}

static void signal_hup_handler(int signo)
{
	printf("SIGHUP recviced!\n");
	MESA_handle_runtime_log_reconstruction(NULL);
}

static void signal_take_over(void)
{
	sapp_config_t *pconfig = &sapp_global_val->config;
	signal(SIGHUP, signal_hup_handler);
	if (0 == sapp_global_single.signal_take_over_sw && 0 == pconfig->tools.signal_handler.signal)
	{
		return;
	}

	signal(SIGUSR1, signal_user_handler);
	signal(SIGUSR2, signal_user_handler);
	//signal(pconfig->tools.signal_handler.signal, signal_handler);
}


static void show_mesa_log(void)
{
	int i;

	for(i = 0; (i < sizeof(MESA_art_log)) && (MESA_art_log[i] != 0); i ++){
		//putchar(MESA_log[i]);
		printf("%c", MESA_art_log[i]);
	}
	printf("\n");
	sapp_runtime_log(30, "\n\n%s", MESA_art_log);	
}


int libsapp_setup_env(int argc, char *argv[])
{
	int ret;
	
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

	while((SAPP_STATE_PROCESSING == sapp_global_val->individual_volatile->current_state)
	 && (sapp_global_val->config.packet_io.depolyment_mode_bin)){
		usleep(1);
	}

	return 0;
}


static void wait_for_all_io_threads(void)
{
	int tseq;

	for(tseq = 0; tseq < g_packet_io_thread_num; tseq++){
		pthread_join(sapp_global_val->individual_fixed.thread_obtain_id[tseq], NULL);
	}

	pthread_join(sapp_global_val->individual_fixed.thread_timer_event_id, NULL);
}



void libsapp_destroy_env_per_thread(int tseq)
{
	if(sapp_global_val->mthread_volatile[tseq]->destory_env_done){
		return;
	}

	sapp_global_val->mthread_volatile[tseq]->destory_env_done = 1;
	packet_io_clean_thread_context(tseq);
	sapp_global_val->mthread_volatile[tseq]->destory_env_done = 2;
}




void libsapp_destroy_env(void)
{
	/* 
		一种特殊情况: sapp -d读包完毕后, 会自动调用libsapp_destroy_env(),
		但是插件也可能会在外部主动调用libsapp_destroy_env(),
		如果不做控制, 就double free了!!
		此处靠变量控制一下先后逻辑顺序.
	*/
	if(MESA_ATOMIC_READ(sapp_global_val->individual_volatile->destory_env_done) != 0){
		while(MESA_ATOMIC_READ(sapp_global_val->individual_volatile->destory_env_done) != 2);
		return;
	}else{
		MESA_ATOMIC_SET(sapp_global_val->individual_volatile->destory_env_done, 1);
	}

	sapp_global_val->individual_volatile->destory_env_done = 1;
	sapp_set_current_state(SAPP_STATE_READY_TO_EXIT);

	wait_for_all_io_threads();
	
	packet_io_exit();

	sapp_global_val->individual_volatile->destory_env_done = 2;
}


#ifdef __cplusplus
}
#endif

