#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

const unsigned char MESA_art_log[] = 
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


static void dump_backtrace(int max_depth, const char *path) {
	/* 
		NOTE:
		此处一定要使用栈里的内存, 调用malloc可能会调用锁, 
		在中断处理函数中调用锁可能和其他处理线程冲突, 导致整个进程死锁!!!!
	*/
	static char stack_trace[65536];
	
	int stack_depth = backtrace((void **)stack_trace, max_depth);
	int fp = open(path, O_APPEND|O_RDWR|O_CREAT, 0444);
	if(fp < 0)return;
	time_t t = time(NULL);
	char time_str[64];
	ctime_r(&t, time_str);
	const char *spilt_str = "---------------------------------------------------";
	write(fp, spilt_str, strlen(spilt_str));	
	write(fp, time_str, strlen(time_str));	
	backtrace_symbols_fd((void **)stack_trace, stack_depth, fp);
	close(fp);
	return;
}

static void signal_handler(int signo)
{
	time_t last_time = time(NULL);
	
	while(time(NULL) < last_time + 10); /* wait 10 second, for DPDK IO module detect this process is not running */
	signal(signo, SIG_DFL);
	//dump_backtrace(128, "./sapp_bt.log");	
	kill(getpid(), signo);
}

static void signal_take_over(void)
{
	if(0 == sapp_global_single.signal_take_over_sw){
		return;
	}
	
	signal(SIGABRT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGBUS, signal_handler);
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

int main(int argc, char *argv[])
{	
	sapp_gval_init();
	sapp_set_current_state(SAPP_STATE_JUST_START);
	sapp_set_current_state(SAPP_STATE_CONFIG_PARSE);
	
	if(argc >= 2){
		/* 如果有命令行参数, 先解析cla, 因为可能使用-h, -v等帮助信息       */
		if(sapp_parse_cmd_args(argc, argv) < 0){
			return -1;
		}

		sapp_parse_config();
	}else{
		sapp_parse_config();
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

	if(MESA_platform_init(argc, argv) < 0){
		exit(1);
	}

	signal_take_over();

	MESA_platform_run();

	return 0;
}


#ifdef __cplusplus
}
#endif

