#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/types.h>			/* See NOTES */
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <stdarg.h>

#include "gtest_sapp_fun.h"


static int gtest_sapp_master_fd;
static pid_t sapp_child_pid = -1;
static int sapp_child_progress_exit_flag = 0;
static time_t sapp_child_progress_exit_time;

#if SAPP_V3
	const char *sapp_start_args[1] = {NULL};
#elif SAPP_V4
	const char *sapp_start_args[3] = {"./sapp", "--dumpfile", NULL};
	const char *sapp_online_start_args[2] = {"./sapp", NULL};
	const char *sapp_inline_start_args[2] = {"./sapp", NULL};
	const char *sapp_transparent_start_args[2] = {"./sapp", NULL};
#else
	#error ("invalid sapp version!")
#endif


/*
    convert time_t to time string like "YY-MM-DD HH:MM:SS".
*/
char *gtest_timet_to_str(time_t timet, char *time_str, int time_str_len)
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

/*
	非阻塞模�? time_ms后仍无数据包, 返回错误.
*/
ssize_t recv_with_timeout(int sockfd, void *buf, size_t len,int time_ms)
{
	int i;
	int ret = 0;
	
	for(i = 0; i < time_ms*1000; i++){
		ret = recv(sockfd, buf, len, MSG_DONTWAIT);
		if(ret < 0){
		    if((EWOULDBLOCK == errno)){
				usleep(1);
				continue;
			}else{
				break;
			}
		}else{
			break;
		}
	}

	return ret;
}


void gtest_sig_handler(int signum)
{
	pid_t child_pid;
	
	if(SIGCHLD == signum){
		if(sapp_child_pid != -1){
			child_pid = waitpid(sapp_child_pid, NULL, WNOHANG);
			if((child_pid > 0) && (child_pid == sapp_child_pid)){
				sapp_child_pid = -1;
				sapp_child_progress_exit_time = time(NULL);
				sapp_child_progress_exit_flag = 1;
				printf("recv SIGCHLD, sapp child exit, sapp_child_pid=%d\n", child_pid);
			}else{
				printf("recv SIGCHLD, no sapp progress, it's pid=%d\n", child_pid);
			}
		}else{
			printf("recv SIGCHLD, but sapp hasn't run, child_pid=%d\n", sapp_child_pid);
		}
	}
}


int gtest_if_file_exist(const char *file_name)
{
	struct stat file_stat;
	
	if(stat(file_name, &file_stat) == 0)
	{
		return 1;
	}
	return 0;
}



unsigned long gtest_get_file_length(const char *file_name)
{
	struct stat file_stat;
	
	if(stat(file_name, &file_stat) == 0)
	{
		return file_stat.st_size;
	}
	return 0;
}


int gtest_file_md5sum(const char *filename, char *md5sum_result, int result_len)
{
	FILE *cmd_res_fp;
	char file_real_md5sum[33] = {};
	char cmd_buf[128];
	int ret = 0;

	if(result_len < 33){
		md5sum_result[0] = '\0';
		return -1;
	}

	snprintf(cmd_buf, sizeof(cmd_buf), "%s %s", "md5sum", filename);

	cmd_res_fp = popen(cmd_buf, "r");
	if(NULL == cmd_res_fp){
		return -1;
	}

	fgets(file_real_md5sum, 33, cmd_res_fp);
	strcpy(md5sum_result, file_real_md5sum);

	fclose(cmd_res_fp);

	return ret;

}


int file_md5_checksum(const char *filename, const char *expect_md5sum)
{
	FILE *cmd_res_fp;
	char file_real_md5sum[33];
	char cmd_buf[1024];
	int ret = 0;

	snprintf(cmd_buf, 1024, "%s %s", "md5sum", filename);

	cmd_res_fp = popen(cmd_buf, "r");
	if(NULL == cmd_res_fp){
		return -1;
	}

	fgets(file_real_md5sum, 33, cmd_res_fp);

	if(strncasecmp(file_real_md5sum, expect_md5sum, 32) != 0){
		printf("file md5:%s, but expect md5:%s\n", file_real_md5sum, expect_md5sum);
		ret = -1;
	}

	fclose(cmd_res_fp);

	return ret;
}

/*
	验证一个文件夹内的所�?pcap文件是否符合预期.
	先遍历单个文件的所有md5�?
	然后再计算这些文件md5值的md5.
*/
int directory_md5_checksum(const char *dir_name, const char *expect_md5sum)
{
	FILE *cmd_res_fp;
	char file_real_md5sum[33];
	char cmd_buf[1024];
	int ret = 0;

	/* 不受相对路径影响, 用awk {'print $1'} 只输出文件的md5sum */
	snprintf(cmd_buf, 1024,  "md5sum %s/*.pcap | awk {'print $1'} | md5sum | awk {'print $1'}", dir_name);

	cmd_res_fp = popen(cmd_buf, "r");
	if(NULL == cmd_res_fp){
		return -1;
	}

	fgets(file_real_md5sum, 33, cmd_res_fp);

	if(strncasecmp(file_real_md5sum, expect_md5sum, 32) != 0){
		printf("all files md5:%s, but expect md5:%s\n", file_real_md5sum, expect_md5sum);
		ret = -1;
	}

	fclose(cmd_res_fp);

	return ret;
}


void set_pcap_dumpfile(const char *relative_filename)
{
	char cmd_buf[1024];

	assert(relative_filename);
	snprintf(cmd_buf, 1024, "ln -sf %s/%s dumpfile", BENCHMARK_PCAP_ROOT_DIR,relative_filename);
	system(cmd_buf);
}

/*
	生成一个空的plugin.inf头部, [ENTRY_NAME]这些在每个测试用例里自行添加.
*/
void set_default_plugin_inf(void)
{
	FILE *fp;
	
	fp = fopen("plug/business/gtest_sapp/gtest_sapp.inf", "w+");
	if(NULL == fp){
		printf("update_plugin_inf(): open %s error, %s\n", "plug/business/gtest_sapp/gtest_sapp.inf", strerror(errno));
		exit(1);
	}

	fprintf(fp, "%s", "[PLUGINFO]\nPLUGNAME=gtest\nSO_PATH=./plug/business/gtest_sapp/libgtest_sapp.so\nINIT_FUNC=gtest_sapp_slave_init\n");
	fclose(fp);

	return;
}


int update_plugin_inf(const char *entry_name, const char *fun_name)
{
	char file_buf[1024];
	FILE *fp;
	
	snprintf(file_buf, 1024, "[PLUGINFO]\nPLUGNAME=gtest\nSO_PATH=./plug/business/gtest_sapp/libgtest_sapp.so\nINIT_FUNC=gtest_sapp_slave_init\nDESTROY_FUNC=gtest_sapp_slave_destroy\n[%s]\nFUNC_FLAG=ALL\nFUNC_NAME=%s\n", entry_name, fun_name);
	fp = fopen("plug/business/gtest_sapp/gtest_sapp.inf", "w+");
	if(NULL == fp){
		printf("update_plugin_inf(): open %s error, %s\n", "plug/business/gtest_sapp/gtest_sapp.inf", strerror(errno));
		exit(1);
	}

	fprintf(fp, "%s", file_buf);

	fclose(fp);

	return 0;
}


int update_plugin_inf_with_options(const char *filepath, const char *plugname, const char *init_fun_name, 
	const char *destroy_fun_name, const char *entry_name, const char *fun_name)
{
	char file_buf[1024];
	char file_name[1024];
	char cmd_buf[1024];
	FILE *fp;

	snprintf(cmd_buf, 1024, "mkdir -p %s", filepath);
	system(cmd_buf);

	snprintf(file_name, 1024, "%s/gtest_sapp.inf", filepath);

	if(destroy_fun_name){
		snprintf(file_buf, 1024, "[PLUGINFO]\nPLUGNAME=%s\nSO_PATH=%s/libgtest_sapp.so\nINIT_FUNC=%s\nDESTROY_FUNC=%s\n\n[%s]\nFUNC_FLAG=ALL\nFUNC_NAME=%s\n", 
			 plugname, filepath, init_fun_name, destroy_fun_name, entry_name, fun_name);

	}else{
		snprintf(file_buf, 1024, "[PLUGINFO]\nPLUGNAME=%s\nSO_PATH=%s/libgtest_sapp.so\nINIT_FUNC=%s\n\n[%s]\nFUNC_FLAG=ALL\nFUNC_NAME=%s\n", 
			 plugname, filepath, init_fun_name, entry_name, fun_name);
	}		 
	fp = fopen(file_name, "w+");
	if(NULL == fp){
		printf("update_plugin_inf_with_options(): open %s error, %s\n", "plug/business/gtest_sapp/gtest_sapp.inf", strerror(errno));
		exit(1);
	}

	fprintf(fp, "%s", file_buf);

	fclose(fp);

	return 0;
}

int update_protocol_plugin_inf(const char *filepath, const char *plugname, const char *init_fun_name, 
    const char *get_plugid_fun, const char *flag_change_fun, const char *flagstate_fun, 
	const char *entry_name, const char *fun_name)
{
	char file_buf[1024];
	char file_name[1024];
	FILE *fp;

	snprintf(file_name, 1024, "%s/gtest_sapp.inf", filepath);
	
	snprintf(file_buf, 1024, "[PLUGINFO]\nPLUGNAME=%s\nSO_PATH=%s/libgtest_sapp.so\nINIT_FUNC=%s\nGETPLUGID_FUNC=%s\nFLAGCHANGE_FUNC=%s\nFLAGSTATE_FUNC=%s\n\n[%s]\nFUNC_FLAG=ALL\nFUNC_NAME=%s\n", 
			 plugname, filepath, init_fun_name,get_plugid_fun, flag_change_fun,flagstate_fun,entry_name, fun_name);
	fp = fopen(file_name, "w+");
	if(NULL == fp){
		printf("update_plugin_inf_with_options(): open %s error, %s\n", "plug/business/gtest_sapp/gtest_sapp.inf", strerror(errno));
		exit(1);
	}

	fprintf(fp, "%s", file_buf);

	fclose(fp);

	return 0;
}
	


int set_project_list_conf_default(void)
{
	FILE *fp;
#if SAPP_V3		
	fp = fopen("conf/project_list.conf", "w+");
#elif SAPP_V4
	fp = fopen("etc/project_list.conf", "w+");
#else
	abort();
#endif	

	fprintf(fp, "%s\n", "#project_name\tvalue_type\ntcp_flow_stat\tstruct\nudp_flow_stat\tstruct\ntcp_deduce_flow_stat\tstruct\n");

	fclose(fp);

	return 0;	
}

int append_project_list_conf(const char *name, const char *type)
{
	FILE *fp;
#if SAPP_V3		
	fp = fopen("conf/project_list.conf", "a+");
#elif SAPP_V4
	fp = fopen("etc/project_list.conf", "w+");
#else
	abort();
#endif	

	fprintf(fp, "%s\t%s\n", name,type);

	fclose(fp);

	return 0;	

}

int append_plugin_inf(const char *entry_name, const char *fun_name)
{
	char file_buf[1024];
	FILE *fp;
	
	snprintf(file_buf, 1024, "[%s]\nFUNC_FLAG=ALL\nFUNC_NAME=%s\n", entry_name, fun_name);
	fp = fopen("plug/business/gtest_sapp/gtest_sapp.inf", "a+");

	fprintf(fp, "%s", file_buf);

	fclose(fp);

	return 0;
}


int update_config_file(const char *filename, const char *param, const char *value)
{
	char cmd_buf[1024];
	int ret;

	snprintf(cmd_buf, 1024, "sed 's/^[ \t]*%s=.*/%s=%s/g' -i %s", param, param, value, filename);

	ret = system(cmd_buf);

	return ret;
}

/* 
	修改指定行的下一行内�?
*/
int update_config_file_by_lastline(const char *filename, const char *lastline, const char *param, const char *value)
{
	char cmd_buf[1024] = {};
	int ret;

	//snprintf(cmd_buf, 1024, "sed '0,/%s/{n;s/^%s=.*/%s=%s/;}' -i %s", lastline, param, param, value, filename);
	snprintf(cmd_buf, 1024, "sed '/%s/{n;s/%s=.*/%s=%s/;}' -i %s", lastline, param, param, value, filename);

	ret = system(cmd_buf);

	return ret;
}


/* 
	修改指定行的下面第N行内�? 因为像[packet_io.internal.interface]这种配置, 下面的name和type都需要改, 需要指定第几行.
	N表示修改lastline后的第N行内�?
*/
int update_config_file_by_lastNline(const char *filename, const char *lastline, int N, const char *param, const char *value)
{
	char cmd_buf[1024] = {};
	int ret;
	const char *sed_n_line = "n";
	

	switch(N){
		case 1:
			sed_n_line = "n";
		break;

		case 2:
			sed_n_line = "n;n";
		break;

		case 3:
			sed_n_line = "n;n;n";
		break;

		case 4:
			sed_n_line = "n;n;n;n";
		break;

		case 5:
			sed_n_line = "n;n;n;n;n";
		break;		

		default:
			printf("max support N is:%d\n", 5);
		break;
	}	

	//snprintf(cmd_buf, 1024, "sed '/%s/{%s;s/^%s=.*/%s=%s/;}' -i %s", lastline, sed_n_line, param, param, value, filename);
	snprintf(cmd_buf, 1024, "sed '/%s/{%s;s/%s=.*/%s=%s/;}' -i %s", lastline, sed_n_line, param, param, value, filename);

	ret = system(cmd_buf);

	return ret;
}


void update_conflist_inf(const char *plug_inf_path)
{
	FILE *fp;

#if SAPP_V3	
	fp = fopen("./plug/business/conflist_business.inf", "w+");
#elif SAPP_V4
	fp = fopen("./plug/conflist.inf", "w+");
	fprintf(fp, "%s\n", "[platform]");
	fprintf(fp, "%s\n", "[protocol]");
	fprintf(fp, "%s\n", "[business]");
#else
	abort();
#endif
	fprintf(fp, "%s\n", plug_inf_path);

	fclose(fp);
}

void append_conflist_inf(const char *plug_inf_path)
{
	FILE *fp;

#if SAPP_V3	
	fp = fopen("./plug/business/conflist_business.inf", "a+");
#elif SAPP_V4
	fp = fopen("./plug/conflist.inf", "a+");
#else
	abort();
#endif
	fprintf(fp, "%s\n", plug_inf_path);

	fclose(fp);
}

void append_entry_list(const char *entryname)
{
	FILE *fp;
	char cmd_buf[1024];
	char result_buf[1024] = {};
	
	snprintf(cmd_buf, sizeof(cmd_buf), "cat etc/entrylist.conf | grep %s", entryname);
	fp = popen(cmd_buf, "r");
	if(fp){
		fgets(result_buf, sizeof(result_buf), fp);
		if('\0' == result_buf[0]){
			snprintf(cmd_buf, sizeof(cmd_buf), "echo %s >> etc/entrylist.conf", entryname);
			system(cmd_buf);
		}

		pclose(fp);
	}
	
}

/* 
	在指定的[module]后面插入一�? 内容为plug_inf_path.
*/
void insert_into_conflist_inf(const char *module, const char *plug_inf_path)
{
	char sed_cmd_buf[256];
//example : sed -i '/\[protocol\]/a xxxx' ./plug/conflist.inf
#if SAPP_V3	
	assert(0); //TODO
#elif SAPP_V4
	char *sed_cmd_format = (char *)"sed -i '/\\[%s\\]/a %s' ./plug/conflist.inf";
	
	snprintf(sed_cmd_buf, 256, sed_cmd_format, module, plug_inf_path);
#else
	abort();
#endif

	system(sed_cmd_buf);
}
void set_default_asymmetric_addr_layer_conf(const char *config_value)
{
	char cmd_buf[1024];

	snprintf(cmd_buf, sizeof(cmd_buf), "echo \"%s\" > etc/asymmetric_addr_layer.conf", config_value);

	system(cmd_buf);
}

void set_default_asymmetric_presence_layer_conf(const char *config_value)
{
	char cmd_buf[1024];

	snprintf(cmd_buf, sizeof(cmd_buf), "echo \"%s\" > etc/asymmetric_presence_layer.conf", config_value);

	system(cmd_buf);
}

void set_default_stream_compare_layer_conf(const char *config_value)
{
	char cmd_buf[1024];

	snprintf(cmd_buf, sizeof(cmd_buf), "echo \"%s\" > etc/stream_compare_layer.conf", config_value);

	system(cmd_buf);
}

void set_default_vlan_flipping_conf(const char *config_value)
{
	char cmd_buf[1024];

	snprintf(cmd_buf, sizeof(cmd_buf), "echo \"%s\" > etc/vlan_flipping_map.conf", config_value);

	system(cmd_buf);
}


void set_default_well_known_port_conf(void)
{
 	system("echo [TCP] > etc/well_known_port.conf");
 	system("echo [UDP] >> etc/well_known_port.conf");
}


void set_default_config(void)
{
#if SAPP_V3
	update_config_file("conf/main.conf", "threadnum", "1");
	update_config_file("conf/main.conf", "MaxTcpStreams", "1000");
	update_config_file("conf/main.conf", "MaxUdpStreams", "1000");
	update_config_file("conf/main.conf", "LinkTimeout", "0");
	update_config_file("conf/main.conf", "UdpResetTime", "0");
	update_config_file("conf/main.conf", "capdatamodlel", "2");
	update_config_file("conf/main.conf", "pcapdevice", "dumpfile");
	update_config_file("conf/main.conf", "dumpfile_speed", "topspeed");
#elif SAPP_V4

	/* 
		16进制 字符
		0x22   "
		0x2F   /
	*/
	system(">./etc/necessary_plug_list.conf");

	update_config_file("./etc/sapp.toml", "cfg_file_sapp_log", "\\x22etc\\x2Fsapp_log.conf\\x22");
	update_config_file("./etc/sapp.toml", "cfg_file_plug_list", "\\x22plug\\x2Fconflist.inf\\x22");
	update_config_file("./etc/sapp.toml", "data_file_sysinfo_log", "\\x22sysinfo.log\\x22");

	update_config_file("./etc/sapp.toml", "BSD_packet_filter", "\\x22\\x22");
	
	update_config_file("etc/sapp.toml", "worker_threads", "1");
	update_config_file("etc/sapp.toml", "max", "1000");
	update_config_file("etc/sapp.toml", "reorder_pkt_max", "5");
	update_config_file("etc/sapp.toml", "timeout", "999");
	update_config_file("etc/sapp.toml", "interval", "1");
	update_config_file("etc/sapp.toml", "dumpfile_sleep_time_before_exit", "0");
	update_config_file("etc/sapp.toml", "watchdog_enabled", "0");
	update_config_file("etc/sapp.toml", "overlay_mode", "none");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.deployment", "mode", "mirror");
	update_config_file_by_lastline("etc/sapp.toml", "tools.pkt_dump", "enabled", "0"); /* 默认关闭捕包功能, 特殊测试用例单独打开 */
	update_config_file("etc/sapp.toml", "l2_l3_tunnel_support", "0");
	update_config_file("etc/sapp.toml", "skip_not_ip_layer_over_eth", "0");
	update_config_file_by_lastline("etc/sapp.toml", "packet_io.polling","enabled", "1");
#else
	abort();
#endif

	update_config_file("etc/sapp.toml", "auto_remedy", "0"); 
	
	/* 插件会调用exit()退�?但是sapp不允许在运行过程中调用exit, 会生成core, 此处仅用于测�? 先关闭core */
	update_config_file("etc/sapp.toml", "disable_coredump", "0");  
	update_config_file("etc/sapp.toml", "enable_breakpad", "0");

 	update_conflist_inf("./plug/business/gtest_sapp/gtest_sapp.inf");

	set_default_asymmetric_presence_layer_conf("#\n");
	set_default_asymmetric_addr_layer_conf("ethernet[*]\nvlan[*]\nvxlan[*]\nmpls[*]\ngre[*]\ngtp[*]\n\n");
 	set_default_stream_compare_layer_conf("#\n"); 

 	update_config_file("./etc/sapp.toml", "extract_linkdir_from_mac_in_mirror_mode", "\\x22\\x22");

	update_config_file("./etc/sapp.toml", "stream_bypass_enabled", "0");

	/* 设置最小间隔, sapp退出时, 调用FS_stop()可以节省时间 */
	update_config_file("./etc/sapp.toml", "interval", "1");

	update_config_file("etc/sapp.toml", "monitor_thread_enabled", "0");

	set_default_plugin_inf();
	
 	set_default_well_known_port_conf();

 	gtest_set_timeout_default_result(GTEST_SAPP_ERR);
}





void gtest_sapp_sleep(int sleep_time, const char *tips)
{
	int i;

	for(i = 0; i < sleep_time; i++){
		printf("\033[33mgtest sleep for %s, please wait......\033[0m\n", tips);
		sleep(1);
	}
}

void gtest_start_inline_env_progress(const char *prog_name, const char *pcap_filename, int timeout)
{
	pid_t pid;
	int null_fd;
	char timeout_string[32];
	char nouse_result[2048];
	const char *__argv[4] = {0};
	__argv[0] = prog_name;
	__argv[1] = pcap_filename;

	char kill_last_progress[128] = {};
	snprintf(kill_last_progress, sizeof(kill_last_progress), "killall -q -9 %s", GTEST_INLINE_PROG_NAME);
	system(kill_last_progress);

	snprintf(timeout_string, 32, "%d", timeout);
	__argv[2] = timeout_string;

	char **argv = (char **)__argv;

	/* 每次重新运行一个测试用例之�? 清空socket缓冲区上一个测试用例已经发�? 但可能没有处理的返回结果, 或者是重复发送的结果 */
	while(recv(gtest_sapp_master_fd, &nouse_result, sizeof(int), MSG_DONTWAIT) > 0){
		usleep(100);
	}

	pid = fork();	
	if(0 == pid){
		null_fd = open("/dev/null", O_CREAT | O_RDWR); /* 消除sapp刷屏信息 */
		if(null_fd > 0){
			dup2(null_fd, STDOUT_FILENO);
			dup2(null_fd, STDERR_FILENO);
		}
		execv(prog_name, argv);

		/* execv不会退出, 执行到这里肯定是个错误 */
		printf("inline mode fork and execv ./%s error!\n", prog_name);
		exit(1);	
	}else if(pid < 0){
		printf("inline_env fork error!\n");
		exit(1);
	}else{
		usleep(100000);
		/* 等inline env进程创建了tun设备, 才能启动sapp */
		while(ifconfig_device_up(GTEST_TAP_UP_DEV_NAME) < 0){
			usleep(100000);
		}
	}
}

void gtest_start_transparent_env_progress(const char *prog_name, const char *pcap_filename)
{
	pid_t pid;
	int  null_fd;
	const char *__argv[3] = {0};
	char nouse_result[2048];
	__argv[0] = prog_name;
	__argv[1] = pcap_filename;


	char kill_last_progress[128] = {};
	snprintf(kill_last_progress, sizeof(kill_last_progress), "killall -q -9 %s", GTEST_TRANSPARENT_PROG_NAME);
	system(kill_last_progress);	
	
	char **argv = (char **)__argv;

 	/* 每次重新运行一个测试用例之�? 清空socket缓冲区上一个测试用例已经发�? 但可能没有处理的返回结果, 或者是重复发送的结果 */
	while(recv(gtest_sapp_master_fd, &nouse_result, sizeof(int), MSG_DONTWAIT) > 0){	
		usleep(100);
	}
	
	pid = fork();
	if(0 == pid){
		null_fd = open("/dev/null", O_CREAT | O_RDWR); /* 消除sapp刷屏信息 */
		if(null_fd > 0){
			dup2(null_fd, STDOUT_FILENO);
			dup2(null_fd, STDERR_FILENO);
		}
		execv(prog_name, argv);

		/* execv不会退出, 执行到这里肯定是个错误 */
		printf("transparent mode fork and execv ./%s error!\n", prog_name);
		exit(1);		
	}else if(pid < 0){
		printf("transparent_env fork error!\n");
		exit(1);
	}else{
		usleep(10000);
		/* 等transparent env进程创建了双向的tun设备, 才能启动sapp */
		while(ifconfig_device_up(GTEST_TAP_UP_DEV_NAME) < 0){
			usleep(100000);
		}
		while(ifconfig_device_up(GTEST_TAP_DOWN_DEV_NAME) < 0){
			usleep(100000);
		}
		printf("transparent_env start tap device succ!\n");
	}
}


void gtest_start_sapp_progress(const char *user_argv[])
{
	pid_t pid;
	int nouse_result;
	const char *__null_argv[1] = {0};
	char **argv;

	/* 每次重新运行一个测试用例之�? 清空socket缓冲区上一个测试用例已经发�? 但可能没有处理的返回结果, 或者是重复发送的结果 */
	while(recv(gtest_sapp_master_fd, &nouse_result, sizeof(int), MSG_DONTWAIT) > 0){
		usleep(100);
	}

	system("killall -9 -q sapp");
	system("> sysinfo.log");

	if(NULL == user_argv[0]){
		argv = (char **)__null_argv;
	}else{
		argv = (char **)user_argv;
	}

	sapp_child_progress_exit_flag = 0;
	sapp_child_progress_exit_time = 0;
	sapp_child_pid = -1;
 	
	pid = fork();
	if(0 == pid){
		//null_fd = open("/dev/null", O_CREAT | O_RDWR); /* 消除sapp刷屏信息 */
		//if(null_fd > 0){
		//	dup2(null_fd, STDOUT_FILENO);
		//	dup2(null_fd, STDERR_FILENO);
		//}
		execv("./sapp", argv);

		exit(1);
	}else if(pid < 0){
		printf("vfork error!\n");
		exit(1);
	}else{
		sapp_child_pid = pid;
		while(sapp_child_pid == waitpid(sapp_child_pid, NULL, 0)); /* 等待sapp子进程退�?*/
		sapp_child_pid = -1;
		sapp_child_progress_exit_time = time(NULL);
		sapp_child_progress_exit_flag = 1;
	}
}


static int g_timeout_default_res = GTEST_SAPP_ERR; /* 超时没有结果�? 默认的返回�?*/
int gtest_set_timeout_default_result(int res_value)
{
	g_timeout_default_res = res_value;
	return 0;
}

int gtest_get_timeout_default_result()
{
	return  g_timeout_default_res;
}

int check_test_result(void)
{
	ssize_t ret;
	int chk_res = -1;

	while((sapp_child_progress_exit_flag == 0)  /* sapp进程还未退�?*/
	    || (sapp_child_progress_exit_time + 5 >= time(NULL))){ /* sapp进程刚刚退�? 还未及时收取结果反馈消息, 多等几秒 */
		ret = recv(gtest_sapp_master_fd, &chk_res, sizeof(int), MSG_DONTWAIT);
		if(ret < 0){
			if(EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno){
				usleep(1000); /* 非阻塞模�? 继续重试 */
				continue;
			}else{
				printf("socket recv error, errno=%d!\n", errno);
				chk_res = -1;
				return -1;
			}
		}else{
			//gtest_write_log("recv check result:0x%x, ret=%d\n\n", chk_res, ret);
			return chk_res; /* 收到结果反馈消息 */
		}

		usleep(100);
	}

	if((sapp_child_progress_exit_time + 5 < time(NULL))){
		printf("recv check result timeout! use default result:0x%x\n", g_timeout_default_res);
		chk_res = g_timeout_default_res;
	}
	
	return chk_res;
}

int gtest_sapp_master_init(void)
{
	int ret;
	
#if (1 == GTEST_SAPP_COMM_MODE)	
	struct sockaddr_un unix_server_addr;
	
	gtest_sapp_master_fd = socket(AF_UNIX,SOCK_DGRAM,0);
	if(gtest_sapp_master_fd < 0){
		printf("unix domain socket error, %s!\n", strerror(errno));
		exit(1);
	}

	memset(&unix_server_addr, 0, sizeof(unix_server_addr));
	unix_server_addr.sun_family = AF_UNIX;
	strcpy(unix_server_addr.sun_path, UNIX_SOCKET_NAME);

	unlink(UNIX_SOCKET_NAME);
	ret = bind(gtest_sapp_master_fd, (struct sockaddr *)&unix_server_addr, sizeof(unix_server_addr));
	if(ret < 0){
		printf("bind error, %s!\n", strerror(errno));
		exit(1);	
	}
#elif  (2 == GTEST_SAPP_COMM_MODE)
	struct sockaddr_in udp_servaddr;
	
	gtest_sapp_master_fd = socket(AF_INET,SOCK_DGRAM,0);
	if(gtest_sapp_master_fd < 0){
		printf("udp socket error, %s!\n", strerror(errno));
		exit(1);
	}

	udp_servaddr.sin_family = AF_INET;
	udp_servaddr.sin_port = htons(UDP_SERVER_BIND_PORT);	//host to network hostshort
	udp_servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");

	int opt_enable = 1;
	setsockopt(gtest_sapp_master_fd, SOL_SOCKET, SO_REUSEADDR, &opt_enable, sizeof(int));

	ret = bind(gtest_sapp_master_fd, (struct sockaddr *)&udp_servaddr, sizeof(udp_servaddr));
	if(ret < 0){
		printf("bind port:%d error, %s!\n", UDP_SERVER_BIND_PORT, strerror(errno));
		exit(1);	
	}	

#else
	printf("unsupport comm mode!\n");
	exit(1);
#endif

	return 0;
}


/* 
	避免因sapp还没启动, 本模块就回放数据包, 怎么判断sapp真正的运行起来了??
	
	不能简单用"ps -afx | grep sapp", 看sapp进程在不在判断, 因为sapp可能刚启动, 但插件还未初始化成功;
	检查runtime.log? 只能是说明初始化成功了;
	收到第一个包打印一条debug日志? 但是创建虚拟tap网卡, 不回放pcap就没有包, 先有鸡还是先有蛋的问题;
	
	先判断sysinfo.log是否在刷新, 其实也不一定100%正确.
		0: sapp没启动;
		1: sapp已经启动;
		-1:错误;

	TODO:
		把sapp的运行状态enum sapp_state_t, 输出fs2日志.  	
*/
int wait_for_sapp_running(void)
{
	const char *__get_sapp_state_cmd = "head sysinfo.log -n 2 | grep '%s'";
	char get_sapp_state_cmd_buf[256] = {};
	FILE *result_fp;
	char cmd_result[512] = {};
	char time_string[64];
	int ret = 0;

	/* sapp启动后, sysinfo.log每秒刷新一次 */
	gtest_timet_to_str(time(NULL), time_string, sizeof(time_string));
	snprintf(get_sapp_state_cmd_buf, sizeof(get_sapp_state_cmd_buf), __get_sapp_state_cmd, time_string);

	result_fp = popen(get_sapp_state_cmd_buf, "r");
	if(NULL == result_fp){
		printf("\033[1;31;40mpopen() error!\033[0m\n");
		return -1;
	}

	fgets(cmd_result, sizeof(cmd_result), result_fp);
	if(strlen(cmd_result) >= strlen("1970-01-01 01:00:00")){
		ret = 1;
	}

	fclose(result_fp);
	return ret;
}

int ifconfig_device_up(const char *interface_name)
{
	int 			ret;	
	int 			socket_fd;	  
	struct ifreq	ifr;		
	//struct sockaddr_in sin;
	
	if(interface_name == NULL)  
	{  
		return -1;	
	}  
	
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)	  
	{
		printf("Create Socket Failed.\n");		  
		return -2;	  
	}
	//指定网卡名称且up
	sprintf(ifr.ifr_name, "%s", interface_name);
	/* 获得接口的标�?*/
	if (ioctl(socket_fd, SIOCGIFFLAGS, (void *)&ifr) < 0) {
		fprintf(stderr, "ifconfig_device_up(%s), ioctl SIOCGIFFLAGS: %s\n", interface_name, strerror(errno));
		close(socket_fd);
		return -3;
	}
	ifr.ifr_flags |= IFF_UP;
	ret = ioctl(socket_fd, SIOCSIFFLAGS, &ifr);
	if (ret != 0)	 
	{
		fprintf(stderr, "ifconfig_device_up(%s), ioctl SIOCSIFFLAGS: %s\n", interface_name, strerror(errno));
		close(socket_fd);
		return -3;
	}
	
	close(socket_fd);

	return 0;
}

int ifconfig_device_mtu(const char *interface_name, int mtu_val)
{
	int 			ret;	
	int 			socket_fd;	  
	struct ifreq	ifr;		
	
	if(interface_name == NULL)  
	{  
		return -1;	
	}  
	
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0)	  
	{
		printf("Create Socket Failed.\n");		  
		return -2;	  
	}
	sprintf(ifr.ifr_name, "%s", interface_name);
	/* 获得接口的标�?*/
	if (ioctl(socket_fd, SIOCGIFMTU, (void *)&ifr) < 0) {
		fprintf(stderr, "ifconfig_device_mtu(%s), ioctl SIOCGIFMTU: %s\n", interface_name, strerror(errno));
		close(socket_fd);
		return -3;
	}
	ifr.ifr_ifru.ifru_mtu = mtu_val;  
	ret = ioctl(socket_fd, SIOCSIFMTU, &ifr);
	if (ret != 0)	 
	{
		fprintf(stderr, "ifconfig_device_mtu(%s), ioctl SIOCSIFMTU: %s\n", interface_name, strerror(errno));
		close(socket_fd);
		return -3;
	}
	
	close(socket_fd);

	return 0;
}


int tuntap_dev_create(char *dev, int flags)
{
    assert(dev != NULL);

    struct ifreq ifr;
    int fd, err;

    char *clonedev = (char *)"/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev != '\0') {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		fprintf(stderr, "tuntap_dev_create(%s), ioctl TUNSETIFF: %s\n", dev, strerror(errno));
        close(fd);
        return err;
    }

    ifconfig_device_up(dev);

    ifconfig_device_mtu(dev, 2000); /* 某些pcap包可能开启了offload,  或者vlan, vxlan 增加MTU */

    return fd;
}

pcap_t *pcap_dumpfile_init(const char *pcap_filename)
{	
	pcap_t *tmp_handle;
	
	char err_buf[PCAP_ERRBUF_SIZE];
	
	tmp_handle = pcap_open_offline(pcap_filename, err_buf);
	if(NULL == tmp_handle){
		printf("pcap_open_offline() error, %s\n", err_buf);
		return NULL;
	}

	return tmp_handle;
}


int check_ethernet_pkt_equal(const struct ethhdr *ethdr1, const struct ethhdr *ethdr2, int reverse)
{
	if(reverse){
		if(memcmp(ethdr1->h_source, ethdr2->h_dest, ETH_ALEN) != 0){
			return -1;
		}
		if(memcmp(ethdr1->h_dest, ethdr2->h_source, ETH_ALEN) != 0){
			return -1;
		}
	}else{
		if(memcmp(ethdr1->h_source, ethdr2->h_source, ETH_ALEN) != 0){
			return -1;
		}
		if(memcmp(ethdr1->h_dest, ethdr2->h_dest, ETH_ALEN) != 0){
			return -1;
		}
	}

	if(ethdr1->h_proto != ethdr2->h_proto){
		return -1;
	}

	return 0;
}

int check_ip_pkt_equal(const struct ip *iphdr1, const struct ip *iphdr2, int reverse_dir, int check_length)
{
	
	if(reverse_dir){
		if(iphdr1->ip_src.s_addr != iphdr2->ip_dst.s_addr){
			return -1;
		}
		if(iphdr1->ip_dst.s_addr != iphdr2->ip_src.s_addr){
			return -1;
		}
	}else{
		if(iphdr1->ip_src.s_addr != iphdr2->ip_src.s_addr){
			return -1;
		}
		if(iphdr1->ip_dst.s_addr != iphdr2->ip_dst.s_addr){
			return -1;
		}
	}

	if(iphdr1->ip_p != iphdr2->ip_p){
		return -1;
	}

	if(check_length){
		if(iphdr1->ip_len != iphdr2->ip_len){
			return -1;
		}
	}

	return 0;
}


int check_ipv6_pkt_equal(const struct ip6_hdr *iphdr1, const struct ip6_hdr *iphdr2, int reverse_dir, int check_length)
{
	
	if(0 == reverse_dir){
		if(memcmp(&iphdr1->ip6_src, &iphdr2->ip6_src, sizeof(struct in6_addr)) != 0){
			return -1;
		}
		if(memcmp(&iphdr1->ip6_dst, &iphdr2->ip6_dst, sizeof(struct in6_addr)) != 0){
			return -1;
		}
	}else{
		if(memcmp(&iphdr1->ip6_src, &iphdr2->ip6_dst, sizeof(struct in6_addr)) != 0){
			return -1;
		}
		if(memcmp(&iphdr1->ip6_dst, &iphdr2->ip6_src, sizeof(struct in6_addr)) != 0){
			return -1;
		}
	}

	if(iphdr1->ip6_nxt != iphdr2->ip6_nxt){
		return -1;
	}

	if(check_length){
		if(iphdr1->ip6_plen != iphdr2->ip6_plen){
			return -1;
		}
	}

	return 0;
}



int check_udp_pkt_equal(const struct udphdr *udphdr1, const struct udphdr *udphdr2, int reverse_dir, int check_length)
{
	if(reverse_dir){
		if(udphdr1->source != udphdr2->dest){
			return -1;
		}
		if(udphdr1->dest != udphdr2->source){
			return -1;
		}
	}else{
		if(udphdr1->source != udphdr2->source){
			return -1;
		}
		if(udphdr1->dest != udphdr2->dest){
			return -1;
		}
	}

	if(check_length){
		if(udphdr1->len != udphdr2->len){
			return -1;
		}
	}

	return 0;
}

int check_tcp_pkt_equal(const struct mesa_tcp_hdr *raw_hdr, const struct mesa_tcp_hdr *snd_hdr, unsigned char flags,
	unsigned int seq_net_order, unsigned int ack_net_order, int reverse_dir)
{
	if(reverse_dir){
		if(raw_hdr->th_sport != snd_hdr->th_dport){
			return -1;
		}
		if(raw_hdr->th_dport != snd_hdr->th_sport){
			return -1;
		}
	}else{
		if(raw_hdr->th_sport != snd_hdr->th_sport){
			return -1;
		}
		if(raw_hdr->th_dport != snd_hdr->th_dport){
			return -1;
		}
	}

	if((flags != 0) 
	&& ((snd_hdr->th_flags & flags) != flags)){
		return -1;
	}

	if((seq_net_order != 0)
	&& (seq_net_order != snd_hdr->th_seq)){
		return -1;
	}
	if((ack_net_order != 0)
	&& (ack_net_order != snd_hdr->th_ack)){
		return -1;
	}

	return 0;
}


/* 此函数copy自sapp : deal_mpls.c->set_mpls_addr   */
static int sapp_mpls_addr_net_to_mem(const struct mesa_mpls_hdr *net_mpls_hdr, struct single_layer_mpls_addr *mem_mpls_hdr)
{
	assert(net_mpls_hdr!=NULL);
	memset(mem_mpls_hdr, 0, sizeof(struct single_layer_mpls_addr));

	mem_mpls_hdr->label = htonl( (net_mpls_hdr->mpls_label_low<<12) | (net_mpls_hdr->mpls_label_mid<<4) | net_mpls_hdr->mpls_label_high ); /* network order */
	mem_mpls_hdr->experimental = net_mpls_hdr->mpls_exp;
	mem_mpls_hdr->bottom = net_mpls_hdr->mpls_bls;
	mem_mpls_hdr->ttl = net_mpls_hdr->mpls_ttl;

	return 0;
}

/* 此函数copy自sapp     */
static int __sapp_guess_mpls_with_control_word(const unsigned char *maybe_eth_hdr)
{
	const struct mesa_ethernet_hdr *ehdr = (struct mesa_ethernet_hdr *)(maybe_eth_hdr);

	/* 
	    MPLS没有字段表示承载的协议类�? 靠猜!!
	    
	    https://tools.ietf.org/html/rfc4623
	    https://wiki.mikrotik.com/wiki/Manual:VPLS_Control_Word
	    https://www.ciscopress.com/articles/article.asp?p=386788&seqNum=2
	    
	    除标准的ipv4, ipv6之外, 还有可能是ethernet, 还有可能是带PW Ethernet Control Word�? 格式如下:
	    
        0               1               2                 3
		0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		|0 0 0 0| flags |frag|len(6bit) |    Sequence Number(16bit)     |
		+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		实际情况证明, �?bit是否==0为条�? 还是可能猜错, 再判断一下以太类型是否为常见类型.
	*/

	switch(ntohs(ehdr->ether_type)){
		case ETH_P_IP:
		case ETH_P_IPV6:
		case ETH_P_8021Q:
		case ETH_P_MPLS_UC:
		case ETH_P_PPP_SES:
			return 0; /* 合法的ethernet类型, 不含CW */
		break;
	}

	ehdr = (struct mesa_ethernet_hdr *)(maybe_eth_hdr + 4);
	switch(ntohs(ehdr->ether_type)){
		case ETH_P_IP:
		case ETH_P_IPV6:
		case ETH_P_8021Q:
		case ETH_P_MPLS_UC:
		case ETH_P_PPP_SES:
			return 1; /* 合法的ethernet类型, 包含CW */
		break;
	}

	/* TODO: 以上都不�? 此处应该返回个什么�? */
	return 0;
}

/* 此函数copy自sapp     */
int sapp_set_mpls_addr(struct layer_addr_mpls *addr, const unsigned char *raw_mpls_pkt_data)
{
	const struct mesa_mpls_hdr *this_mpls_hdr=NULL;
	int i;
	
	memset(addr, 0, sizeof(struct layer_addr_mpls));
	for(i = 0; i < MAX_MPLS_ADDR_LAYER; i++)
	{
		this_mpls_hdr = (const struct mesa_mpls_hdr *)raw_mpls_pkt_data;
		if (this_mpls_hdr)
		{
		sapp_mpls_addr_net_to_mem(this_mpls_hdr, &addr->c2s_addr_array[i]); /* 函数栈里的地址, 每次暂存在c2s方向, TCP/UDP层再根据流方向翻�?*/
		
		addr->c2s_layer_num += 1;
		if(1 == this_mpls_hdr->mpls_bls){
			raw_mpls_pkt_data += sizeof(struct mesa_mpls_hdr); /* 为了后面方便判断是否还有ctrl word */
			break;
		}
		raw_mpls_pkt_data += sizeof(struct mesa_mpls_hdr);
		}
	}

	if(this_mpls_hdr== NULL || 1 != this_mpls_hdr->mpls_bls) /* 超过MAX_MPLS_ADDR_LAYER, MPLS还没有结�?*/
	{
		return -1;
	}
	
	if(((*raw_mpls_pkt_data & 0xF0) != 0x40) && ((*raw_mpls_pkt_data & 0xF0) != 0x60)){ //VPLS, MPLS with Control Word
		if(__sapp_guess_mpls_with_control_word(raw_mpls_pkt_data) > 0){
			memcpy(&addr->c2s_mpls_ctrl_word, raw_mpls_pkt_data,  sizeof(int));
			addr->c2s_has_ctrl_word = 1;
		}
	}

	return 0;
}
	

int check_mpls_pkt_equal(const struct mesa_mpls_hdr *raw_mhdr, const struct mesa_mpls_hdr *inject_mhdr )
{
	int i;
	struct layer_addr_mpls raw_mpls_addr, inject_mpls_addr;
	
	sapp_set_mpls_addr(&raw_mpls_addr, (unsigned char *)raw_mhdr);
	sapp_set_mpls_addr(&inject_mpls_addr, (unsigned char *)inject_mhdr);

	if(raw_mpls_addr.c2s_layer_num != inject_mpls_addr.c2s_layer_num){
		return -1;
	}
	
	if(raw_mpls_addr.c2s_has_ctrl_word != inject_mpls_addr.c2s_has_ctrl_word){
		return -1;
	}

	for( i = 0; i < raw_mpls_addr.c2s_layer_num; i++){
		if(raw_mpls_addr.c2s_addr_array[i].label != inject_mpls_addr.c2s_addr_array[i].label){
			return -1;
		}
		if(raw_mpls_addr.c2s_addr_array[i].experimental != inject_mpls_addr.c2s_addr_array[i].experimental){
			return -1;
		}		
	}

	return 0;
}

/* 此函数copy自sapp     */
int sapp_set_vxlan_addr(const void *this_layer_hdr, struct layer_addr_vxlan_private *addr_pr)
{
	unsigned short vlan_id_high, vlan_id_low;
	
	const inline_vxlan_hdr_t *vxlan_hdr = (inline_vxlan_hdr_t *)this_layer_hdr;

	addr_pr->addr_public.C2S_vxlan_addr.dir = vxlan_hdr->dir;
	addr_pr->addr_public.C2S_vxlan_addr.link_id = vxlan_hdr->link_id;
	addr_pr->addr_public.C2S_vxlan_addr.link_type = vxlan_hdr->link_layer_type;
	vlan_id_high = vxlan_hdr->vlan_id_half_high;
	vlan_id_low = vxlan_hdr->vlan_id_half_low;
	addr_pr->addr_public.C2S_vxlan_addr.vlan_id = htons((vlan_id_high<<4) | vlan_id_low);
	addr_pr->addr_public.C2S_vxlan_addr.flag = vxlan_hdr->flags;

	addr_pr->actual_total_len = sizeof(inline_vxlan_hdr_t);

	switch(addr_pr->addr_public.C2S_vxlan_addr.link_type){
		case VXLAN_ENCAP_HDLC:
		{
			const struct hdlc_net_hdr *net_hdlc_hdr = (struct hdlc_net_hdr *)((char *)this_layer_hdr + sizeof(inline_vxlan_hdr_t));
			addr_pr->inner_hdlc.address = net_hdlc_hdr->address;
			addr_pr->inner_hdlc.control = net_hdlc_hdr->control;
			addr_pr->inner_hdlc.protocol = net_hdlc_hdr->protocol;
			addr_pr->actual_total_len += sizeof(struct hdlc_net_hdr);
		}
		break;

		case VXLAN_ENCAP_PPP:
		{
			const struct layer_ppp_hdr *net_ppp_hdr = (struct layer_ppp_hdr *)((char *)this_layer_hdr + sizeof(inline_vxlan_hdr_t));
			addr_pr->inner_ppp.address = net_ppp_hdr->address;
			addr_pr->inner_ppp.control = net_ppp_hdr->control;
			addr_pr->inner_ppp.protocol = net_ppp_hdr->protocol;
			addr_pr->actual_total_len += sizeof(struct layer_ppp_hdr);
		}
		break;
	}

	return 0;
}


int check_vxlan_private_pkt_equal(const void *raw_net_hdr, const void *inject_net_hdr, struct layer_addr_vxlan_private *raw_vxlan_addr, struct layer_addr_vxlan_private *inject_vxlan_addr, int reverse_dir)
{
	sapp_set_vxlan_addr(raw_net_hdr, raw_vxlan_addr);
	sapp_set_vxlan_addr(inject_net_hdr, inject_vxlan_addr);

	if(raw_vxlan_addr->addr_public.C2S_vxlan_addr.vlan_id != inject_vxlan_addr->addr_public.C2S_vxlan_addr.vlan_id){
		return -1;
	}
	if(raw_vxlan_addr->addr_public.C2S_vxlan_addr.link_id != inject_vxlan_addr->addr_public.C2S_vxlan_addr.link_id){
		return -1;
	}
	if(raw_vxlan_addr->addr_public.C2S_vxlan_addr.link_type != inject_vxlan_addr->addr_public.C2S_vxlan_addr.link_type){
		return -1;
	}

	if(0 == reverse_dir){
		if(raw_vxlan_addr->addr_public.C2S_vxlan_addr.dir != inject_vxlan_addr->addr_public.C2S_vxlan_addr.dir){
			return -1;
		}
	}else{
		/* 反向注入, dir值取�?*/
		if((raw_vxlan_addr->addr_public.C2S_vxlan_addr.dir ^ 1) != inject_vxlan_addr->addr_public.C2S_vxlan_addr.dir){
			return -1;
		}
	}

	return 0;
}


/*
	检查某个文件是否包括某些内�?
*/
int expect_file_has_some_string(const char *filename, const char *expect_string)
{
	char check_cmd[1024];
	char cmd_result[1024] = {};
	FILE *fp;

	snprintf(check_cmd, sizeof(check_cmd), "cat %s | grep %s", filename, expect_string);
	fp = popen(check_cmd, "r");
	if(NULL == fp){
		return -1;
	}

	fgets(cmd_result, sizeof(cmd_result), fp);
	if(strlen(cmd_result) == 0){
		fclose(fp);
		return -1;
	}
	
	fclose(fp);
	return 0;
}


#include <stdarg.h>
void gtest_write_log(const char *fmt, ...)
{
	//obsolescent
	
	return;
}

/*
	fake marsio模式回放普通数据包�?     用于根据内层ip地址判断一个route方向.
*/
int pcap_replay_route_dir(const void *raw_eth_data)
{
	int route_dir;
	const void *res;
	const struct ip *ipv4_hdr;
	const struct ip6_hdr *ipv6_hdr;

	res = MESA_jump_layer_greedy((const void *)raw_eth_data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V4);

	if(res){
		ipv4_hdr = (const struct ip *)res;
		if(memcmp(&ipv4_hdr->ip_src.s_addr, &ipv4_hdr->ip_dst.s_addr, sizeof(int)) >= 0){
			route_dir = 0;
		}else{
			route_dir = 1;
		}

		//TODO, 此处应该再判断一下ip相等�? 判断tcp或udp端口

		goto bingo;
	}

	res = MESA_jump_layer_greedy((const void *)raw_eth_data, ADDR_TYPE_MAC, __ADDR_TYPE_IP_PAIR_V6);
	if(res){
		ipv6_hdr = (const struct ip6_hdr *)res;
		if(memcmp(&ipv6_hdr->ip6_src, &ipv6_hdr->ip6_dst, sizeof(struct in6_addr)) >= 0){
			route_dir = 0;
		}else{
			route_dir = 1;
		}

		//TODO, 此处应该再判断一下ip相等�? 判断tcp或udp端口

		goto bingo;
	}

	printf("### pcap_replay_route_dir() error, not found any ip header!\n");
	return -1;

bingo:

	return route_dir;
}

#if GTEST_SAPP
void gtest_exec_printf(const char *fmt, ...)
{
	va_list ap;
	
	if(g_slient_mode != 0){
		return;
	}

    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);

    return;
}
#endif

