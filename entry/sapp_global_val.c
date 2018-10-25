#ifdef __cplusplus
extern "C" {
#endif

#include "stream.h"
#include "stream_internal.h"
#include "packet_io_internal.h"
#include "mesa_net.h"
#include "sysinfo.h"
#include "stream_manage.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

struct sapp_global_single_t sapp_global_single;
struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];

extern int g_packet_io_thread_num;
extern int tcpstate_num[MAX_TCP_STATE];
extern int udpstate_num[MAX_UDP_STATE];

extern char *MESA_MD5_sum_str(unsigned char *raw_data, unsigned int raw_data_len, char result[33]);

static off_t _check_hdr_get_file_length(const char *file_name)
{
	struct stat file_stat;
	
	if(stat(file_name, &file_stat) == 0)
	{
		return file_stat.st_size;
	}
	return 0;
}

static void sapp_include_header_check_file(const char *file_name, const char *std_md5_sum_str)
{
	char file_md5_sum_str[33];
	FILE *fp;
	char *tmp_file_buf;
	off_t file_len;

	fp = fopen(file_name, "r");
	if(NULL == fp){
		return;
	}

	file_len = _check_hdr_get_file_length(file_name);
	tmp_file_buf = (char *)malloc(file_len);

	fread(tmp_file_buf, file_len, 1, fp);

	MESA_MD5_sum_str((unsigned char *)tmp_file_buf, file_len, file_md5_sum_str);

	if(memcmp(file_md5_sum_str, std_md5_sum_str, 32) != 0){
		printf("\033[33m[Warning]stream_inc header file %s is disaccord with current sapp!\033[0m\n", file_name);
		usleep(200 * 1000);
	}

	fclose(fp);
	free(tmp_file_buf);

	return;
}

/* 检测当前运行环境下的.h与编译环境是否一致 */
void sapp_include_header_check(void)
{
	const char *hdr_dir;
	char tmp_file_path[1024];
	
	hdr_dir = "/opt/MESA/include/MESA/stream_inc";
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_base.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_BASE_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_control.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_CONTROL_MD5_CHECK);
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_entry.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_ENTRY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_inject.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_INJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_project.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_proxy.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROXY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_rawpkt.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_RAWPKT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_tunnel.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_TUNNEL_MD5_CHECK);

	hdr_dir = "/usr/include/MESA/stream_inc";
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_base.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_BASE_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_control.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_CONTROL_MD5_CHECK);
	
	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_entry.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_ENTRY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_inject.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_INJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_project.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROJECT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_proxy.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_PROXY_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_rawpkt.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_RAWPKT_MD5_CHECK);

	snprintf(tmp_file_path, 1024, "%s/%s", hdr_dir, "stream_tunnel.h");
	sapp_include_header_check_file(tmp_file_path, STREAM_TUNNEL_MD5_CHECK);
}

void sapp_global_val_check(void)
{
	/* 多线程全局变量size必须是64字节整数倍, 否则多核cache缓存冲突, 极大影响性能 */
	if((sizeof(struct sapp_global_mthread_t) % 64) != 0){
		printf("\033[1;31;40msizeof(struct sapp_global_mthread_t)=%u, is not multiple of 64B!\033[0m\n", sizeof(struct sapp_global_mthread_t));
		abort();
	}

	if((sizeof(layer_args_t) % 64) != 0){
		printf("\033[1;31;40msizeof(struct layer_args_t)=%u, is not multiple of 64B!\033[0m\n", sizeof(layer_args_t));
		abort();
	}

	sapp_include_header_check();
}


int sapp_global_val_init(void)
{
	int i;
	
	sapp_global_val_check();
	
	for(i = 0; i < g_packet_io_thread_num; i++){
		sapp_global_mthread[i].tcp_stream_special_timeout_num = tcpstate_num[TCP_DATA_STATE]/10 + 1;
		sapp_global_mthread[i].udp_stream_special_timeout_num = udpstate_num[UDP_TWO_STATE]/10 + 1;
	}

	return 0;
}


#ifdef __cplusplus
}
#endif

