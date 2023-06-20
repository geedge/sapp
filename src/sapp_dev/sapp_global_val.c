#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

sapp_global_t *sapp_global_val;

struct sapp_global_single_t sapp_global_single;
struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];

//extern int g_packet_io_thread_num;
extern int tcpstate_num[MAX_TCP_STATE];
extern int udpstate_num[MAX_UDP_STATE];
extern char g_cmd_args_main_cfg_file[PATH_MAX];
extern int g_sapp_global_mem_used_block;
extern int g_sapp_global_mem_used_bytes;

/* 测试时先使用全局变量, 以后动态读取配置文件,
   overlay层定义, 比如vxlan的环境下, overlay包括四层, eth[0], ipv4[1], udp[2], vxlan[3], 这些层不是原始包内容, 是为了便于分流生造出来的层, 不能调用插件, 
   但实际回注、发包时也要携带,

   TODO, 那vxlan保活插件怎么办?  
   将gdev_keepalive模块移到sapp内部, 不作为插件.so挂载, 使用sapp.toml开关控制而不是靠plug conflist控制.

   TODO: 移动到全局变量sapp_global_val中.
*/
int g_overlay_layer_set[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX];    

/* 
   注入包修剪层定义, 即发包时跳过此层, 
   mirror模式下, 捕包和注入点不一样时, 发rst包要跳过vlan, mpls, gtp等层, 
   因为不像overlay, overlay格式肯定是预先规定好的, 但真实流量不一定能预先指定某个协议在哪层, 
   所以支持模糊层数, 用*表示, 如vlan[*], gtp[*]等, 表示发包时包括此层肯定跳过, 不论在哪一层,
   如果是ip-in-ip, ip-gre-ip, 4over6, 6over4这类隧道, 想跳过外层ip直接注入内层ip和四元组, 是非常危险的, 
   因为即不能写成ip[*], 也不能写成ip[1], ip[2]这种, 会把不含隧道的纯ip/tcp包搞乱, 

   所以设置成一个地址层数组, 必须同时符合指定数组所有层, 才跳过.
*/

/*
	发包时必须同时满足一条完整的prune链才跳过, 顺序是从internal到external, 
	最多可支持N条跳层配置,   mirror模式下, 最底层的ethernet写不写都可以, 

	比如卫星项目gtp原始包层数为:     ethernet/ipv4/udp/gtp/ipv4/tcp/http, 跳过gtp的配置: "gtp[3],udp[2],ip[1]", 

	比如某GRE隧道原始包层数为: ethernet/ipv4/gre/ipv4/udp/dns,   跳过最外层隧道的配置: "gre[2],ip[1]", 
	TODO: 移动到全局变量sapp_global_val中.
*/

embed_layer_t g_prune_inject_layer_set[SAPP_PRUNE_LAYER_NUM_MAX];


/*
	描述哪些层是非对称存在层, 即C2S和S2C方向有可能没有这一层,导致创建流compare_addr时两侧不对称, 需要创建一个空层, 但注入包时尤其注意, 需要跳过. 
	TODO: 移动到全局变量sapp_global_val中.
*/
asymmetric_presence_layer_t g_asymmetric_presence_layer_set[__ADDR_TYPE_MAX];    


/*
	与g_asymmetric_presence_layer_set含义不同, 描述哪些层是层数一样但双向地址不一致的层, 
	即C2S和S2C方向的层数虽然是一样的,但双向的地址不一样, 常见的如gtp, gre, mpls等, ethernet, vlan也有可能.
	如果反向注入数据包, 必须是双向流, 
	需要更新对侧信息, 注入包时尤其注意. 
	如果是单向流, 且开启此项配置, 反向注入包是失败的!!
	TODO: 移动到全局变量sapp_global_val中.
*/
embed_layer_t g_asymmetric_addr_layer_set; 


/* 
    用于指定哪些协议层作为地址参数, 用于唯一确定一个流, 比如不同隧道内都使用私有地址时, 是有可能冲突的, 应该把底层vlan,mpls等层也作为地址比较参数,
    TODO: 移动到全局变量sapp_global_val中.
*/
embed_layer_t g_stream_compare_layer_set; 


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

static inline int mem_alignment_pad(int size)
{
	return 64 - (size % 64);
}

void sapp_global_val_sanity_check(void)
{
	/* 多线程全局变量size必须是64字节整数倍, 否则多核cache缓存冲突, 极大影响性能 */
	if((sizeof(struct sapp_global_mthread_t) % 64) != 0){
		printf("\033[1;31;40msizeof(struct sapp_global_mthread_t)=%u, is not multiple of 64B!\033[0m\n", sizeof(struct sapp_global_mthread_t));
		printf("\033[1;31;40mYou must add %d bytes padding to sapp_global_mthread_t!\033[0m\n", mem_alignment_pad(sizeof(struct sapp_global_mthread_t)));
		abort();
	}

	if((sizeof(sapp_gval_mthread_t) % 64) != 0){
		printf("\033[1;31;40msizeof(sapp_gval_mthread_t)=%u, is not multiple of 64B!\033[0m\n", sizeof(sapp_gval_mthread_t));
		printf("\033[1;31;40mYou must add %d bytes padding to sapp_gval_mthread_t!\033[0m\n", mem_alignment_pad(sizeof(sapp_gval_mthread_t)));
		abort();
	}

	if((sizeof(sapp_gval_individual_volatile_t) % 64) != 0){
		printf("\033[1;31;40msizeof(sapp_gval_individual_volatile_t)=%u, is not multiple of 64B!\033[0m\n", sizeof(sapp_gval_individual_volatile_t));
		printf("\033[1;31;40mYou must add %d bytes padding to sapp_gval_individual_volatile_t!\033[0m\n", mem_alignment_pad(sizeof(sapp_gval_individual_volatile_t)));
		abort();
	}
	
	if((sizeof(layer_args_t) % 64) != 0){
		printf("\033[1;31;40msizeof(struct layer_args_t)=%u, is not multiple of 64B!\033[0m\n", sizeof(layer_args_t));
		abort();
	}

	sapp_include_header_check();
	if(INDEPENDENT_SEND_QUEUE_MAX_NUM > MAX_THREAD_NUM){
		printf("\033[1;31;40m INDEPENDENT_SEND_QUEUE_MAX_NUM(%d) > MAX_THREAD_NUM(%d)!\033[0m\n", INDEPENDENT_SEND_QUEUE_MAX_NUM, MAX_THREAD_NUM);
		abort();
	}

}

extern int tomlc99_wrap_load_int_def(const char *file,const char *section, char *key,int *val,int dval);
void sapp_gval_init(void)
{
	int tseq;

	/* 内存统计的数据自身就是存储在全局变量中, 这是先有鸡还是先有蛋的问题, 此处直接用系统的calloc, 独立计数 */
	sapp_global_val = (sapp_global_t *)calloc(1, sizeof(sapp_global_t));
	g_sapp_global_mem_used_block++;
	g_sapp_global_mem_used_bytes += sizeof(sapp_global_t);
	
	sapp_global_val->individual_volatile = (sapp_gval_individual_volatile_t *)calloc(1, sizeof(sapp_gval_individual_volatile_t));
	g_sapp_global_mem_used_block++;
	g_sapp_global_mem_used_bytes += sizeof(sapp_gval_individual_volatile_t);
	
	for(tseq = 0; tseq < SAPP_MAX_THREADS; tseq++){
		sapp_global_val->mthread_volatile[tseq] = (sapp_gval_mthread_t *)calloc(1, sizeof(sapp_gval_mthread_t));
		sapp_global_val->individual_fixed.cpu_bind_core_id_per_thread[tseq] = -1; /* 初始化设置为-1, 表示没绑定到任何一个cpu core */
		g_sapp_global_mem_used_block++;
		g_sapp_global_mem_used_bytes += sizeof(sapp_gval_mthread_t);
	}

	/* set default value, maybe not input by user or config file */
	snprintf(sapp_global_val->config.packet_io.pcap_dumpfile_name, NAME_MAX, "dumpfile");

	ABBR_CURRENT_TIME = time(NULL);
}

void sapp_gval_destroy(void)
{
	int tseq;

	if(sapp_global_val->cla.cmd_args_array){
		int i, args_num = sapp_global_val->cla.cmd_args_num;
		sapp_cmd_args_val_t *free_opt;

		for(i = 0; i < args_num; i++){
			free_opt = sapp_global_val->cla.cmd_args_array[i];
			SAPP_GLOBAL_FREE(free_opt->long_opt_name);
			SAPP_GLOBAL_FREE(free_opt->arg_val.string_value);
			SAPP_GLOBAL_FREE(free_opt);
		}
		
		SAPP_GLOBAL_FREE(sapp_global_val->cla.cmd_args_array);//此处使用了realloc追加, 要用sapp_mem_free()
	}

	SAPP_GLOBAL_FREE(sapp_global_val->config.stream.tcp.well_known_ports_array);
	SAPP_GLOBAL_FREE(sapp_global_val->config.stream.udp.well_known_ports_array);

	sapp_config_file_link_t *pconfig = &sapp_global_val->config.cfg_file_path;
	SAPP_GLOBAL_FREE(pconfig->cfg_files_root_dir);
	SAPP_GLOBAL_FREE(pconfig->cfg_main_entry_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_main_entry_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_sapp_log_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_sapp_log_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_plug_list_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_plug_list_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_project_list_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_project_list_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_entry_list_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_entry_list_absolute);	
	SAPP_GLOBAL_FREE(pconfig->cfg_file_send_raw_pkt_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_send_raw_pkt_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vxlan_sport_map_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vxlan_sport_map_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_inline_dev_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_inline_dev_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_necessary_plug_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_necessary_plug_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_stream_compare_layer_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_stream_compare_layer_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vlan_flipping_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_vlan_flipping_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_asymmetric_addr_layer_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_asymmetric_addr_layer_absolute);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_well_known_port_relative);
	SAPP_GLOBAL_FREE(pconfig->cfg_file_well_known_port_absolute);

	sapp_data_file_link_t *pdata = &sapp_global_val->config.data_file_path;
	SAPP_GLOBAL_FREE(pdata->data_files_root_dir);
	SAPP_GLOBAL_FREE(pdata->data_sapp_sysinfo_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_sapp_sysinfo_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs2_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_sapp_fs2_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_inline_keepalive_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_inline_keepalive_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_load_plugin_stat_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_load_plugin_stat_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_under_ddos_stat_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_under_ddos_stat_log_absolute);
	SAPP_GLOBAL_FREE(pdata->data_memory_stat_log_relative);
	SAPP_GLOBAL_FREE(pdata->data_memory_stat_log_absolute);

	SAPP_GLOBAL_FREE(sapp_global_val->config.packet_io.input_bpf_filter);

	SAPP_GLOBAL_FREE(sapp_global_val->config.library_file_path.libmarsio_file_path);
	SAPP_GLOBAL_FREE(sapp_global_val->config.tools.pkt_dump.bpf_filter);
	SAPP_GLOBAL_FREE(sapp_global_val->config.tools.pkt_dump.storge_path);

	/* individual_volatile, sapp_global_val最后free */
	if(sapp_global_val->individual_volatile){
		free(sapp_global_val->individual_volatile); /* 初始化时用calloc, 此处只能用free */
		g_sapp_global_mem_used_block--;
		g_sapp_global_mem_used_bytes -= sizeof(sapp_gval_individual_volatile_t);
	}

	for(tseq = 0; tseq < SAPP_MAX_THREADS; tseq++){
		free(sapp_global_val->mthread_volatile[tseq]); /* 初始化时用calloc, 此处只能用free */
		g_sapp_global_mem_used_block--;
		g_sapp_global_mem_used_bytes -= sizeof(sapp_gval_mthread_t);
	}	

	memset((void *)sapp_global_val, 0xFE, sizeof(sapp_global_t));
	free(sapp_global_val);
	sapp_global_val = NULL;
}


#ifdef __cplusplus
}
#endif

