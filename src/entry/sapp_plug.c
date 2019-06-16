#include "sapp_api.h"
#include "sapp_private_api.h"


#ifdef __cplusplus
extern "C" {
#endif

#if SAPP_AS_TARGET_SO
extern int MESA_platform_init(int argc, char *argv[]);
extern int ipv4_entry(struct streaminfo_private *pfstream_pr, const void *this_layer_data, int thread_num, 
			unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr);
extern void packet_io_clean_thread_context(int thread_seq);
extern void MESA_platform_run(void);
extern int sapp_parse_config(void);

#define DUMPFILE_EOF_FLAG	(void*)0xF1E2D3C4B5A6 /* 用一个独特变量表示当前dumpfile模式已结束, 清理内存 */

char MESA_IP_PLUG_ENTRY(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const struct mesa_ip4_hdr *ipv4_hdr)
{
	char ret = PASS;
	raw_pkt_t raw_pkt;

	if(DUMPFILE_EOF_FLAG == pstream){
		packet_io_clean_thread_context(thread_seq);
		sleep(3);
		return PASS;
	}

	raw_pkt.magic_num = RAW_PKT_MAGIC_NUM;
	raw_pkt.offset_to_raw_pkt_hdr = 0;
	raw_pkt.low_layer_type = (enum addr_type_t)CAP_LEVEL_IPV4;
	raw_pkt.raw_pkt_len = ntohs(ipv4_hdr->ip_len);
	raw_pkt.raw_pkt_data = ipv4_hdr;
	raw_pkt.hd_hash = 0;

	ret = ipv4_entry(NULL, ipv4_hdr, thread_seq, 0, &raw_pkt, 0);
	
	return ret;
}

int MESA_PLUG_INIT(void)
{	
	int i;
	pthread_t pid;

	sapp_gval_init();
	sapp_set_current_state(SAPP_STATE_JUST_START);
	sapp_set_current_state(SAPP_STATE_CONFIG_PARSE);

	sapp_parse_config();

	if(MESA_platform_init(0, NULL) < 0){
		sapp_runtime_log(30, "IIE plug init error!\n");
		return -1;
	}

	g_packet_io_cap_level = CAP_LEVEL_IPV4; /* 挂载到IP层插件, 强制指定为IPv4 */

	MESA_platform_run();
	
	return 1;
}

#endif

#ifdef __cplusplus
}
#endif

