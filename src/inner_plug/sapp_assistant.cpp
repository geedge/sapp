/*
	此文件非平台核心功能和函数(Ip分片, 流还原, 隧道解析, 插件管理等), 
	是提供给其他业务插件的接口, 如sapp_get_platform_opt等, 做为一个.so文件挂载到平台,
	便于更新部署.
*/
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "field_stat2.h"

static int sapp_fs2_init(void);
static int sapp_line_protocol_init(void);

#ifdef __cplusplus
extern "C" {
#endif

//extern time_t g_CurrentTime;//add by lqy 20070606
//extern int g_packet_io_thread_num;
extern char g_app_instance_name[64];
//extern int g_timestamp_record_sw;

static pthread_mutex_t g_plug_Independent_thread_mutex;
static pthread_t *g_plug_Independent_thread_pid;


static const unsigned char G_BROADCAST_ADDR[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

int sapp_assistant_version_VERSION_20181024;
extern int MESA_get_dev_ipv4(const char *device, int *ip_add);
extern int MESA_get_dev_mac(const char *device, unsigned char mac[6]);

void * (*dl_marsio_buff_ctrlzone)(void *m, uint8_t id);
extern void * (*ptr_marsio_buff_ctrlzone)(marsio_buff_t *m, uint8_t id);

int sapp_identify_broad_multicast_init(void)
{
#if 0
	void *io_lib_handle;
	
	if(CAP_MODEL_MARSIOV4 == g_packet_io_cap_mode){
#if LINK_MODE_DYNAMIC	
		io_lib_handle = dlopen("./platform_lib/packet_io_marsio.so", RTLD_NOW | RTLD_GLOBAL);
		if(NULL == io_lib_handle){
			printf("\033[1;31;40m[Error]dlopen %s error, %s!\033[0m\n", "./platform_lib/packet_io_marsio.so", dlerror());
			return -1;
		}	
		dl_marsio_buff_ctrlzone = (void * (*)(void *m, uint8_t id))dlsym(io_lib_handle, "marsio_buff_ctrlzone");
		if(NULL == dl_marsio_buff_ctrlzone){
			printf("\033[1;31;40m[Error]dlsym %s error, %s!\033[0m\n", "marsio_buff_ctrlzone", dlerror());
			return -1;
		}

		/* 此处不要用dlclose(), 因为后续还要用dlopen打开packet_io_marsio.so,  */
#else
	dl_marsio_buff_ctrlzone = (void * (*)(void *m, uint8_t id))ptr_marsio_buff_ctrlzone;
#endif
	}
#endif

	return 0;
}

/* 识别是否隧道内部数据包           , 隧道内的包应该无条件转发/回注        */
int sapp_identify_tunnel_inner_pkt(const raw_pkt_t *raw_pkt)
{
	int ret = 0;
#if IOMODE_MARSIO
	if(CAP_MODEL_MARSIOV4 == g_packet_io_cap_mode){
		if(0 == sapp_global_val->config.packet_io.packet_io_tunnel.l2_l3_tunnel_support){
			const struct mr_tunnat_ctrlzone *mr_ctzone;
			if(ptr_marsio_buff_ctrlzone){
				mr_ctzone = (const struct mr_tunnat_ctrlzone *)((*ptr_marsio_buff_ctrlzone)((void *)raw_pkt->io_lib_pkt_reference, 0));
				if(mr_ctzone->action & TUNNAT_CZ_ACTION_FORWARD){
					ret = 1; 
				}
			}
		}else{
			/* 没有mrtunnat时, 如果开启l2_l3_tunnel_support, 要判断overlay类型, 是否是给本机的, 是否是经过overlay原始链路里的包    */
			if(raw_pkt->is_overlay_pkt){
				ret = 1;
			}
		}
	}
#endif

	return ret;
}
int sapp_identify_broad_multicast_pkt(const void *this_layer_data, const raw_pkt_t *raw_pkt)
{
	const struct mesa_ethernet_hdr *p_eth_hdr = (const struct mesa_ethernet_hdr *)this_layer_data;
	unsigned short eth_type = ntohs(p_eth_hdr->ether_type); 

	if(sapp_identify_tunnel_inner_pkt(raw_pkt) != 0){
		return 0;
	}

	if(memcmp(G_BROADCAST_ADDR, p_eth_hdr->ether_dhost, ETH_ALEN) == 0){
		/* G串联模式下，非ARP协议的广播包，直接丢弃! 防止再回注到网络中, 造成广播风暴等网络问题 */
		if(eth_type != ETH_P_ARP){
			return 1;
		}
	}else{
		/* 2017-10-10 lijia add, 组播MAC地址, 通常为局域网内控制类数据包, 如LLMNR, STP等协议, 一般无需处理 
			参考:https://en.wikipedia.org/wiki/Multicast_address 
		*/
		if((p_eth_hdr->ether_dhost[0]  == 0x01)
		  &&(p_eth_hdr->ether_dhost[1] == 0x00)
		  &&(p_eth_hdr->ether_dhost[2] == 0x0C)
		  &&(p_eth_hdr->ether_dhost[3] == 0xCC)){
			return 1;
		}else if((p_eth_hdr->ether_dhost[0]  == 0x01)
		  &&(p_eth_hdr->ether_dhost[1] == 0x80)
		  &&(p_eth_hdr->ether_dhost[2] == 0xC2)
		  &&(p_eth_hdr->ether_dhost[3] == 0x00)){
			return 1;
		  }else if((p_eth_hdr->ether_dhost[0]  == 0x01)
		  &&(p_eth_hdr->ether_dhost[1] == 0x00)
		  &&(p_eth_hdr->ether_dhost[2] == 0x5E)){
			return 1;
		  }else if((p_eth_hdr->ether_dhost[0]  == 0x33)
		  &&(p_eth_hdr->ether_dhost[1] == 0x33)){
			return 1;
		  }else if((p_eth_hdr->ether_dhost[0]  == 0x01)
		  &&(p_eth_hdr->ether_dhost[1] == 0x0C)
		  &&(p_eth_hdr->ether_dhost[2] == 0xCD)){
			return 1;
		  }
	}

	return 0;
}

/*
	ctype:
		'c':count;
		'l':length;
*/
static inline unsigned long long __get_platform_opt_traffic(int ctype, sapp_sys_stat_type_t index)
{
	int i;
	unsigned long long tmp_long = 0;
	
	for(i = 0; i < g_packet_io_thread_num; i++){
		if('c' == ctype){
			tmp_long += sapp_global_val->mthread_volatile[i]->sys_stat.count[index];
		}else{
			tmp_long += sapp_global_val->mthread_volatile[i]->sys_stat.length[index];
		}
	}

	return tmp_long;
}

/* 2017-09-04 lijia add, for 网管需求, 插件获取平台内部参数 */
int sapp_get_platform_opt(enum sapp_platform_opt opt, void *opt_val, int *opt_val_len)
{
	int i, ret = 0;
	unsigned long long tmp_long;

	if((NULL == opt_val) ||  (NULL == opt_val_len) || (*opt_val_len <= 0)){
		return -1;
	}

	switch((int)opt){
		case SPO_TOTAL_RCV_PKT:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TOTAL_RCV_PKT error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('c', SAPP_STAT_RCV_ETHERNET);
		}
		break;

		case SPO_TOTAL_RCV_BYTE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TOTAL_RCV_BYTE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_RCV_ETHERNET);;
		}
		break;

		case SPO_TOTAL_INBOUND_PKT:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TOTAL_INBOUND_PKT error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *inbound_pkt = (unsigned long long *)opt_val;
			*inbound_pkt = __get_platform_opt_traffic('c', SAPP_STAT_RAW_INBOUND);
		}
		break;
		
		case SPO_TOTAL_INBOUND_BYTE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TOTAL_INBOUND_BYTE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *inbound_byte = (unsigned long long *)opt_val;
			*inbound_byte = __get_platform_opt_traffic('l', SAPP_STAT_RAW_INBOUND);

		}
		break;

		case SPO_TOTAL_OUTBOUND_PKT:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TOTAL_OUTBOUND_PKT error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *outbound_pkt = (unsigned long long *)opt_val;
			*outbound_pkt = __get_platform_opt_traffic('c', SAPP_STAT_RAW_OUTBOUND);
		}
		break;
		
		case SPO_TOTAL_OUTBOUND_BYTE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TOTAL_OUTBOUND_BYTE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *outbound_byte = (unsigned long long *)opt_val;
			*outbound_byte = __get_platform_opt_traffic('l', SAPP_STAT_RAW_OUTBOUND);

		}
		break;

		case SPO_TCP_STREAM_NEW:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TCP_STREAM_NEW error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_TCP_STREAM_NEW);
		}
		break;		

		case SPO_TCP_STREAM_ESTAB:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TCP_STREAM_ESTAB error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_TCP_STREAM_DATA);
		}
		break;	

		case SPO_TCP_STREAM_CLOSE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TCP_STREAM_CLOSE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_TCP_STREAM_DEL);
		}
		break;	

		case SPO_UDP_STREAM_NEW:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_UDP_STREAM_NEW error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_UDP_STREAM_NEW);
		}
		break;		

		case SPO_UDP_STREAM_CONCURRENT:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_UDP_STREAM_CONCURRENT error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_UDP_STREAM_TWO);
		}
		break;	
		

		case SPO_UDP_STREAM_CLOSE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_UDP_STREAM_CLOSE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_UDP_STREAM_DEL);
		}
		break;

		case SPO_TOTAL_RCV_INBOUND_IPV4_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('c', SAPP_STAT_IPV4_INBOUND);
		}
		break;
		case SPO_TOTAL_RCV_INBOUND_IPV4_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('l', SAPP_STAT_IPV4_INBOUND);
		}
		break;
		case SPO_TOTAL_RCV_OUTBOUND_IPV4_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_IPV4_OUTBOUND);
			;
		}
		break;
		case SPO_TOTAL_RCV_OUTBOUND_IPV4_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_IPV4_OUTBOUND);
			;
		}
		break;

		case SPO_TOTAL_RCV_INBOUND_IPV6_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('c', SAPP_STAT_IPV6_INBOUND);
		}
		break;
		case SPO_TOTAL_RCV_INBOUND_IPV6_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('l', SAPP_STAT_IPV6_INBOUND);
		}
		break;
		case SPO_TOTAL_RCV_OUTBOUND_IPV6_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_IPV6_OUTBOUND);
			;
		}
		break;
		case SPO_TOTAL_RCV_OUTBOUND_IPV6_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_IPV6_OUTBOUND);
			;
		}
		break;

		case SPO_TOTAL_RCV_INBOUND_TCP_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('c', SAPP_STAT_TCP_INBOUND);
		}
		break;
		case SPO_TOTAL_RCV_INBOUND_TCP_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('l', SAPP_STAT_TCP_INBOUND);
		}
		break;
		case SPO_TOTAL_RCV_OUTBOUND_TCP_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_TCP_OUTBOUND);
			;
		}
		break;
		case SPO_TOTAL_RCV_OUTBOUND_TCP_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_TCP_OUTBOUND);
			;
		}
		break;

		case SPO_TOTAL_RCV_INBOUND_UDP_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('c', SAPP_STAT_UDP_INBOUND);
		}
		break;

		case SPO_TOTAL_RCV_INBOUND_UDP_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_pkt = (unsigned long long *)opt_val;
			*tot_pkt = __get_platform_opt_traffic('l', SAPP_STAT_UDP_INBOUND);
		}
		break;

		case SPO_TOTAL_RCV_OUTBOUND_UDP_PKT:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_UDP_OUTBOUND);
			;
		}
		break;

		case SPO_TOTAL_RCV_OUTBOUND_UDP_BYTE:
		{
			if (*opt_val_len != sizeof(long long))
			{
				ret = -1;
				sapp_runtime_log(RLOG_LV_DEBUG, "sapp_get_platform_opt() error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_byte = (unsigned long long *)opt_val;
			*tot_byte = *tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_UDP_OUTBOUND);
			;
		}
		break;

		case SPO_THREAD_COUNT:
		{
			if(*opt_val_len != sizeof(int)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_THREAD_COUNT error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}

			int *tcnt = (int *)opt_val;
			*tcnt = g_packet_io_thread_num;
		}
		break;

		case SPO_CURTIME_TIMET:
		{
			if(*opt_val_len != sizeof(time_t)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CURTIME_TIMET error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			time_t *curtime = (time_t *)opt_val;
			*curtime = g_CurrentTime;
		}
		break;

		case SPO_CURTIME_TIMET_MS:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CURTIME_TIMET_MS error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			long long *curtime_ms = (long long *)opt_val;
			*curtime_ms = sapp_global_val->individual_volatile->current_time_ms;

		}
		break;

		case SPO_CURTIME_STRING:
		{
			if(*opt_val_len <= (int)strlen("1970-01-01 11:11:11")){

				ret = -1;
				
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CURTIME_STRING error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;			
			}
			time_t cur_time = g_CurrentTime;
			struct tm date_loc;
			int ret;
			
			localtime_r(&cur_time, &date_loc);
			ret = snprintf((char *)opt_val, *opt_val_len, "%04d-%02d-%02d %02d:%02d:%02d", 
					date_loc.tm_year+1900, date_loc.tm_mon+1,date_loc.tm_mday, 
					date_loc.tm_hour, date_loc.tm_min, date_loc.tm_sec);
			*opt_val_len = ret;
		}
		break;
		
		case SPO_START_TIME:
		{
			if(*opt_val_len != sizeof(time_t)){
				ret = -1;
				
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_START_TIME error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			time_t *stime = (time_t *)opt_val;
			*stime = ABBR_SAPP_START_TIME;
		}
		break;

		case SPO_RUN_TIME:
		{
			if(*opt_val_len != sizeof(time_t)){
				ret = -1;
				
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_RUN_TIME error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			time_t *runtime = (time_t *)opt_val;
			*runtime = ABBR_CURRENT_TIME - ABBR_SAPP_START_TIME;
		}
		break;

		/* 外部插件频繁调用rand等函数比较消耗CPU, 使用CPU当前的时钟周期数, 和当前平台处理的包数拼成一个随机数 */
		case SPO_RAND_NUMBER:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_RAND_NUMBER error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}

			long long *rnum = (long long *)opt_val;

			*rnum = ((sapp_get_cpu_cycle() & 0xFFFF) << 48)
			         | ((sapp_global_val->mthread_volatile[0]->sys_stat.count[SAPP_STAT_RCV_ETHERNET] & 0xFFFF) << 32)
			         | ((sapp_global_val->mthread_volatile[0]->sys_stat.length[SAPP_STAT_RCV_ETHERNET] & 0xFFFF) << 16)
			         | ((sapp_global_val->mthread_volatile[0]->sys_stat.count[SAPP_STAT_RCV_IPV4] & 0xFFFF));
		}
		break;

		case SPO_FIELD_STAT_HANDLE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_FIELD_STAT_HANDLE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			void **out_handle = (void **)opt_val;
			*out_handle = sapp_global_val->individual_fixed.profiling_log_remote_handle;
		}
		break;

		case SPO_INDEPENDENT_THREAD_ID:
		{
			int id_index = -1;
			int *opt_int = (int *)opt_val;
			int i;
			pthread_t this_pid = pthread_self(); /* 获取当前线程id */
			
			pthread_mutex_lock(&g_plug_Independent_thread_mutex);

			/* 为避免一个线程多次调用此接口, 先查找之前是否保存过 */
			for(i = 0; i < sapp_global_val->config.cpu.send_only_threads_max_num; i++){
				if(g_plug_Independent_thread_pid[i] == this_pid){
					id_index = i;
					break;
				}
			}

			if(-1 == id_index){ /* 当前线程第一次创建, 没找到 */
				for(i = 0; i < sapp_global_val->config.cpu.send_only_threads_max_num; i++){
					if(0 == g_plug_Independent_thread_pid[i]){
						g_plug_Independent_thread_pid[i] = this_pid;
						break;
					}
				}
				if(i >= sapp_global_val->config.cpu.send_only_threads_max_num ){  /* 超过发包线程最大数量 */
					sapp_runtime_log(RLOG_LV_FATAL, "Independent_thread num more than CPU->send_only_threads_max:%d!\n", 
									sapp_global_val->config.cpu.send_only_threads_max_num);
					*opt_int = -1;
					ret = -1;
				}else{
					*opt_int = g_packet_io_thread_num + i; 
				}
			}else{
				*opt_int = g_packet_io_thread_num + id_index;
			}
			
			pthread_mutex_unlock(&g_plug_Independent_thread_mutex);
		}
		break;		

		case SPO_DEPLOYMENT_MODE_STR:
		{
			if(*opt_val_len <= strlen(sapp_global_val->config.packet_io.depolyment_mode_str)){
				ret = -1;
				
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_DEPLOYMENT_MODE_STR error:opt_val_len:%d is not enough!\n", *opt_val_len);
				break;
			}
			strncpy((char *)opt_val, sapp_global_val->config.packet_io.depolyment_mode_str, *opt_val_len);
		}
		break;

		case SPO_DEPLOYMENT_MODE:
		{
			if(*opt_val_len != sizeof(enum sapp_deploment_mode_t)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_DEPLOYMENT_MODE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}	
			enum sapp_deploment_mode_t *dep_mode = (enum sapp_deploment_mode_t *)opt_val;
			*dep_mode = (enum sapp_deploment_mode_t)sapp_global_val->config.packet_io.depolyment_mode_bin;			
		}
		break;

		case SPO_CURRENT_STATE:
		{
			if(*opt_val_len != sizeof(enum sapp_state_t)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CURRENT_STATE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			enum sapp_state_t *cur_stage = (enum sapp_state_t *)opt_val;
			*cur_stage = (enum sapp_state_t)sapp_global_val->individual_volatile->current_state;
		}

		case SPO_CONFIG_ROOT_DIR:
		{
			if(NULL == sapp_global_val->config.cfg_file_path.cfg_files_root_dir){
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CONFIG_ROOT_DIR error: no config root dir cmd args!\n");
				ret = -1;
				break;
			}
			if(*opt_val_len <= strlen(sapp_global_val->config.cfg_file_path.cfg_files_root_dir)+1){
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CONFIG_ROOT_DIR error:opt_val_len:%d is smaller than root dir string len!\n", *opt_val_len);
				ret = -1;
			}
			strncpy((char *)opt_val, sapp_global_val->config.cfg_file_path.cfg_files_root_dir, *opt_val_len);
		}
		break;

		case SPO_DATA_ROOT_DIR:
		{
			if(NULL == sapp_global_val->config.data_file_path.data_files_root_dir){
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CONFIG_ROOT_DIR error: no data root dir cmd args!\n");
				ret = -1;
				break;
			}		
			if(*opt_val_len <= strlen(sapp_global_val->config.data_file_path.data_files_root_dir)+1){
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_DATA_ROOT_DIR error:opt_val_len:%d is smaller than root dir string len!\n", *opt_val_len);
				ret = -1;
			}
			strncpy((char *)opt_val, sapp_global_val->config.data_file_path.data_files_root_dir, *opt_val_len);
		}
		break;
		
		default:
			
			sapp_runtime_log(RLOG_LV_FATAL, "sapp_get_platform_opt() error:opt_type:%d not support!\n", (int)opt);
			ret = -1;
	}

	return ret;
}

static int __sdo_get_dev_mtu(const char *device, int *mtu)
{
    struct ifreq ifr;
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0)
    {
	return -1;
    }

    memset(ifr.ifr_ifrn.ifrn_name, 0, sizeof(ifr.ifr_ifrn.ifrn_name));
    strncpy(ifr.ifr_ifrn.ifrn_name, device, sizeof(ifr.ifr_ifrn.ifrn_name));
    if(ioctl(fd, SIOCGIFMTU, &ifr) == -1) 
    {
        //perror("Cann't get ip addr:");
        goto err_exit;
    }

    *mtu = ifr.ifr_ifru.ifru_mtu;

    close(fd);

    return 0;

err_exit:
    close(fd);
    return -1;
}

int sapp_get_device_opt(const char *device, enum sapp_device_opt opt_type, void *opt_val, int *opt_val_len)
{
	int ret;
	unsigned char uchar_tmp_buf[8];
	//char *char_out_value;
	int int_out_value;
	
	if((NULL == opt_val) || (NULL == opt_val_len) || (*opt_val_len <= 0)){
		return -1;
	}

	switch((int)opt_type){
		case SDO_MAC_ADDR:
		{
			ret = MESA_get_dev_mac(device, uchar_tmp_buf);
			if(ret < 0){
				return ret;
			}
			if(*opt_val_len < ETH_ALEN){
				return -1;
			}
			memcpy(opt_val, uchar_tmp_buf, ETH_ALEN);
			*opt_val_len = ETH_ALEN;
			ret = 0;
		}
		break;

		case SDO_IPV4_ADDR:
		{
			ret = MESA_get_dev_ipv4(device, &int_out_value);
			if(ret < 0){
				return ret;
			}
			if(*opt_val_len < (int)sizeof(int)){
				return -1;
			}
			memcpy(opt_val, &int_out_value, sizeof(int));
			*opt_val_len = (int)sizeof(int);
			ret = 0;
		}
		break;

		case SDO_MTU:
		{
			ret = __sdo_get_dev_mtu(device, &int_out_value);
			if(ret < 0){
				return ret;
			}
			if(*opt_val_len < (int)sizeof(int)){
				return -1;
			}
			memcpy(opt_val, &int_out_value, sizeof(int));
			*opt_val_len = (int)sizeof(int);
			ret = 0;			
		}
		break;

		default:
			sapp_runtime_log(RLOG_LV_FATAL, "sapp_get_device_opt() error: opt_type:%d is invalid!\n", opt_type);
			return -1;
	}

	return ret;
}


#if 0
void sapp_statsd_flush_buf(void)
{
	struct sockaddr_in statsd_addr;

	if(sapp_global_single.statsd_fd < 0){
		return;
	}
	
	if(sapp_global_single.stats_send_ptr -  sapp_global_single.stats_send_buf > 0){
		statsd_addr.sin_family = AF_INET;
		statsd_addr.sin_addr.s_addr = sapp_global_single.statsd_ip_net;
		statsd_addr.sin_port = sapp_global_single.statsd_port_net;
		
		sendto(sapp_global_single.statsd_fd, 
			 sapp_global_single.stats_send_buf, 
			 sapp_global_single.stats_send_ptr -  sapp_global_single.stats_send_buf,
			  MSG_DONTWAIT, 
			  (struct sockaddr *)&statsd_addr,
			  sizeof(statsd_addr));
		sapp_global_single.stats_send_ptr = sapp_global_single.stats_send_buf;
	}
}

/*
	为了避免每个信息都发送一个UDP包, 此处先缓存, 到了MTU再发送.
	最后一条信息, 需要调用sapp_statsd_flush_buf()强制刷新一下.
*/
void sapp_statsd_add_para(const char *key, unsigned long long value)
{
	int ret;
	int line_len;
	char tmp_buf[128];

	if(sapp_global_single.statsd_fd < 0){
		return;
	}

	line_len = snprintf(tmp_buf, 128, "[sapp]%s:%lu|c\n", key, value);

	if(sapp_global_single.stats_send_ptr -  sapp_global_single.stats_send_buf + line_len > STATSD_SEND_MSS){
		sapp_statsd_flush_buf();
	}
	
	sprintf(sapp_global_single.stats_send_ptr, "%s", tmp_buf);

	sapp_global_single.stats_send_ptr += line_len;
}
#endif

void sapp_fs2_update_count(int field_index, unsigned  long long value)
{
	if(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle != NULL){
		FS_operate(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle, 
					sapp_global_val->individual_fixed.field_stat2_para.fs_id_count_array[field_index], 
					0, FS_OP_SET,  (long long)value);
	}
}

void sapp_fs2_update_length(int field_index, unsigned  long long value)
{
	if(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle != NULL){
		FS_operate(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle, 
					sapp_global_val->individual_fixed.field_stat2_para.fs_id_length_array[field_index],  
					0, FS_OP_SET,  (long long)value);
	}
}


void sapp_fs2_set_latency(int thead_seq, long long time_cost)
{
    if(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle != NULL){
        FS_operate(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle, 
        		   sapp_global_val->individual_fixed.field_stat2_para.fs_latency_id_array[thead_seq], 
        		   0, FS_OP_SET, time_cost);
    }
}


void sapp_fs2_set_plug_entry_latency(int entry_id, long long time_cost)
{
	if(unlikely(entry_id < 0 || entry_id >= SAPP_MAX_PLUG_ENTRY_NUM)){
		return;
	}
    if(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle != NULL){
        FS_operate(sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle, 
        		   sapp_global_val->individual_fixed.field_stat2_para.fs_latency_plug_entrg_id_array[entry_id], 
        		   0, FS_OP_SET, time_cost);
    }
}

/*
	模糊计算包处理延时, 不用每个包都调用一次FS_operate(),
	由sapp timer线程每隔一段时间调用sapp_fuzzy_latency_update(), 更新filed_stat2计数.
*/
void sapp_fs2_fuzzy_latency_update_per_thread(int thead_seq, long long time_cost)
{
	sapp_fuzzy_latency_stat_t *this_thread_stat = &sapp_global_val->mthread_volatile[thead_seq]->fuzzy_pkt_latency_stat_per_thread;

	if(time_cost < this_thread_stat->min_time_cost){
		this_thread_stat->min_time_cost = time_cost;
	}

	if(time_cost > this_thread_stat->max_time_cost){
		this_thread_stat->max_time_cost = time_cost;
	}
	
	this_thread_stat->time_cost_sum += time_cost;
	this_thread_stat->stat_count++;
}

void sapp_fs2_fuzzy_latency_update_per_entry(int thead_seq, int entry_id, long long time_cost)
{
	sapp_fuzzy_latency_stat_t *this_thread_stat;
	if(unlikely(entry_id < 0 || entry_id >= SAPP_MAX_PLUG_ENTRY_NUM)){
		return;
	}	

	this_thread_stat = &sapp_global_val->mthread_volatile[thead_seq]->fuzzy_pkt_latency_stat_per_entry_per_thread[entry_id];

	if(time_cost < this_thread_stat->min_time_cost){
		this_thread_stat->min_time_cost = time_cost;
	}

	if(time_cost > this_thread_stat->max_time_cost){
		this_thread_stat->max_time_cost = time_cost;
	}
	
	this_thread_stat->time_cost_sum += time_cost;
	this_thread_stat->stat_count++;

}


/*
	由sapp timer独立线程调用, 每隔一段时间, 将积累的包处理延时数据刷新给field_stat2.
*/
void sapp_fuzzy_latency_update(void)
{
	int tid, entry_id, this_stat_count;
	long long min_latency, max_latency;
	double avg_latency;
	sapp_fuzzy_latency_stat_t *this_thread_stat, *this_entry_stat;
	
	if(sapp_global_val->config.profiling.pkt_latency_accurate_enable != 0){
		/* 精确模式, 单包调用FS_operate(), 此处无需再处理 */
		return;
	}

	for(tid = 0; tid < g_packet_io_thread_num; tid++){
		this_thread_stat = &sapp_global_val->mthread_volatile[tid]->fuzzy_pkt_latency_stat_per_thread;
		avg_latency = (double)this_thread_stat->time_cost_sum/(double)this_thread_stat->stat_count;
		min_latency = this_thread_stat->min_time_cost;
		max_latency = this_thread_stat->max_time_cost;
		this_stat_count = this_thread_stat->stat_count;

		if(this_stat_count > 0){
			memset(this_thread_stat, 0, sizeof(sapp_fuzzy_latency_stat_t));
			this_thread_stat->min_time_cost = 999999999; /* 要记录最小值, 初始化要设成最大值 */

			/* 每次更新三个值, 最大,最小和平均值 */
			sapp_fs2_set_latency(tid, min_latency);
			sapp_fs2_set_latency(tid, max_latency);
			sapp_fs2_set_latency(tid, (long long)avg_latency);
		}
		
		for(entry_id = 1; entry_id < g_plug_global_entry_index; entry_id++){
			this_entry_stat = &sapp_global_val->mthread_volatile[tid]->fuzzy_pkt_latency_stat_per_entry_per_thread[entry_id];
			avg_latency = (double)this_entry_stat->time_cost_sum/(double)this_entry_stat->stat_count;
			min_latency = this_entry_stat->min_time_cost;
			max_latency = this_entry_stat->max_time_cost;
			this_stat_count = this_entry_stat->stat_count;
			if(this_stat_count > 0){
				memset(this_entry_stat, 0, sizeof(sapp_fuzzy_latency_stat_t));
				this_entry_stat->min_time_cost = 999999999; /* 要记录最小值, 初始化要设成最大值 */
				
				sapp_fs2_set_latency(tid, min_latency);
				sapp_fs2_set_latency(tid, max_latency);
				sapp_fs2_set_plug_entry_latency(entry_id, (long long)avg_latency);
			}
		}
	}
}


int sapp_independent_thread_init(void)
{
	pthread_mutex_init(&g_plug_Independent_thread_mutex, NULL);

	if(sapp_global_val->config.cpu.send_only_threads_max_num > 0){
		g_plug_Independent_thread_pid = (pthread_t *)calloc(g_packet_io_thread_num + sapp_global_val->config.cpu.send_only_threads_max_num, sizeof(pthread_t));
	}

	return 0;
}

int sapp_assistant_init(void)
{
	sapp_fs2_init();
	
	return 0;
}


#ifdef __cplusplus
}
#endif


static int fs2_plug_entry_historgram_init(void *fs2_handle)
{
	int i;
	sapp_gval_individual_fixed_fs_t *pfs_para = &sapp_global_val->individual_fixed.field_stat2_para;

	/* 0保留给sapp内置插件, index从1开始 */
	for(i = 1; i < g_plug_global_entry_index; i++){
		pfs_para->fs_latency_plug_entrg_id_array[i] = FS_register_histogram(fs2_handle,  //Field Stat句柄
								  FS_CALC_SPEED,    //输出累计值或瞬时值
								  g_plug_global_entry[i].plug_entry_name,     //统计项名称，字符串
								  1,                  //可追踪的最小值
								  1000000,            //可追踪的最大值
								  2);                 //精度，即小数点后几位，范围1~4
	}

	return 0;
}


/************************ C++ compiler **************************************/
static int sapp_fs2_init(void)
{
	char cfg_ip_str[32];
	char fs_name[1024];
	int cfg_port;
	int fs2_opt;
	int cycle;
	int send_historgram = 0;
	void *fs2_handle;
	unsigned short fs_server_port;
	sapp_gval_individual_fixed_fs_t *pfs_para = &sapp_global_val->individual_fixed.field_stat2_para;
	int fs2_local_enabled = 0;
	int fs2_remote_enabled = 0;

	if(sapp_global_val->config.profiling.log.remote.enabled){
		if(strncasecmp(sapp_global_val->config.profiling.log.remote.remote_send_out_type, "field_stat2", strlen("field_stat2")) == 0){
			fs2_remote_enabled = 1;
		}else{
			sapp_log(RLOG_LV_INFO, 10, 10, "profiling.log.remote.enabled, remote_send_out_type is line_protocol, field_stat2 send metrics to server is disable.\n");
			fs2_remote_enabled = 0;
		}
	}else{
		fs2_remote_enabled = 0;
	}
	
	fs2_local_enabled = sapp_global_val->config.profiling.log.local.enabled;

	sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle = FS_create_handle();
	if(NULL == sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle){
		sapp_log(RLOG_LV_FATAL, 30, 30, "FS_create_handle() error: %s!\n", strerror(errno));
		return -1;
	}

	if(sapp_global_val->config.profiling.log.prometheus.enabled){
		FS_library_set_prometheus_port((unsigned short)sapp_global_val->config.profiling.log.prometheus.port);
		FS_library_set_prometheus_url_path(sapp_global_val->config.profiling.log.prometheus.url_path);
		if(FS_library_init() < 0){
			sapp_log(RLOG_LV_FATAL, 30, 30, "FS_library_init() error, port:%d, url:%s\n", 
					sapp_global_val->config.profiling.log.prometheus.port,
					sapp_global_val->config.profiling.log.prometheus.url_path);
			return -1;			
		}
	}

	fs2_handle = sapp_global_val->individual_fixed.field_stat2_para.field_stat2_handle;
	if(fs2_remote_enabled){
		sapp_global_val->individual_fixed.profiling_log_remote_handle = fs2_handle;
	}
	FS_set_para(fs2_handle, STAT_CYCLE, &sapp_global_val->config.profiling.log.interval, sizeof(int));

	if(sapp_global_val->config.profiling.log.local.file_truncate_enabled){
		fs2_opt = 1; /* 1:Rewrite ,2: Append.  */
	}else{
		fs2_opt = 2; /* 1:Rewrite ,2: Append.  */
	}
	FS_set_para(fs2_handle, PRINT_MODE, &fs2_opt, sizeof(int));

	fs2_opt = 1;
	FS_set_para(fs2_handle, PRINT_TRIGGER, &fs2_opt, sizeof(int));

	fs2_opt = 1;
    FS_set_para(fs2_handle, NOT_SEND_METRIC_TO_SERVER, &fs2_opt, sizeof(int));

	if(fs2_local_enabled){
    	FS_set_para(fs2_handle, OUTPUT_DEVICE, ABBR_FS2_LOG_DATA_FILE, strlen(ABBR_FS2_LOG_DATA_FILE)+1);
	}else{
		sapp_log(RLOG_LV_INFO, 10, 10, "profiling.log.local.enabled is 0, not save local stat log file.\n");
		FS_set_para(fs2_handle, OUTPUT_DEVICE, "/dev/null", strlen("/dev/null") + 1);
	}
	FS_set_para(fs2_handle, APP_NAME, sapp_global_val->config.profiling.log.remote.field_stat2.app_name, strlen(sapp_global_val->config.profiling.log.remote.field_stat2.app_name)+1);

	if(fs2_remote_enabled){
		FS_set_para(fs2_handle, STATS_SERVER_IP, (void *)sapp_global_val->config.profiling.log.remote.server_ip, strlen(sapp_global_val->config.profiling.log.remote.server_ip)+1);
		fs_server_port = (unsigned short)sapp_global_val->config.profiling.log.remote.server_port;
		FS_set_para(fs2_handle, STATS_SERVER_PORT, &fs_server_port, sizeof(short));
	}

	FS_set_para(fs2_handle, METRIS_FORMAT, &sapp_global_val->config.profiling.log.remote.field_stat2.metrics_type, sizeof(int));

	if(sapp_global_val->config.profiling.log.prometheus.enabled){
		fs2_opt = 1;
		FS_set_para(fs2_handle, OUTPUT_PROMETHEUS, &fs2_opt, sizeof(int));
	}

	pfs_para->fs_id_count_array[SAPP_STAT_RCV_LINE] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Line_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_LINE] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Line_Bit");
	
	pfs_para->fs_id_count_array[SAPP_STAT_RCV_ETHERNET] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Eth_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_ETHERNET] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Eth_Bit");

	if((DEPOLYMENT_MODE_INLINE == sapp_global_val->config.packet_io.depolyment_mode_bin)
	 || (DEPOLYMENT_MODE_TRANSPARENT == sapp_global_val->config.packet_io.depolyment_mode_bin)){
		pfs_para->fs_id_count_array[SAPP_STAT_ETH_INBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Pkt_Inbound");
		pfs_para->fs_id_length_array[SAPP_STAT_ETH_INBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Bit_Inbound");	 
		pfs_para->fs_id_count_array[SAPP_STAT_ETH_OUTBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Pkt_Outbound");
		pfs_para->fs_id_length_array[SAPP_STAT_ETH_OUTBOUND] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Bit_Outbound");			
	}

	pfs_para->fs_id_count_array[SAPP_STAT_RCV_IPV4] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv4_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_IPV4] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv4_Bit");

	pfs_para->fs_id_count_array[SAPP_STAT_RCV_IPV6] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv6_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_IPV6] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Ipv6_Bit");

	pfs_para->fs_id_count_array[SAPP_STAT_RCV_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bit");
	pfs_para->fs_id_count_array[SAPP_STAT_RCV_DUP_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Tcp_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_DUP_TCP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Tcp_Bit");
    pfs_para->fs_id_length_array[SAPP_STAT_TCP_LOST_PKT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Lost_Bit");	
	pfs_para->fs_id_count_array[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Lost_STM");	

    pfs_para->fs_id_count_array[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Close_byT");	
	pfs_para->fs_id_count_array[SAPP_STAT_TCP_CLOSE_BY_KICKOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Close_byK");	
	
	pfs_para->fs_id_count_array[SAPP_STAT_RCV_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bit");
	pfs_para->fs_id_count_array[SAPP_STAT_RCV_DUP_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Udp_Pkt");
	pfs_para->fs_id_length_array[SAPP_STAT_RCV_DUP_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Dup_Udp_Bit");

    pfs_para->fs_id_count_array[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Close_byT");	
	pfs_para->fs_id_count_array[SAPP_STAT_UDP_CLOSE_BY_KICKOUT] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Close_byK");	
	
	pfs_para->fs_id_count_array[SAPP_STAT_RCV_UNKNOWN] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Unknown_Pkt");
	pfs_para->fs_id_count_array[SAPP_STAT_RCV_UNKNOWN] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Unknown_Bit");

	pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_NEW] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Link_New");
	pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_DEL] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Link_Del");
	pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_DATA] = FS_register(fs2_handle, FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Concurrent");

    pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Tcp_Link_Double");
    pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_C2S");
    pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_S2C");

    pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Tcp_Link_Double_ALL");
    pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_TOTAL_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_C2S_ALL");
    pfs_para->fs_id_count_array[SAPP_STAT_TCP_STREAM_TOTAL_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Tcp_Link_S2C_ALL");
 

    pfs_para->fs_id_count_array[SAPP_STAT_UDP_STREAM_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Udp_Link_Double");
    pfs_para->fs_id_count_array[SAPP_STAT_UDP_STREAM_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_C2S");
    pfs_para->fs_id_count_array[SAPP_STAT_UDP_STREAM_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_S2C");

    pfs_para->fs_id_count_array[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE] = FS_register(fs2_handle, FS_STYLE_STATUS,FS_CALC_CURRENT, "Udp_Link_Double_ALL");
    pfs_para->fs_id_count_array[SAPP_STAT_UDP_STREAM_TOTAL_C2S] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_C2S_ALL");
    pfs_para->fs_id_count_array[SAPP_STAT_UDP_STREAM_TOTAL_S2C] = FS_register(fs2_handle,FS_STYLE_STATUS, FS_CALC_CURRENT, "Udp_Link_S2C_ALL");


    pfs_para->fs_id_count_array[SAPP_STAT_SND_TCP_RST] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Send_Tcp_Rst");
	pfs_para->fs_id_count_array[SAPP_STAT_SND_TCP_SYNACK] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Send_Tcp_S/A");
	pfs_para->fs_id_count_array[SAPP_STAT_SND_UDP] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Send_Udp");

	pfs_para->fs_id_count_array[SAPP_STAT_TCP_BYPASS_STREAM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bypass_STM");	
	pfs_para->fs_id_count_array[SAPP_STAT_TCP_BYPASS_PKTS] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bypass_Pkt");
	pfs_para->fs_id_count_array[SAPP_STAT_TCP_BYPASS_BYTES] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Tcp_Bypass_Bit");

	pfs_para->fs_id_count_array[SAPP_STAT_UDP_BYPASS_STREAM] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bypass_STM");	
	pfs_para->fs_id_count_array[SAPP_STAT_UDP_BYPASS_PKTS] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bypass_Pkt");
	pfs_para->fs_id_count_array[SAPP_STAT_UDP_BYPASS_BYTES] = FS_register(fs2_handle, FS_STYLE_FIELD, FS_CALC_CURRENT, "Udp_Bypass_Bit");

	
	if(unlikely(g_timestamp_record_sw))
	{
		for(int i = 0; i < g_packet_io_thread_num; i++)
		{
			char histogram_name[16];
			sprintf(histogram_name, "tid_%d(ns)", i);
			pfs_para->fs_latency_id_array[i] = FS_register_histogram(fs2_handle,  //Field Stat句柄
								  FS_CALC_SPEED,    //输出累计值或瞬时值
								  histogram_name,     //统计项名称，字符串
								  1,                  //可追踪的最小值
								  1000000,            //可追踪的最大值
								  2);                 //精度，即小数点后几位，范围1~4
			if(send_historgram == 0)
            {
                FS_set_para(fs2_handle, NOT_SEND_METRIC_TO_SERVER, &pfs_para->fs_latency_id_array[i], sizeof(int));
            }
		}

		fs2_plug_entry_historgram_init(fs2_handle);
	}
	FS_start(fs2_handle);
	
	return 0;
}


static int sapp_line_protocol_init(void)
{
	log_line_protocol_handle_t *lp_handle;

	if(0 == sapp_global_val->config.profiling.log.remote.enabled){
		sapp_log(RLOG_LV_INFO, 10, 10, "profiling.log.remote.enabled = 0, line protocol is disable.\n");
		return 0;
	}

	if(strncasecmp(sapp_global_val->config.profiling.log.remote.remote_send_out_type, "line_protocol", strlen("line_protocol")) != 0){
		sapp_log(RLOG_LV_INFO, 10, 10, "profiling.log.remote.enabled, remote_send_out_type is field_stat2, line protocol is disable.\n");
		return 0;
	}

	lp_handle = (log_line_protocol_handle_t *)calloc(1, sizeof(log_line_protocol_handle_t));

	lp_handle->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    lp_handle->sock_addr.sin_family = AF_INET;
    inet_pton(AF_INET, sapp_global_val->config.profiling.log.remote.server_ip, &lp_handle->sock_addr.sin_addr.s_addr);
    lp_handle->sock_addr.sin_port = ntohs((unsigned short)sapp_global_val->config.profiling.log.remote.server_port);

    lp_handle->last_send_metrics_time = 0;

	sapp_global_val->individual_fixed.profiling_log_remote_handle = lp_handle;
	
	return 0;
}

