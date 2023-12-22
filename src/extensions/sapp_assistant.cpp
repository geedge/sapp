/*
	���ļ���ƽ̨���Ĺ��ܺͺ���(Ip��Ƭ, ����ԭ, ��������, ���������), 
	���ṩ������ҵ�����Ľӿ�, ��sapp_get_platform_opt��, ��Ϊһ��.so�ļ����ص�ƽ̨,
	���ڸ��²���.
*/
#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"


#include "marsio.h"



//extern time_t g_CurrentTime;//add by lqy 20070606
//extern int g_packet_io_thread_num;
extern char g_app_instance_name[64];

static pthread_mutex_t g_plug_Independent_thread_mutex;
static pthread_t *g_plug_Independent_thread_pid;


static const unsigned char G_BROADCAST_ADDR[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

extern "C" int MESA_get_dev_ipv4(const char *device, int *ip_add);
extern "C" int MESA_get_dev_mac(const char *device, unsigned char mac[6]);

void * (*dl_marsio_buff_ctrlzone)(void *m, uint8_t id);
extern void * (*ptr_marsio_buff_ctrlzone)(marsio_buff_t *m, uint8_t id);


/* ʶ���Ƿ������ڲ����ݰ�           , �����ڵİ�Ӧ��������ת��/��ע        */
int sapp_identify_tunnel_inner_pkt(const raw_pkt_t *raw_pkt)
{
	int ret = 0;
#if IOMODE_MARSIO
	if (CAP_MODEL_MARSIOV4 == g_packet_io_cap_mode)
	{
		/* û��mrtunnatʱ, �������l2_l3_tunnel_support, Ҫ�ж�overlay����, �Ƿ��Ǹ�������, �Ƿ��Ǿ���overlayԭʼ��·��İ�    */
		if (raw_pkt->is_overlay_pkt)
		{
			ret = 1;
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
		/* G����ģʽ�£���ARPЭ��Ĺ㲥����ֱ�Ӷ���! ��ֹ�ٻ�ע��������, ��ɹ㲥�籩���������� */
		if(eth_type != ETH_P_ARP){
			return 1;
		}
	}else{
		/* 2017-10-10 lijia add, �鲥MAC��ַ, ͨ��Ϊ�������ڿ��������ݰ�, ��LLMNR, STP��Э��, һ�����账�� 
			�ο�:https://en.wikipedia.org/wiki/Multicast_address 
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

/* 2017-09-04 lijia add, for ��������, �����ȡƽ̨�ڲ����� */
extern "C" int sapp_get_platform_opt(enum sapp_platform_opt opt, void *opt_val, int *opt_val_len)
{
	int ret = 0;

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
			*tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_RCV_ETHERNET);;
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
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_UDP_STREAM_MORE);
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
			*tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_IPV4_OUTBOUND);
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
			*tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_IPV4_OUTBOUND);
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
			*tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_IPV6_OUTBOUND);
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
			*tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_IPV6_OUTBOUND);
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
			*tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_TCP_OUTBOUND);
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
			*tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_TCP_OUTBOUND);
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
			*tot_byte = __get_platform_opt_traffic('c', SAPP_STAT_UDP_OUTBOUND);
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
			*tot_byte = __get_platform_opt_traffic('l', SAPP_STAT_UDP_OUTBOUND);
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
			*curtime_ms = g_CurrentTime_ms;

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

		/* �ⲿ���Ƶ������rand�Ⱥ����Ƚ�����CPU, ʹ��CPU��ǰ��ʱ��������, �͵�ǰƽ̨�����İ���ƴ��һ������� */
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
			ret = -1;
			sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_FIELD_STAT_HANDLE error: obsolete option");
			break;
		}
		break;

		case SPO_INDEPENDENT_THREAD_ID:
		{
			int id_index = -1;
			int *opt_int = (int *)opt_val;
			int i;
			pthread_t this_pid = pthread_self(); /* ��ȡ��ǰ�߳�id */
			
			pthread_mutex_lock(&g_plug_Independent_thread_mutex);

			/* Ϊ����һ���̶߳�ε��ô˽ӿ�, �Ȳ���֮ǰ�Ƿ񱣴�� */
			for(i = 0; i < sapp_global_val->config.cpu.send_only_threads_max_num; i++){
				if(g_plug_Independent_thread_pid[i] == this_pid){
					id_index = i;
					break;
				}
			}

			if(-1 == id_index){ /* ��ǰ�̵߳�һ�δ���, û�ҵ� */
				for(i = 0; i < sapp_global_val->config.cpu.send_only_threads_max_num; i++){
					if(0 == g_plug_Independent_thread_pid[i]){
						g_plug_Independent_thread_pid[i] = this_pid;
						break;
					}
				}
				if(i >= sapp_global_val->config.cpu.send_only_threads_max_num ){  /* ���������߳�������� */
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
			if(*opt_val_len <= (int)strlen(sapp_global_val->config.packet_io.deployment_mode_str)){
				ret = -1;
				
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_DEPLOYMENT_MODE_STR error:opt_val_len:%d is not enough!\n", *opt_val_len);
				break;
			}
			strncpy((char *)opt_val, sapp_global_val->config.packet_io.deployment_mode_str, *opt_val_len);
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
			*dep_mode = (enum sapp_deploment_mode_t)sapp_global_val->config.packet_io.deployment_mode_bin;			
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
		break;

		case SPO_CONFIG_ROOT_DIR:
		{
			if(NULL == sapp_global_val->config.cfg_file_path.cfg_files_root_dir){
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_CONFIG_ROOT_DIR error: no config root dir cmd args!\n");
				ret = -1;
				break;
			}
			if(*opt_val_len <= (int)strlen(sapp_global_val->config.cfg_file_path.cfg_files_root_dir)+1){
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
			if(*opt_val_len <= (int)strlen(sapp_global_val->config.data_file_path.data_files_root_dir)+1){
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_DATA_ROOT_DIR error:opt_val_len:%d is smaller than root dir string len!\n", *opt_val_len);
				ret = -1;
			}
			strncpy((char *)opt_val, sapp_global_val->config.data_file_path.data_files_root_dir, *opt_val_len);
		}
		break;
		
		case SPO_TCP_STREAM_C2S:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TCP_STREAM_C2S error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_TCP_STREAM_TOTAL_C2S);
		}
		break;	
				
		case SPO_TCP_STREAM_S2C:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TCP_STREAM_S2C error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_TCP_STREAM_TOTAL_S2C);
		}
		break;	

		case SPO_TCP_STREAM_DOUBLE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_TCP_STREAM_DOUBLE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE);
		}
		break;	

		case SPO_UDP_STREAM_C2S:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_UDP_STREAM_C2S error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_UDP_STREAM_TOTAL_C2S);
		}
		break;	
				
		case SPO_UDP_STREAM_S2C:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_UDP_STREAM_S2C error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_UDP_STREAM_TOTAL_S2C);
		}
		break;	

		case SPO_UDP_STREAM_DOUBLE:
		{
			if(*opt_val_len != sizeof(long long)){
				ret = -1;
				sapp_runtime_log(RLOG_LV_INFO, "sapp_get_platform_opt() SPO_UDP_STREAM_DOUBLE error:opt_val_len:%d is invalid!\n", *opt_val_len);
				break;
			}
			unsigned long long *tot_num = (unsigned long long *)opt_val;
			*tot_num = __get_platform_opt_traffic('c', SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE);
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
		fprintf(stderr, "__sdo_get_dev_mtu(%s), ioctl SIOCGIFMTU: %s\n", device, strerror(errno));
        goto err_exit;
    }

    *mtu = ifr.ifr_ifru.ifru_mtu;

    close(fd);

    return 0;

err_exit:
    close(fd);
    return -1;
}

extern "C" int sapp_get_device_opt(const char *device, enum sapp_device_opt opt_type, void *opt_val, int *opt_val_len)
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

int sapp_independent_thread_init(void)
{
	pthread_mutex_init(&g_plug_Independent_thread_mutex, NULL);

	if(sapp_global_val->config.cpu.send_only_threads_max_num > 0){
		g_plug_Independent_thread_pid = (pthread_t *)calloc(g_packet_io_thread_num + sapp_global_val->config.cpu.send_only_threads_max_num, sizeof(pthread_t));
	}

	return 0;
}
