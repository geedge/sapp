#include "field_stat2.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"
#include <stdarg.h>

volatile int update_packet_io_status_sw = 1;

static unsigned long long cur_count[SAPP_STAT_NUM_MAX] = {0};
static unsigned long long cur_length[SAPP_STAT_NUM_MAX] = {0};


static unsigned long long history_count[SAPP_STAT_NUM_MAX];
static unsigned long long history_length[SAPP_STAT_NUM_MAX];

//extern int g_packet_io_thread_num;
extern void sapp_statsd_add_para(const char *key, unsigned long long value);
extern void pkt_runtime_output(void);
extern void sapp_statsd_flush_buf(void);
extern struct sapp_global_mthread_t sapp_global_mthread[MAX_THREAD_NUM];




static void packet_io_update_metrics_fs2(void)
{
	/* 2018-08-29 lijia add field statsd */
	sapp_fs2_update_count(SAPP_STAT_RCV_UNKNOWN, cur_count[SAPP_STAT_RCV_UNKNOWN]);
	sapp_fs2_update_length(SAPP_STAT_RCV_UNKNOWN, 8 *( cur_length[SAPP_STAT_RCV_UNKNOWN])); /* to bps, bit per second */

	sapp_fs2_update_count(SAPP_STAT_RCV_LINE, cur_count[SAPP_STAT_RCV_LINE]);
	sapp_fs2_update_length(SAPP_STAT_RCV_LINE, 8 *( cur_length[SAPP_STAT_RCV_LINE])); /* to bps, bit per second */

	sapp_fs2_update_count(SAPP_STAT_SND_ERROR, cur_count[SAPP_STAT_SND_ERROR]);
	sapp_fs2_update_length(SAPP_STAT_SND_ERROR, 8 *( cur_length[SAPP_STAT_SND_ERROR])); /* to bps, bit per second */

	
	sapp_fs2_update_count(SAPP_STAT_RCV_ETHERNET, cur_count[SAPP_STAT_RCV_ETHERNET]);
	sapp_fs2_update_length(SAPP_STAT_RCV_ETHERNET, 8 *( cur_length[SAPP_STAT_RCV_ETHERNET])); /* to bps, bit per second */

	if((DEPLOYMENT_MODE_INLINE == sapp_global_val->config.packet_io.deployment_mode_bin)
	 || (DEPLOYMENT_MODE_TRANSPARENT == sapp_global_val->config.packet_io.deployment_mode_bin)){
		sapp_fs2_update_count(SAPP_STAT_ETH_INBOUND, cur_count[SAPP_STAT_ETH_INBOUND]);
		sapp_fs2_update_length(SAPP_STAT_ETH_INBOUND, 8 *( cur_length[SAPP_STAT_ETH_INBOUND])); /* to bps, bit per second */

		sapp_fs2_update_count(SAPP_STAT_ETH_OUTBOUND, cur_count[SAPP_STAT_ETH_OUTBOUND]);
		sapp_fs2_update_length(SAPP_STAT_ETH_OUTBOUND, 8 *( cur_length[SAPP_STAT_ETH_OUTBOUND])); /* to bps, bit per second */
	}
	
	sapp_fs2_update_count(SAPP_STAT_RCV_IPV4, cur_count[SAPP_STAT_RCV_IPV4]);
	sapp_fs2_update_length(SAPP_STAT_RCV_IPV4, 8 *(cur_length[SAPP_STAT_RCV_IPV4]));

	sapp_fs2_update_count(SAPP_STAT_RCV_IPV6, cur_count[SAPP_STAT_RCV_IPV6]);
	sapp_fs2_update_length(SAPP_STAT_RCV_IPV6, 8 *(cur_length[SAPP_STAT_RCV_IPV6]));

	sapp_fs2_update_count(SAPP_STAT_RCV_TCP, cur_count[SAPP_STAT_RCV_TCP]);
	sapp_fs2_update_length(SAPP_STAT_RCV_TCP, 8 *(cur_length[SAPP_STAT_RCV_TCP]));

	sapp_fs2_update_count(SAPP_STAT_RCV_DUP_TCP, cur_count[SAPP_STAT_RCV_DUP_TCP]);
	sapp_fs2_update_length(SAPP_STAT_RCV_DUP_TCP, 8 *(cur_length[SAPP_STAT_RCV_DUP_TCP]));
	sapp_fs2_update_count(SAPP_STAT_DUP_IDENTIFY_ERR, cur_count[SAPP_STAT_DUP_IDENTIFY_ERR]);
	
	sapp_fs2_update_length(SAPP_STAT_TCP_LOST_PKT, 8 *(cur_length[SAPP_STAT_TCP_LOST_PKT]));
	sapp_fs2_update_count(SAPP_STAT_TCP_LOST_PKT_STREAM_NUM, cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]);

	sapp_fs2_update_count(SAPP_STAT_TCP_CLOSE_BY_TIMEOUT, cur_count[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT]);
	sapp_fs2_update_count(SAPP_STAT_TCP_CLOSE_BY_KICKOUT, cur_count[SAPP_STAT_TCP_CLOSE_BY_KICKOUT]);
	
	sapp_fs2_update_count(SAPP_STAT_RCV_UDP, cur_count[SAPP_STAT_RCV_UDP]);	
	sapp_fs2_update_length(SAPP_STAT_RCV_UDP, 8 *(cur_length[SAPP_STAT_RCV_UDP]));

	sapp_fs2_update_count(SAPP_STAT_RCV_DUP_UDP, cur_count[SAPP_STAT_RCV_DUP_UDP]);	
	sapp_fs2_update_length(SAPP_STAT_RCV_DUP_UDP, 8 *(cur_length[SAPP_STAT_RCV_DUP_UDP]));

	sapp_fs2_update_count(SAPP_STAT_UDP_CLOSE_BY_TIMEOUT, cur_count[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT]);
	sapp_fs2_update_count(SAPP_STAT_UDP_CLOSE_BY_KICKOUT, cur_count[SAPP_STAT_UDP_CLOSE_BY_KICKOUT]);
	
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_NEW,cur_count[SAPP_STAT_TCP_STREAM_NEW]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_DEL, cur_count[SAPP_STAT_TCP_STREAM_DEL]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_DATA, cur_count[SAPP_STAT_TCP_STREAM_DATA]);

	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_NEW,cur_count[SAPP_STAT_UDP_STREAM_NEW]);
	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_DEL, cur_count[SAPP_STAT_UDP_STREAM_DEL]);
	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_MORE, cur_count[SAPP_STAT_UDP_STREAM_MORE]);
	
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_DOUBLE,cur_count[SAPP_STAT_TCP_STREAM_DOUBLE]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_C2S, cur_count[SAPP_STAT_TCP_STREAM_C2S]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_S2C, cur_count[SAPP_STAT_TCP_STREAM_S2C]);

	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE,cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_TOTAL_C2S, cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S]);
	sapp_fs2_update_count(SAPP_STAT_TCP_STREAM_TOTAL_S2C, cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C]);
	

	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_DOUBLE,cur_count[SAPP_STAT_UDP_STREAM_DOUBLE]);
	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_C2S, cur_count[SAPP_STAT_UDP_STREAM_C2S]);
	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_S2C, cur_count[SAPP_STAT_UDP_STREAM_S2C]);

	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE,cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE]);
	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_TOTAL_C2S, cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S]);
	sapp_fs2_update_count(SAPP_STAT_UDP_STREAM_TOTAL_S2C, cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C]);
	
	sapp_fs2_update_count(SAPP_STAT_SND_TCP_RST,  cur_count[SAPP_STAT_SND_TCP_RST]);
	sapp_fs2_update_count(SAPP_STAT_SND_TCP_SYNACK,  cur_count[SAPP_STAT_SND_TCP_SYNACK]);
	sapp_fs2_update_count(SAPP_STAT_SND_UDP,  cur_count[SAPP_STAT_SND_UDP]);

	sapp_fs2_update_count(SAPP_STAT_GLOBAL_BYPASS, packet_io_under_ddos_global_status());

	sapp_fs2_update_count(SAPP_STAT_TCP_BYPASS_STREAM,  cur_count[SAPP_STAT_TCP_BYPASS_STREAM]);
	sapp_fs2_update_count(SAPP_STAT_TCP_BYPASS_PKTS,  cur_count[SAPP_STAT_TCP_BYPASS_PKTS]);
	sapp_fs2_update_length(SAPP_STAT_TCP_BYPASS_BYTES,  cur_length[SAPP_STAT_TCP_BYPASS_BYTES]);

	sapp_fs2_update_count(SAPP_STAT_UDP_BYPASS_STREAM,  cur_count[SAPP_STAT_UDP_BYPASS_STREAM]);
	sapp_fs2_update_count(SAPP_STAT_UDP_BYPASS_PKTS,  cur_count[SAPP_STAT_UDP_BYPASS_PKTS]);
	sapp_fs2_update_length(SAPP_STAT_UDP_BYPASS_BYTES,  cur_length[SAPP_STAT_UDP_BYPASS_BYTES]);	

	sapp_fs2_update_count(SAPP_STAT_TCP_OFFLOAD_STREAM,  cur_count[SAPP_STAT_TCP_OFFLOAD_STREAM]);
	sapp_fs2_update_count(SAPP_STAT_TCP_OFFLOAD_PKTS,  cur_count[SAPP_STAT_TCP_OFFLOAD_PKTS]);
	sapp_fs2_update_length(SAPP_STAT_TCP_OFFLOAD_BYTES,  cur_length[SAPP_STAT_TCP_OFFLOAD_BYTES]);

	sapp_fs2_update_count(SAPP_STAT_UDP_OFFLOAD_STREAM,  cur_count[SAPP_STAT_UDP_OFFLOAD_STREAM]);
	sapp_fs2_update_count(SAPP_STAT_UDP_OFFLOAD_PKTS,  cur_count[SAPP_STAT_UDP_OFFLOAD_PKTS]);
	sapp_fs2_update_length(SAPP_STAT_UDP_OFFLOAD_BYTES,  cur_length[SAPP_STAT_UDP_OFFLOAD_BYTES]);

	sapp_fs2_update_count(SAPP_STAT_UDP_DUP_KICK_STREAM,  cur_count[SAPP_STAT_UDP_DUP_KICK_STREAM]);
}

static void packet_io_update_metrics_fs3(void)
{
	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_UNKNOWN,cur_count[SAPP_STAT_RCV_UNKNOWN]-history_count[SAPP_STAT_RCV_UNKNOWN]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_UNKNOWN, 8 *( cur_length[SAPP_STAT_RCV_UNKNOWN]-history_length[SAPP_STAT_RCV_UNKNOWN])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_LINE,cur_count[SAPP_STAT_RCV_LINE]-history_count[SAPP_STAT_RCV_LINE]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_LINE, 8 *( cur_length[SAPP_STAT_RCV_LINE]-history_length[SAPP_STAT_RCV_LINE])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_SND_ERROR,cur_count[SAPP_STAT_SND_ERROR]-history_count[SAPP_STAT_SND_ERROR]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_SND_ERROR, 8 *( cur_length[SAPP_STAT_SND_ERROR]-history_length[SAPP_STAT_SND_ERROR])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_ETHERNET,cur_count[SAPP_STAT_RCV_ETHERNET]-history_count[SAPP_STAT_RCV_ETHERNET]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_ETHERNET, 8 *( cur_length[SAPP_STAT_RCV_ETHERNET]-history_length[SAPP_STAT_RCV_ETHERNET])); /* to bps, bit per second */

	if((DEPLOYMENT_MODE_INLINE == sapp_global_val->config.packet_io.deployment_mode_bin)
	 || (DEPLOYMENT_MODE_TRANSPARENT == sapp_global_val->config.packet_io.deployment_mode_bin)){
		sapp_fs3_metric_incrby(0, SAPP_STAT_ETH_INBOUND, cur_count[SAPP_STAT_ETH_INBOUND] - history_count[SAPP_STAT_ETH_INBOUND]);
		sapp_fs3_metric_incrby(1, SAPP_STAT_ETH_INBOUND, 8 * (cur_length[SAPP_STAT_ETH_INBOUND] - history_length[SAPP_STAT_ETH_INBOUND])); /* to bps, bit per second */

		sapp_fs3_metric_incrby(0, SAPP_STAT_ETH_OUTBOUND, cur_count[SAPP_STAT_ETH_OUTBOUND] - history_count[SAPP_STAT_ETH_OUTBOUND]);
		sapp_fs3_metric_incrby(1, SAPP_STAT_ETH_OUTBOUND, 8 * (cur_length[SAPP_STAT_ETH_OUTBOUND] - history_length[SAPP_STAT_ETH_OUTBOUND])); /* to bps, bit per second */
	}
	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_IPV4,cur_count[SAPP_STAT_RCV_IPV4]-history_count[SAPP_STAT_RCV_IPV4]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_IPV4, 8 *( cur_length[SAPP_STAT_RCV_IPV4]-history_length[SAPP_STAT_RCV_IPV4])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_IPV6,cur_count[SAPP_STAT_RCV_IPV6]-history_count[SAPP_STAT_RCV_IPV6]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_IPV6, 8 *( cur_length[SAPP_STAT_RCV_IPV6]-history_length[SAPP_STAT_RCV_IPV6])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_TCP,cur_count[SAPP_STAT_RCV_TCP]-history_count[SAPP_STAT_RCV_TCP]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_TCP, 8 *( cur_length[SAPP_STAT_RCV_TCP]-history_length[SAPP_STAT_RCV_TCP])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_DUP_TCP,cur_count[SAPP_STAT_RCV_DUP_TCP]-history_count[SAPP_STAT_RCV_DUP_TCP]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_DUP_TCP, 8 *( cur_length[SAPP_STAT_RCV_DUP_TCP]-history_length[SAPP_STAT_RCV_DUP_TCP])); /* to bps, bit per second */
	sapp_fs3_metric_incrby(0, SAPP_STAT_DUP_IDENTIFY_ERR,cur_count[SAPP_STAT_DUP_IDENTIFY_ERR]-history_count[SAPP_STAT_DUP_IDENTIFY_ERR]);

	sapp_fs3_metric_incrby(1, SAPP_STAT_TCP_LOST_PKT, 8 *( cur_length[SAPP_STAT_TCP_LOST_PKT]-history_length[SAPP_STAT_TCP_LOST_PKT])); /* to bps, bit per second */
	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_LOST_PKT_STREAM_NUM,cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]-history_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]);

	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_CLOSE_BY_TIMEOUT,cur_count[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT]-history_count[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_CLOSE_BY_KICKOUT,cur_count[SAPP_STAT_TCP_CLOSE_BY_KICKOUT]-history_count[SAPP_STAT_TCP_CLOSE_BY_KICKOUT]);

	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_UDP,cur_count[SAPP_STAT_RCV_UDP]-history_count[SAPP_STAT_RCV_UDP]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_UDP, 8 *( cur_length[SAPP_STAT_RCV_UDP]-history_length[SAPP_STAT_RCV_UDP])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_RCV_DUP_UDP,cur_count[SAPP_STAT_RCV_DUP_UDP]-history_count[SAPP_STAT_RCV_DUP_UDP]);
	sapp_fs3_metric_incrby(1, SAPP_STAT_RCV_DUP_UDP, 8 *( cur_length[SAPP_STAT_RCV_DUP_UDP]-history_length[SAPP_STAT_RCV_DUP_UDP])); /* to bps, bit per second */

	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_CLOSE_BY_TIMEOUT,cur_count[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT]-history_count[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_CLOSE_BY_KICKOUT,cur_count[SAPP_STAT_UDP_CLOSE_BY_KICKOUT]-history_count[SAPP_STAT_UDP_CLOSE_BY_KICKOUT]);

	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_STREAM_NEW,cur_count[SAPP_STAT_TCP_STREAM_NEW]-history_count[SAPP_STAT_TCP_STREAM_NEW]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_STREAM_DEL,cur_count[SAPP_STAT_TCP_STREAM_DEL]-history_count[SAPP_STAT_TCP_STREAM_DEL]);
	sapp_fs3_metric_set(0, SAPP_STAT_TCP_STREAM_DATA,cur_count[SAPP_STAT_TCP_STREAM_DATA]);

	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_STREAM_NEW,cur_count[SAPP_STAT_UDP_STREAM_NEW]-history_count[SAPP_STAT_UDP_STREAM_NEW]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_STREAM_DEL,cur_count[SAPP_STAT_UDP_STREAM_DEL]-history_count[SAPP_STAT_UDP_STREAM_DEL]);
	sapp_fs3_metric_set(0, SAPP_STAT_UDP_STREAM_MORE,cur_count[SAPP_STAT_UDP_STREAM_MORE]);

	sapp_fs3_metric_set(0, SAPP_STAT_TCP_STREAM_DOUBLE,cur_count[SAPP_STAT_TCP_STREAM_DOUBLE]);
	sapp_fs3_metric_set(0, SAPP_STAT_TCP_STREAM_C2S,cur_count[SAPP_STAT_TCP_STREAM_C2S]);
	sapp_fs3_metric_set(0, SAPP_STAT_TCP_STREAM_S2C,cur_count[SAPP_STAT_TCP_STREAM_S2C]);

	sapp_fs3_metric_set(0, SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE,cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE]);
	sapp_fs3_metric_set(0, SAPP_STAT_TCP_STREAM_TOTAL_C2S,cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S]);
	sapp_fs3_metric_set(0, SAPP_STAT_TCP_STREAM_TOTAL_S2C,cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C]);

	sapp_fs3_metric_set(0, SAPP_STAT_UDP_STREAM_DOUBLE,cur_count[SAPP_STAT_UDP_STREAM_DOUBLE]);
	sapp_fs3_metric_set(0, SAPP_STAT_UDP_STREAM_C2S,cur_count[SAPP_STAT_UDP_STREAM_C2S]);
	sapp_fs3_metric_set(0, SAPP_STAT_UDP_STREAM_S2C,cur_count[SAPP_STAT_UDP_STREAM_S2C]);

	sapp_fs3_metric_set(0, SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE,cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE]);
	sapp_fs3_metric_set(0, SAPP_STAT_UDP_STREAM_TOTAL_C2S,cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S]);
	sapp_fs3_metric_set(0, SAPP_STAT_UDP_STREAM_TOTAL_S2C,cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C]);

	sapp_fs3_metric_incrby(0, SAPP_STAT_SND_TCP_RST,cur_count[SAPP_STAT_SND_TCP_RST]-history_count[SAPP_STAT_SND_TCP_RST]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_SND_TCP_SYNACK,cur_count[SAPP_STAT_SND_TCP_SYNACK]-history_count[SAPP_STAT_SND_TCP_SYNACK]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_SND_UDP,cur_count[SAPP_STAT_SND_UDP]-history_count[SAPP_STAT_SND_UDP]);

	sapp_fs3_metric_set(0, SAPP_STAT_GLOBAL_BYPASS,packet_io_under_ddos_global_status());

	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_BYPASS_STREAM,cur_count[SAPP_STAT_TCP_BYPASS_STREAM]-history_count[SAPP_STAT_TCP_BYPASS_STREAM]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_BYPASS_PKTS,cur_count[SAPP_STAT_TCP_BYPASS_PKTS]-history_count[SAPP_STAT_TCP_BYPASS_PKTS]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_BYPASS_BYTES,cur_count[SAPP_STAT_TCP_BYPASS_BYTES]-history_count[SAPP_STAT_TCP_BYPASS_BYTES]);
	
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_BYPASS_STREAM,cur_count[SAPP_STAT_UDP_BYPASS_STREAM]-history_count[SAPP_STAT_UDP_BYPASS_STREAM]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_BYPASS_PKTS,cur_count[SAPP_STAT_UDP_BYPASS_PKTS]-history_count[SAPP_STAT_UDP_BYPASS_PKTS]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_BYPASS_BYTES,cur_count[SAPP_STAT_UDP_BYPASS_BYTES]-history_count[SAPP_STAT_UDP_BYPASS_BYTES]);
	
	//sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_OFFLOAD_STREAM,cur_count[SAPP_STAT_TCP_OFFLOAD_STREAM]-history_count[SAPP_STAT_TCP_OFFLOAD_STREAM]);
	//sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_OFFLOAD_PKTS,cur_count[SAPP_STAT_TCP_OFFLOAD_PKTS]-history_count[SAPP_STAT_TCP_OFFLOAD_PKTS]);
	//sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_OFFLOAD_BYTES,cur_count[SAPP_STAT_TCP_OFFLOAD_BYTES]-history_count[SAPP_STAT_TCP_OFFLOAD_BYTES]);
	
	//sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_OFFLOAD_STREAM,cur_count[SAPP_STAT_UDP_OFFLOAD_STREAM]-history_count[SAPP_STAT_UDP_OFFLOAD_STREAM]);
	//sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_OFFLOAD_PKTS,cur_count[SAPP_STAT_UDP_OFFLOAD_PKTS]-history_count[SAPP_STAT_UDP_OFFLOAD_PKTS]);
	//sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_OFFLOAD_BYTES,cur_count[SAPP_STAT_UDP_OFFLOAD_BYTES]-history_count[SAPP_STAT_UDP_OFFLOAD_BYTES]);


	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_DUP_KICK_STREAM,cur_count[SAPP_STAT_UDP_DUP_KICK_STREAM]-history_count[SAPP_STAT_UDP_DUP_KICK_STREAM]);
	

	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_OPENING_OVERSPEED,cur_count[SAPP_STAT_TCP_OPENING_OVERSPEED]-history_count[SAPP_STAT_TCP_OPENING_OVERSPEED]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_OPENING_OVERSPEED,cur_count[SAPP_STAT_UDP_OPENING_OVERSPEED]-history_count[SAPP_STAT_UDP_OPENING_OVERSPEED]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_TIMEOUTS_OVERSPEED,cur_count[SAPP_STAT_TCP_TIMEOUTS_OVERSPEED]-history_count[SAPP_STAT_TCP_TIMEOUTS_OVERSPEED]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_TIMEOUTS_OVERSPEED,cur_count[SAPP_STAT_UDP_TIMEOUTS_OVERSPEED]-history_count[SAPP_STAT_UDP_TIMEOUTS_OVERSPEED]);

	sapp_fs3_metric_incrby(0, SAPP_STAT_TCP_TRY_TIMEOUTS,cur_count[SAPP_STAT_TCP_TRY_TIMEOUTS]-history_count[SAPP_STAT_TCP_TRY_TIMEOUTS]);
	sapp_fs3_metric_incrby(0, SAPP_STAT_UDP_TRY_TIMEOUTS,cur_count[SAPP_STAT_UDP_TRY_TIMEOUTS]-history_count[SAPP_STAT_UDP_TRY_TIMEOUTS]);

	const sapp_dup_pkt_t *dup_cfg = &sapp_global_val->config.packet_io.dup_pkt_para;
	if (dup_cfg->kickout_udp_stream_enabled 
	  || dup_cfg->dup_pkt_distinguish_ipv4_tcp 
	  || dup_cfg->dup_pkt_distinguish_ipv4_udp 
	  || dup_cfg->dup_pkt_distinguish_all_inject)
	{
		sapp_fs3_metric_set(0, SAPP_STAT_BM_HASH_NUM, cur_count[SAPP_STAT_BM_HASH_NUM]);
		sapp_fs3_metric_incrby(0, SAPP_STAT_BM_EXPAND_NUM, cur_count[SAPP_STAT_BM_EXPAND_NUM]-history_count[SAPP_STAT_BM_EXPAND_NUM]);
		sapp_fs3_metric_incrby(0, SAPP_STAT_BM_SLICE_NUM_NEW, cur_count[SAPP_STAT_BM_SLICE_NUM_NEW]-history_count[SAPP_STAT_BM_SLICE_NUM_NEW]);
		sapp_fs3_metric_incrby(0, SAPP_STAT_BM_SLICE_NUM_FREE, cur_count[SAPP_STAT_BM_SLICE_NUM_FREE]-history_count[SAPP_STAT_BM_SLICE_NUM_FREE]);
		sapp_fs3_metric_set(0, SAPP_STAT_BM_CUR_SLICE_NUM, cur_count[SAPP_STAT_BM_CUR_SLICE_NUM]);
		sapp_fs3_metric_set(0, SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE, cur_count[SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE]);
		sapp_fs3_metric_set(0, SAPP_STAT_DABM_RESIZE_MAX_RATIO, cur_count[SAPP_STAT_DABM_RESIZE_MAX_RATIO]);
	}

	return;
}


static void packet_io_update_metrics_fs4(void)
{
	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_UNKNOWN,cur_count[SAPP_STAT_RCV_UNKNOWN]-history_count[SAPP_STAT_RCV_UNKNOWN]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_UNKNOWN, 8 *( cur_length[SAPP_STAT_RCV_UNKNOWN]-history_length[SAPP_STAT_RCV_UNKNOWN])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_LINE,cur_count[SAPP_STAT_RCV_LINE]-history_count[SAPP_STAT_RCV_LINE]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_LINE, 8 *( cur_length[SAPP_STAT_RCV_LINE]-history_length[SAPP_STAT_RCV_LINE])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_SND_ERROR,cur_count[SAPP_STAT_SND_ERROR]-history_count[SAPP_STAT_SND_ERROR]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_SND_ERROR, 8 *( cur_length[SAPP_STAT_SND_ERROR]-history_length[SAPP_STAT_SND_ERROR])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_ETHERNET,cur_count[SAPP_STAT_RCV_ETHERNET]-history_count[SAPP_STAT_RCV_ETHERNET]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_ETHERNET, 8 *( cur_length[SAPP_STAT_RCV_ETHERNET]-history_length[SAPP_STAT_RCV_ETHERNET])); /* to bps, bit per second */

	if((DEPLOYMENT_MODE_INLINE == sapp_global_val->config.packet_io.deployment_mode_bin)
	 || (DEPLOYMENT_MODE_TRANSPARENT == sapp_global_val->config.packet_io.deployment_mode_bin)){
		sapp_fs4_metric_incrby(0, SAPP_STAT_ETH_INBOUND, cur_count[SAPP_STAT_ETH_INBOUND] - history_count[SAPP_STAT_ETH_INBOUND]);
		sapp_fs4_metric_incrby(1, SAPP_STAT_ETH_INBOUND, 8 * (cur_length[SAPP_STAT_ETH_INBOUND] - history_length[SAPP_STAT_ETH_INBOUND])); /* to bps, bit per second */

		sapp_fs4_metric_incrby(0, SAPP_STAT_ETH_OUTBOUND, cur_count[SAPP_STAT_ETH_OUTBOUND] - history_count[SAPP_STAT_ETH_OUTBOUND]);
		sapp_fs4_metric_incrby(1, SAPP_STAT_ETH_OUTBOUND, 8 * (cur_length[SAPP_STAT_ETH_OUTBOUND] - history_length[SAPP_STAT_ETH_OUTBOUND])); /* to bps, bit per second */
	}
	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_IPV4,cur_count[SAPP_STAT_RCV_IPV4]-history_count[SAPP_STAT_RCV_IPV4]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_IPV4, 8 *( cur_length[SAPP_STAT_RCV_IPV4]-history_length[SAPP_STAT_RCV_IPV4])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_IPV6,cur_count[SAPP_STAT_RCV_IPV6]-history_count[SAPP_STAT_RCV_IPV6]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_IPV6, 8 *( cur_length[SAPP_STAT_RCV_IPV6]-history_length[SAPP_STAT_RCV_IPV6])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_TCP,cur_count[SAPP_STAT_RCV_TCP]-history_count[SAPP_STAT_RCV_TCP]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_TCP, 8 *( cur_length[SAPP_STAT_RCV_TCP]-history_length[SAPP_STAT_RCV_TCP])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_DUP_TCP,cur_count[SAPP_STAT_RCV_DUP_TCP]-history_count[SAPP_STAT_RCV_DUP_TCP]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_DUP_TCP, 8 *( cur_length[SAPP_STAT_RCV_DUP_TCP]-history_length[SAPP_STAT_RCV_DUP_TCP])); /* to bps, bit per second */
	sapp_fs4_metric_incrby(0, SAPP_STAT_DUP_IDENTIFY_ERR,cur_count[SAPP_STAT_DUP_IDENTIFY_ERR]-history_count[SAPP_STAT_DUP_IDENTIFY_ERR]);

	sapp_fs4_metric_incrby(1, SAPP_STAT_TCP_LOST_PKT, 8 *( cur_length[SAPP_STAT_TCP_LOST_PKT]-history_length[SAPP_STAT_TCP_LOST_PKT])); /* to bps, bit per second */
	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_LOST_PKT_STREAM_NUM,cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]-history_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]);

	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_CLOSE_BY_TIMEOUT,cur_count[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT]-history_count[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_CLOSE_BY_KICKOUT,cur_count[SAPP_STAT_TCP_CLOSE_BY_KICKOUT]-history_count[SAPP_STAT_TCP_CLOSE_BY_KICKOUT]);

	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_UDP,cur_count[SAPP_STAT_RCV_UDP]-history_count[SAPP_STAT_RCV_UDP]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_UDP, 8 *( cur_length[SAPP_STAT_RCV_UDP]-history_length[SAPP_STAT_RCV_UDP])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_RCV_DUP_UDP,cur_count[SAPP_STAT_RCV_DUP_UDP]-history_count[SAPP_STAT_RCV_DUP_UDP]);
	sapp_fs4_metric_incrby(1, SAPP_STAT_RCV_DUP_UDP, 8 *( cur_length[SAPP_STAT_RCV_DUP_UDP]-history_length[SAPP_STAT_RCV_DUP_UDP])); /* to bps, bit per second */

	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_CLOSE_BY_TIMEOUT,cur_count[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT]-history_count[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_CLOSE_BY_KICKOUT,cur_count[SAPP_STAT_UDP_CLOSE_BY_KICKOUT]-history_count[SAPP_STAT_UDP_CLOSE_BY_KICKOUT]);

	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_STREAM_NEW,cur_count[SAPP_STAT_TCP_STREAM_NEW]-history_count[SAPP_STAT_TCP_STREAM_NEW]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_STREAM_DEL,cur_count[SAPP_STAT_TCP_STREAM_DEL]-history_count[SAPP_STAT_TCP_STREAM_DEL]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_STREAM_DATA,cur_count[SAPP_STAT_TCP_STREAM_DATA]);

	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_STREAM_NEW,cur_count[SAPP_STAT_UDP_STREAM_NEW]-history_count[SAPP_STAT_UDP_STREAM_NEW]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_STREAM_DEL,cur_count[SAPP_STAT_UDP_STREAM_DEL]-history_count[SAPP_STAT_UDP_STREAM_DEL]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_STREAM_MORE,cur_count[SAPP_STAT_UDP_STREAM_MORE]);

	sapp_fs4_metric_set(0, SAPP_STAT_TCP_STREAM_DOUBLE,cur_count[SAPP_STAT_TCP_STREAM_DOUBLE]);
	sapp_fs4_metric_set(0, SAPP_STAT_TCP_STREAM_C2S,cur_count[SAPP_STAT_TCP_STREAM_C2S]);
	sapp_fs4_metric_set(0, SAPP_STAT_TCP_STREAM_S2C,cur_count[SAPP_STAT_TCP_STREAM_S2C]);

	sapp_fs4_metric_set(0, SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE,cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE]);
	sapp_fs4_metric_set(0, SAPP_STAT_TCP_STREAM_TOTAL_C2S,cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S]);
	sapp_fs4_metric_set(0, SAPP_STAT_TCP_STREAM_TOTAL_S2C,cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C]);

	sapp_fs4_metric_set(0, SAPP_STAT_UDP_STREAM_DOUBLE,cur_count[SAPP_STAT_UDP_STREAM_DOUBLE]);
	sapp_fs4_metric_set(0, SAPP_STAT_UDP_STREAM_C2S,cur_count[SAPP_STAT_UDP_STREAM_C2S]);
	sapp_fs4_metric_set(0, SAPP_STAT_UDP_STREAM_S2C,cur_count[SAPP_STAT_UDP_STREAM_S2C]);

	sapp_fs4_metric_set(0, SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE,cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE]);
	sapp_fs4_metric_set(0, SAPP_STAT_UDP_STREAM_TOTAL_C2S,cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S]);
	sapp_fs4_metric_set(0, SAPP_STAT_UDP_STREAM_TOTAL_S2C,cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C]);

	sapp_fs4_metric_incrby(0, SAPP_STAT_SND_TCP_RST,cur_count[SAPP_STAT_SND_TCP_RST]-history_count[SAPP_STAT_SND_TCP_RST]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_SND_TCP_SYNACK,cur_count[SAPP_STAT_SND_TCP_SYNACK]-history_count[SAPP_STAT_SND_TCP_SYNACK]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_SND_UDP,cur_count[SAPP_STAT_SND_UDP]-history_count[SAPP_STAT_SND_UDP]);

	sapp_fs4_metric_set(0, SAPP_STAT_GLOBAL_BYPASS,packet_io_under_ddos_global_status());

	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_BYPASS_STREAM,cur_count[SAPP_STAT_TCP_BYPASS_STREAM]-history_count[SAPP_STAT_TCP_BYPASS_STREAM]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_BYPASS_PKTS,cur_count[SAPP_STAT_TCP_BYPASS_PKTS]-history_count[SAPP_STAT_TCP_BYPASS_PKTS]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_BYPASS_BYTES,cur_count[SAPP_STAT_TCP_BYPASS_BYTES]-history_count[SAPP_STAT_TCP_BYPASS_BYTES]);
	
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_BYPASS_STREAM,cur_count[SAPP_STAT_UDP_BYPASS_STREAM]-history_count[SAPP_STAT_UDP_BYPASS_STREAM]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_BYPASS_PKTS,cur_count[SAPP_STAT_UDP_BYPASS_PKTS]-history_count[SAPP_STAT_UDP_BYPASS_PKTS]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_BYPASS_BYTES,cur_count[SAPP_STAT_UDP_BYPASS_BYTES]-history_count[SAPP_STAT_UDP_BYPASS_BYTES]);
	
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_DUP_KICK_STREAM,cur_count[SAPP_STAT_UDP_DUP_KICK_STREAM]-history_count[SAPP_STAT_UDP_DUP_KICK_STREAM]);
	

	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_OPENING_OVERSPEED,cur_count[SAPP_STAT_TCP_OPENING_OVERSPEED]-history_count[SAPP_STAT_TCP_OPENING_OVERSPEED]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_OPENING_OVERSPEED,cur_count[SAPP_STAT_UDP_OPENING_OVERSPEED]-history_count[SAPP_STAT_UDP_OPENING_OVERSPEED]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_TIMEOUTS_OVERSPEED,cur_count[SAPP_STAT_TCP_TIMEOUTS_OVERSPEED]-history_count[SAPP_STAT_TCP_TIMEOUTS_OVERSPEED]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_TIMEOUTS_OVERSPEED,cur_count[SAPP_STAT_UDP_TIMEOUTS_OVERSPEED]-history_count[SAPP_STAT_UDP_TIMEOUTS_OVERSPEED]);

	sapp_fs4_metric_incrby(0, SAPP_STAT_TCP_TRY_TIMEOUTS,cur_count[SAPP_STAT_TCP_TRY_TIMEOUTS]-history_count[SAPP_STAT_TCP_TRY_TIMEOUTS]);
	sapp_fs4_metric_incrby(0, SAPP_STAT_UDP_TRY_TIMEOUTS,cur_count[SAPP_STAT_UDP_TRY_TIMEOUTS]-history_count[SAPP_STAT_UDP_TRY_TIMEOUTS]);

	const sapp_dup_pkt_t *dup_cfg = &sapp_global_val->config.packet_io.dup_pkt_para;
	if (dup_cfg->kickout_udp_stream_enabled 
	  || dup_cfg->dup_pkt_distinguish_ipv4_tcp 
	  || dup_cfg->dup_pkt_distinguish_ipv4_udp 
	  || dup_cfg->dup_pkt_distinguish_all_inject)
	{
		sapp_fs4_metric_set(0, SAPP_STAT_BM_HASH_NUM, cur_count[SAPP_STAT_BM_HASH_NUM]);
		sapp_fs4_metric_incrby(0, SAPP_STAT_BM_EXPAND_NUM, cur_count[SAPP_STAT_BM_EXPAND_NUM]-history_count[SAPP_STAT_BM_EXPAND_NUM]);
		sapp_fs4_metric_incrby(0, SAPP_STAT_BM_SLICE_NUM_NEW, cur_count[SAPP_STAT_BM_SLICE_NUM_NEW]-history_count[SAPP_STAT_BM_SLICE_NUM_NEW]);
		sapp_fs4_metric_incrby(0, SAPP_STAT_BM_SLICE_NUM_FREE, cur_count[SAPP_STAT_BM_SLICE_NUM_FREE]-history_count[SAPP_STAT_BM_SLICE_NUM_FREE]);
		sapp_fs4_metric_set(0, SAPP_STAT_BM_CUR_SLICE_NUM, cur_count[SAPP_STAT_BM_CUR_SLICE_NUM]);
		sapp_fs4_metric_set(0, SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE, cur_count[SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE]);
		sapp_fs4_metric_set(0, SAPP_STAT_DABM_RESIZE_MAX_RATIO, cur_count[SAPP_STAT_DABM_RESIZE_MAX_RATIO]);
	}

	return;
}

static void packet_io_update_metrics(void)
{
	if (1 == sapp_global_val->config.profiling.fs2.enabled )
	{
		packet_io_update_metrics_fs2();
	}
	if (1 == sapp_global_val->config.profiling.fs3.enabled )
	{
		packet_io_update_metrics_fs3();
	}
	if (1 == sapp_global_val->config.profiling.fs4.enabled )
	{
		packet_io_update_metrics_fs4();
	}	
	return;
}

static void sysinfo_output_per_layer_stat(FILE *fp)
{
	int i, j, k, layer_num;
	int layer_type;
	sapp_gval_mthread_t **mstat = sapp_global_val->mthread_volatile;
	unsigned long long stat_sum;
	unsigned long long sum_count_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX] = {{0}};
	unsigned long long sum_length_per_layer[__ADDR_TYPE_MAX][SAPP_SUPPORT_LAYER_NUM_MAX] = {{0}};
	char layer_length_human_str[SAPP_SUPPORT_LAYER_NUM_MAX][STATS_STR_LEN];

	for(i=0;i<g_packet_io_thread_num;i++){
		for(j = 0; j < __ADDR_TYPE_MAX; j++){
			for(k = 0; k < SAPP_SUPPORT_LAYER_NUM_MAX; k++){
				sum_count_per_layer[j][k] +=  mstat[i]->sys_stat.count_per_layer[j][k];
				sum_length_per_layer[j][k] +=  mstat[i]->sys_stat.length_per_layer[j][k];
			}
		}
	}

	fprintf(fp,"******************************************************************************************************************\n");
	fprintf(fp,"************* protocol count statistics matrix (number) *************\n");
	fprintf(fp,"%-10s %12s %12s %12s %12s %12s %12s %12s %12s\n","PROTO", "Layer0", "Layer1","Layer2", "Layer3","Layer4","Layer5","Layer6","Layer7");
	

	for(layer_type = 1; layer_type < (int)__ADDR_TYPE_MAX; layer_type++){
		stat_sum = 0;
		for(layer_num = 0; layer_num < SAPP_SUPPORT_LAYER_NUM_MAX; layer_num++){
			stat_sum += sum_count_per_layer[layer_type][layer_num];
		}
		if(0 == stat_sum){
			continue; /* ����ȫ��0�Ĳ�Ͳ���ʾ�� */
		}
			
		fprintf(fp,"%-10s %12llu %12llu %12llu %12llu %12llu %12llu %12llu %12llu\n",  addr_type_abbreviation_ntop((enum addr_type_t)layer_type), 
				sum_count_per_layer[layer_type][0], sum_count_per_layer[layer_type][1], sum_count_per_layer[layer_type][2], sum_count_per_layer[layer_type][3],
				sum_count_per_layer[layer_type][4], sum_count_per_layer[layer_type][5], sum_count_per_layer[layer_type][6], sum_count_per_layer[layer_type][7]);		
	}

	fprintf(fp,"\n*********** protocol length statistics matrix (bytes) *************\n");
	fprintf(fp,"%-10s %12s %12s %12s %12s %12s %12s %12s %12s\n","PROTO", "Layer0", "Layer1","Layer2", "Layer3","Layer4","Layer5","Layer6","Layer7");
	for(layer_type = 1; layer_type < (int)__ADDR_TYPE_MAX; layer_type++){
		stat_sum = 0;
		for(layer_num = 0; layer_num < SAPP_SUPPORT_LAYER_NUM_MAX; layer_num++){
			stat_sum += sum_length_per_layer[layer_type][layer_num];
			byte_convert_human(sum_length_per_layer[layer_type][layer_num], 1, 1, layer_length_human_str[layer_num]); /* �ܼ��ֽ���, �˴���������������, ���ܳ���8 */
		}
		if(0 == stat_sum){
			continue; /* ����ȫ��0�Ĳ�Ͳ���ʾ�� */
		}
			
		fprintf(fp,"%-10s %12s %12s %12s %12s %12s %12s %12s %12s\n",  addr_type_abbreviation_ntop((enum addr_type_t)layer_type),
				layer_length_human_str[0], layer_length_human_str[1], layer_length_human_str[2], layer_length_human_str[3],
				layer_length_human_str[4], layer_length_human_str[5], layer_length_human_str[6], layer_length_human_str[7]);		
	}		

	fprintf(fp,"******************************************************************************************************************\n\n");

	return;
}

static void sysinfo_find_the_maximum_value(sapp_sys_stat_type_t stype)
{
	sapp_gval_mthread_t **mstat = sapp_global_val->mthread_volatile;
	unsigned long long max_val = 0;
	for (int i = 0; i < g_packet_io_thread_num; i++){
		if (max_val < mstat[i]->sys_stat.count[stype]){
			max_val = mstat[i]->sys_stat.count[stype];
		}
	}
	cur_count[stype] = max_val;
}

void sysinfo_output(void)
{
	int i, j;
	FILE* fp;
	//unsigned long long cur_count[COUNTER_NUM] = {0};
	char time_string[32];

	static sapp_gval_mthread_sys_stat_t history_threads_stat[SAPP_MAX_THREADS];
	unsigned long long cur_project_in_use_array[PROJECT_REQ_MAX_PLUG_NUM] = {}, cur_bridge_in_use_array[STREAM_BRIDGE_MAX_NUM] = {};
	
	char s1[STATS_STR_LEN], s2[STATS_STR_LEN];
	sapp_gval_mthread_t **mstat = sapp_global_val->mthread_volatile;

	if(0 == update_packet_io_status_sw){
		return;
	}

	MESA_mkdir_p(sapp_global_val->config.cfg_file_path.cfg_files_root_dir, 0755);
	
	fp = fopen(ABBR_SYSINFO_LOG_DATA_FILE,"w+");
	if(fp == NULL)
	{
		printf("\033[1;31;40mopen %s error, %s\033[0m\n", ABBR_SYSINFO_LOG_DATA_FILE, strerror(errno));
		return;
	}

	memset(cur_count, 0, sizeof(cur_count));
	memset(cur_length, 0, sizeof(cur_length));

	timet_to_str(ABBR_CURRENT_TIME, time_string, sizeof(time_string));

	for(i=0;i<g_packet_io_thread_num;i++){
		for(j = 0; j < SAPP_STAT_NUM_MAX; j++){
			cur_count[j] +=  mstat[i]->sys_stat.count[j];
			cur_length[j] +=  mstat[i]->sys_stat.length[j];		
		}
	}

	sysinfo_find_the_maximum_value(SAPP_STAT_BM_HASH_NUM);
	sysinfo_find_the_maximum_value(SAPP_STAT_BM_CUR_SLICE_NUM);
	sysinfo_find_the_maximum_value(SAPP_STAT_APBM_EXPAND_MAX_MULTIPLE);
	sysinfo_find_the_maximum_value(SAPP_STAT_DABM_RESIZE_MAX_RATIO);

	for(i=0;i<g_packet_io_thread_num;i++){
		for(j = 0; j < PROJECT_REQ_MAX_PLUG_NUM; j++){
			cur_project_in_use_array[j] += mstat[i]->sys_stat.count_project_in_use[j];
		}
	}

	for(i=0;i<g_packet_io_thread_num;i++){
		for(j = 0; j < STREAM_BRIDGE_MAX_NUM; j++){
			cur_bridge_in_use_array[j] += mstat[i]->sys_stat.count_bridge_in_use[j];
		}
	}	

	fprintf(fp,"\n*********************** %s *********************\n", time_string);
	fprintf(fp,"*********************** \033[41m%s\033[0m *************************\n", "sysinfo exactly");

	fprintf(fp,"\n|------------------------------------------------ TCP statistics detail ----------------------------------------------|\n");
	fprintf(fp,"%3s %6s %3s %-27s %-19s %-27s %-27s\n", "", "", "","|-----------Current---------|", "|------Realtime-----|",
			"|--------From-of-startup---------|", "|----Special----|");
	fprintf(fp,"%3s %6s %3s %8s %9s %10s %10s %10s %10s %9s %13s %17s\n", "seq", "tid", "PSR", "link-syn", "link-data", "link-nouse",
			"link-new/s", "link-del/s", "stream-num", "reset-num", "hash-list-max", "special-timeout");
	for(i = 0; i < g_packet_io_thread_num; i++){	
		fprintf(fp, "%3d %6ld %3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13llu %13d\n",
				i, 
				(long)sapp_global_val->individual_fixed.thread_tid[i],
				sapp_global_val->individual_fixed.cpu_bind_core_id_per_thread[i],
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_SYN], 
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DATA],
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NOUSE], 
				(mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NEW]-history_threads_stat[i].count[SAPP_STAT_TCP_STREAM_NEW]), 
				(mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DEL]-history_threads_stat[i].count[SAPP_STAT_TCP_STREAM_DEL]),
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_NEW],
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_STREAM_DEL],
				mstat[i]->sys_stat.count[SAPP_STAT_TCP_HASH_LIST_MAX],
				sapp_global_mthread[i].tcp_stream_special_timeout_num);
	}

	fprintf(fp,"\n|----------------------------------------- UDP statistics detail ---------------------------------------|\n");
	fprintf(fp,"%3s%6s %3s %-27s %-19s %-27s %-27s\n", "", "", "", "|-----------Current---------|", "|------Realtime-----|",
		"|--------From-of-startup---------|", "|----Special----|");
	fprintf(fp,"%3s %6s %3s %8s %9s %10s %10s %10s %10s %9s %13s %17s\n", "seq", "tid", "PSR", "link-one", "link-two", "link-more", "link-new/s",
			"link-del/s", "stream-num", "reset-num", "hash-list-max",  "special-timeout");
	for(i = 0; i < g_packet_io_thread_num; i++){	
		fprintf(fp, "%3d %6ld %3d %8llu %9llu %10llu %10llu %10llu %10llu %9llu %13llu %13d\n",
				i, 
				(long)sapp_global_val->individual_fixed.thread_tid[i],
				sapp_global_val->individual_fixed.cpu_bind_core_id_per_thread[i],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_ONE], 
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_TWO],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_MORE], 
				(mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_NEW]-history_threads_stat[i].count[SAPP_STAT_UDP_STREAM_NEW]), 
				(mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_DEL]-history_threads_stat[i].count[SAPP_STAT_UDP_STREAM_DEL]),
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_NEW],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_STREAM_DEL],
				mstat[i]->sys_stat.count[SAPP_STAT_UDP_HASH_LIST_MAX],
				sapp_global_mthread[i].udp_stream_special_timeout_num);
	}

	sysinfo_output_per_layer_stat(fp);
	
	fprintf(fp,"*****************************************************************\n\n");
	fprintf(fp,"################# \033[41m%s\033[0m --- is same as above! #########\n", "sysinfo humanly");
	fprintf(fp,"%-12s %12s %12s %12s %12s\n", "Layer", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "Polling_work", (unsigned long long)0,(unsigned long long)0,(cur_count[SAPP_POLLING_WORK]-history_count[SAPP_POLLING_WORK]),(unsigned long long)0);
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu\n", "Polling_idle", (unsigned long long)0,(unsigned long long)0,(cur_count[SAPP_POLLING_IDLE]-history_count[SAPP_POLLING_IDLE]),(unsigned long long)0);
	
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","Line",cur_count[SAPP_STAT_RCV_LINE],byte_convert_human(cur_length[SAPP_STAT_RCV_LINE],1 ,1,s1),(cur_count[SAPP_STAT_RCV_LINE]-history_count[SAPP_STAT_RCV_LINE]),byte_convert_human((cur_length[SAPP_STAT_RCV_LINE]-history_length[SAPP_STAT_RCV_LINE]),1,8,s2));	
	
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","Raw",cur_count[SAPP_STAT_RCV_RAW],byte_convert_human(cur_length[SAPP_STAT_RCV_RAW],1 ,1,s1),(cur_count[SAPP_STAT_RCV_RAW]-history_count[SAPP_STAT_RCV_RAW]),byte_convert_human((cur_length[SAPP_STAT_RCV_RAW]-history_length[SAPP_STAT_RCV_RAW]),1,8,s2));	
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","Ethernet",cur_count[SAPP_STAT_RCV_ETHERNET],byte_convert_human(cur_length[SAPP_STAT_RCV_ETHERNET],1 ,1,s1),(cur_count[SAPP_STAT_RCV_ETHERNET]-history_count[SAPP_STAT_RCV_ETHERNET]),byte_convert_human((cur_length[SAPP_STAT_RCV_ETHERNET]-history_length[SAPP_STAT_RCV_ETHERNET]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","IPv4",cur_count[SAPP_STAT_RCV_IPV4],byte_convert_human(cur_length[SAPP_STAT_RCV_IPV4],1 ,1,s1),(cur_count[SAPP_STAT_RCV_IPV4]-history_count[SAPP_STAT_RCV_IPV4]),byte_convert_human((cur_length[SAPP_STAT_RCV_IPV4]-history_length[SAPP_STAT_RCV_IPV4]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","IPv6",cur_count[SAPP_STAT_RCV_IPV6],byte_convert_human(cur_length[SAPP_STAT_RCV_IPV6],1,1,s1),(cur_count[SAPP_STAT_RCV_IPV6]-history_count[SAPP_STAT_RCV_IPV6]),byte_convert_human((cur_length[SAPP_STAT_RCV_IPV6]-history_length[SAPP_STAT_RCV_IPV6]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","TCP",cur_count[SAPP_STAT_RCV_TCP],byte_convert_human(cur_length[SAPP_STAT_RCV_TCP],1,1,s1),(cur_count[SAPP_STAT_RCV_TCP]-history_count[SAPP_STAT_RCV_TCP]),byte_convert_human((cur_length[SAPP_STAT_RCV_TCP]-history_length[SAPP_STAT_RCV_TCP]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","UDP",cur_count[SAPP_STAT_RCV_UDP],byte_convert_human(cur_length[SAPP_STAT_RCV_UDP],1,1,s1),(cur_count[SAPP_STAT_RCV_UDP]-history_count[SAPP_STAT_RCV_UDP]),byte_convert_human((cur_length[SAPP_STAT_RCV_UDP]-history_length[SAPP_STAT_RCV_UDP]),1,8,s2));	
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","Unknown",cur_count[SAPP_STAT_RCV_UNKNOWN],byte_convert_human(cur_length[SAPP_STAT_RCV_UNKNOWN],1,1,s1),(cur_count[SAPP_STAT_RCV_UNKNOWN]-history_count[SAPP_STAT_RCV_UNKNOWN]),byte_convert_human((cur_length[SAPP_STAT_RCV_UNKNOWN]-history_length[SAPP_STAT_RCV_UNKNOWN]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n","Sapp_Drop",
				cur_count[SAPP_STAT_DROP_ETHERNET]+cur_count[SAPP_STAT_DROP_IPV4]+cur_count[SAPP_STAT_DROP_IPV6],
				byte_convert_human(cur_length[SAPP_STAT_DROP_ETHERNET]+cur_length[SAPP_STAT_DROP_IPV4]+cur_length[SAPP_STAT_DROP_IPV6],1,1,s1),
				(cur_count[SAPP_STAT_DROP_ETHERNET]+cur_count[SAPP_STAT_DROP_IPV4]+cur_count[SAPP_STAT_DROP_IPV6]-history_count[SAPP_STAT_DROP_ETHERNET]-history_count[SAPP_STAT_DROP_IPV4]-history_count[SAPP_STAT_DROP_IPV6]),
				byte_convert_human((cur_count[SAPP_STAT_DROP_ETHERNET]+cur_count[SAPP_STAT_DROP_IPV4]+cur_count[SAPP_STAT_DROP_IPV6]-history_count[SAPP_STAT_DROP_ETHERNET]-history_count[SAPP_STAT_DROP_IPV4]-history_count[SAPP_STAT_DROP_IPV6]),1,8,s2));

	fprintf(fp,"#################################################################\n");
	fprintf(fp,"Network Link Quality:\n");	
	fprintf(fp,"%-12s %16s %16s %7s \n","LOST_STAT", "total", "lost", "percent");
	if((cur_length[SAPP_STAT_RCV_TCP] > 0) && (cur_length[SAPP_STAT_TCP_LOST_PKT] > 0)){
		fprintf(fp,"%-12s %16llu %16llu %2.3f%%\n", "bytes", cur_length[SAPP_STAT_RCV_TCP], cur_length[SAPP_STAT_TCP_LOST_PKT], 100.0 * (double)cur_length[SAPP_STAT_TCP_LOST_PKT]/(double)(cur_length[SAPP_STAT_RCV_TCP]+cur_length[SAPP_STAT_TCP_LOST_PKT]));
	}else{
		fprintf(fp,"%-12s %16llu %16llu %2.3f%%\n", "bytes", cur_length[SAPP_STAT_RCV_TCP], cur_length[SAPP_STAT_TCP_LOST_PKT], 0.0);
	}
	if((cur_count[SAPP_STAT_TCP_STREAM_NEW] > 0) && (cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM] > 0)){
		fprintf(fp,"%-12s %16llu %16llu %2.3f%%\n", "stream", cur_count[SAPP_STAT_TCP_STREAM_NEW], cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM], 100.0*(double)cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM]/(double)(cur_count[SAPP_STAT_TCP_STREAM_NEW]));
	}else{
		fprintf(fp,"%-12s %16llu %16llu %2.3f%%\n", "stream", cur_count[SAPP_STAT_TCP_STREAM_NEW], cur_count[SAPP_STAT_TCP_LOST_PKT_STREAM_NUM], 0.0);
	}
	fprintf(fp,"-----------------------------------------------------------------\n");

	fprintf(fp,"Stream Close Cause Statistics:\n");	
	///fprintf(fp,"Note: If there are any TCP_ALL plugins, after receiving two-way fin or rst packets,\n      the TCP plugins will close immediately, but TCP_ALL plugins will wait until timeout or kicked out.\n\n");	
	fprintf(fp,"%-12s %12s %12s %12s %12s %12s %12s %12s\n", "STREAM_TYPE",  "TIMEOUT", "KICKOUT", "DUMPFILE", "BY_FIN", "BY_RST", "PORT_REUSE", "SHOULD_CLOSE");
	fprintf(fp,"%-12s %12llu %12llu %12llu %12llu %12llu %12llu %12llu\n", "TCP",  cur_count[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT], cur_count[SAPP_STAT_TCP_CLOSE_BY_KICKOUT], cur_count[SAPP_STAT_TCP_CLOSE_BY_DUMPFILE_END], cur_count[SAPP_STAT_TCP_CLOSE_BY_FIN], cur_count[SAPP_STAT_TCP_CLOSE_BY_RST], cur_count[SAPP_STAT_TCP_CLOSE_BY_REUSE], cur_count[SAPP_STAT_TCP_SHOULD_CLOSE_BUT_TCPALL]);
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s %12s %12s %12s\n", "UDP",  cur_count[SAPP_STAT_UDP_CLOSE_BY_TIMEOUT], cur_count[SAPP_STAT_UDP_CLOSE_BY_KICKOUT], cur_count[SAPP_STAT_UDP_CLOSE_BY_DUMPFILE_END], "N/A","N/A","N/A","N/A");
	
	fprintf(fp,"-----------------------------------------------------------------\n");
	fprintf(fp,"%-12s %12s %12s %12s %12s\n","STREAM_TYPE", "total_stream", "link_del/s", "total_pkts", "total_len");
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "TCP_DOU", cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE] - history_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_TCP_STREAM_TOTAL_DOUBLE_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "TCP_C2S", cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S] - history_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_TCP_STREAM_TOTAL_C2S_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "TCP_S2C", cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C] - history_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C],
			cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_TCP_STREAM_TOTAL_S2C_BYTES],1,1,s1));	

	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "UDP_DOU", cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE] - history_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_UDP_STREAM_TOTAL_DOUBLE_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "UDP_C2S", cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S] - history_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_UDP_STREAM_TOTAL_C2S_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "UDP_S2C", cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C] - history_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C],
			cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_UDP_STREAM_TOTAL_S2C_BYTES],1,1,s2));
			
	fprintf(fp,"----------------------------------------------------------------\n");		
	fprintf(fp, "The follow TCP statistics meet the conditions:(total pkt_num>=%d and byte>=%d)\n", 
				sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_pkt, 
				sapp_global_val->config.stream.tcp.meaningful_statistics_minimum_byte);
	fprintf(fp, "The follow UDP statistics meet the conditions:(total pkt_num>=%d and byte>=%d)\n", 
				sapp_global_val->config.stream.udp.meaningful_statistics_minimum_pkt, 
				sapp_global_val->config.stream.udp.meaningful_statistics_minimum_byte);				
	fprintf(fp,"%-12s %12s %12s %12s %12s\n","STREAM_TYPE", "total_stream", "link_del/s", "total_pkts", "total_len");
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "TCP_DOU", cur_count[SAPP_STAT_TCP_STREAM_DOUBLE],
			cur_count[SAPP_STAT_TCP_STREAM_DOUBLE] - history_count[SAPP_STAT_TCP_STREAM_DOUBLE],
			cur_count[SAPP_STAT_TCP_STREAM_DOUBLE_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_TCP_STREAM_DOUBLE_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "TCP_C2S", cur_count[SAPP_STAT_TCP_STREAM_C2S],
			cur_count[SAPP_STAT_TCP_STREAM_C2S] - history_count[SAPP_STAT_TCP_STREAM_C2S],
			cur_count[SAPP_STAT_TCP_STREAM_C2S_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_TCP_STREAM_C2S_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "TCP_S2C", cur_count[SAPP_STAT_TCP_STREAM_S2C],
			cur_count[SAPP_STAT_TCP_STREAM_S2C] - history_count[SAPP_STAT_TCP_STREAM_S2C],
			cur_count[SAPP_STAT_TCP_STREAM_S2C_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_TCP_STREAM_S2C_BYTES],1,1,s1));

	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "UDP_DOU", cur_count[SAPP_STAT_UDP_STREAM_DOUBLE],
			cur_count[SAPP_STAT_UDP_STREAM_DOUBLE] - history_count[SAPP_STAT_UDP_STREAM_DOUBLE],
			cur_count[SAPP_STAT_UDP_STREAM_DOUBLE_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_UDP_STREAM_DOUBLE_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "UDP_C2S", cur_count[SAPP_STAT_UDP_STREAM_C2S],
			cur_count[SAPP_STAT_UDP_STREAM_C2S] - history_count[SAPP_STAT_UDP_STREAM_C2S],
			cur_count[SAPP_STAT_UDP_STREAM_C2S_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_UDP_STREAM_C2S_BYTES],1,1,s1));
	fprintf(fp,"%-12s %12llu %12llu %12llu %12s\n", "UDP_S2C", cur_count[SAPP_STAT_UDP_STREAM_S2C],
			cur_count[SAPP_STAT_UDP_STREAM_S2C] - history_count[SAPP_STAT_UDP_STREAM_S2C],
			cur_count[SAPP_STAT_UDP_STREAM_S2C_PKTS],
			byte_convert_human(cur_count[SAPP_STAT_UDP_STREAM_S2C_BYTES],1,1,s1));

	fprintf(fp,"----------------------------------------------------------------\n");	
	unsigned long long total_project_num = 0;
	fprintf(fp,"%10s %13s %s\n", "Project_ID", "In_Use_Number", "Project_Name");
	for(i = 0; i < PROJECT_REQ_MAX_PLUG_NUM; i++){
		if(cur_project_in_use_array[i] > 0){
			fprintf(fp,"%10d %13llu %s\n", i, cur_project_in_use_array[i], project_find_name_by_id(i));
			total_project_num += cur_project_in_use_array[i];
		}
	}
	fprintf(fp,"%10s %13llu %s\n", "Total", total_project_num, "N/A");
	
	fprintf(fp,"----------------------------------------------------------------\n");
	unsigned long long total_bridge_num = 0;
	fprintf(fp,"%10s %13s %s\n", "Bridge_ID", "In_Use_Number", "Bridge_Name");
	for(i = 0; i < STREAM_BRIDGE_MAX_NUM; i++){
		if(cur_bridge_in_use_array[i] > 0){
			fprintf(fp,"%10d %13llu %s\n", i, cur_bridge_in_use_array[i], stream_bridge_id_to_name(i));
			total_bridge_num += cur_bridge_in_use_array[i];
		}
	}		
	fprintf(fp,"%10s %13llu %s\n", "Total", total_bridge_num, "N/A");

	fprintf(fp,"#################################################################\n");
	fprintf(fp,"%-12s %12s %12s %12s %12s\n","SND-PKT", "total_pkt", "total_len","pps", "bps");
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n", "TCP_RST", cur_count[SAPP_STAT_SND_TCP_RST], byte_convert_human(cur_length[SAPP_STAT_SND_TCP_RST], 1, 1, s1),(cur_count[SAPP_STAT_SND_TCP_RST]-history_count[SAPP_STAT_SND_TCP_RST]), byte_convert_human((cur_length[SAPP_STAT_SND_TCP_RST]-history_length[SAPP_STAT_SND_TCP_RST]), 1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n", "TCP_S/A", cur_count[SAPP_STAT_SND_TCP_SYNACK], byte_convert_human(cur_length[SAPP_STAT_SND_TCP_SYNACK], 1, 1, s1),(cur_count[SAPP_STAT_SND_TCP_SYNACK]-history_count[SAPP_STAT_SND_TCP_SYNACK]), byte_convert_human((cur_length[SAPP_STAT_SND_TCP_SYNACK]-history_length[SAPP_STAT_SND_TCP_SYNACK]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n", "UDP", cur_count[SAPP_STAT_SND_UDP], byte_convert_human(cur_length[SAPP_STAT_SND_UDP],1,1,s1),(cur_count[SAPP_STAT_SND_UDP]-history_count[SAPP_STAT_SND_UDP]), byte_convert_human((cur_length[SAPP_STAT_SND_UDP]-history_length[SAPP_STAT_SND_UDP]),1,8,s2));
	fprintf(fp,"%-12s %12llu %12s %12llu %12s\n", "SEND-ERR", cur_count[SAPP_STAT_SND_ERROR], byte_convert_human(cur_length[SAPP_STAT_SND_ERROR],1,1,s1),(cur_count[SAPP_STAT_SND_ERROR]-history_count[SAPP_STAT_SND_ERROR]), byte_convert_human((cur_length[SAPP_STAT_SND_ERROR]-history_length[SAPP_STAT_SND_ERROR]),1,8,s2));
    fprintf(fp,"#################################################################\n\n");
	fclose(fp);

	packet_io_update_metrics();
	
	memcpy(history_count, cur_count, sizeof(history_count));
	memcpy(history_length, cur_length, sizeof(history_length));

	for(i = 0;i < g_packet_io_thread_num;i++){
		memcpy(&history_threads_stat[i], &mstat[i]->sys_stat, sizeof(sapp_gval_mthread_sys_stat_t));
	}

	return ;
}


#ifdef __cplusplus
}
#endif

