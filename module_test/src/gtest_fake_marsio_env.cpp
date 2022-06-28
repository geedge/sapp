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
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/limits.h>
#include <linux/if_ether.h>
#include <pthread.h>
#include "fake_marsio.h"
#include "fake_mrtunnat.h"
#include <pcap/pcap.h>
#include "gtest_sapp_fun.h"

/* 本文件创建一个虚假的marsio.so, 用于在无mrzcpd的环境下, 比如虚拟机、CI里测试sapp marsio模式的功能 */

#ifdef __cplusplus
extern "C" {
#endif

static pcap_queue_t g_pcap_pkt_queue; /* pcap包里的原始数据包, 不能直接传递给sapp, 因为可能会被修改! 先要复制一份副本 */
static unsigned char g_fake_marsio_pcap_file_md5sum[64];
static int fake_marsio_default_result_flag = GTEST_SAPP_ERR; /* 0:success; -1:error */

static void __fake_marsio_vlan_flip_no_mac_flip_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	const struct pkt_check_args_t *check_args = (struct pkt_check_args_t *)user;
	int raw_pkt_index = check_args->mr_ins->pcap_queue_index - 1; /* 发送一个自增1, 取前一个包验证时先要index减1 */
	int ret;
	const struct ethhdr *raw_eth_hdr = (struct ethhdr *)g_pcap_pkt_queue.pkt_array[raw_pkt_index].raw_pkt_data;
	const struct ethhdr *sapp_feedback_eth_hdr = (struct ethhdr *)data;

	ret =  check_ethernet_pkt_equal(raw_eth_hdr, sapp_feedback_eth_hdr, 0); /* mac地址不翻转 */
	if(ret < 0){
		MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_no_mac_flip","\033[1;31;40m vlan_flip_no_mac_flip(): mac addr is not equal!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return;
	}

	if(VLAN_UPLINK_ID == g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id){
		/* sapp发出的数据包和原始包vlan id要翻转 */
		if(check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id != VLAN_DOWNLINK_ID){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_no_mac_flip",
					"\033[1;31;40mvlan_flip_no_mac_flip():pkt_index:%d, vlan id is not match, raw vlan id is:%d, sapp set vlan id is:%d!\033[0m\n", 
					raw_pkt_index,
				   g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id,
				   check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id );
			sendto_test_result(GTEST_SAPP_ERR);
			return;
		}
	}else{
		if(check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id != VLAN_UPLINK_ID){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_no_mac_flip",
					"\033[1;31;40mvlan_flip_no_mac_flip(): pkt_index:%d, vlan id is not match, raw vlan id is:%d, sapp set vlan id is:%d!\033[0m\n", 
					raw_pkt_index,
				   g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id,
				   check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id );
			sendto_test_result(GTEST_SAPP_ERR);
			return;
		}
	}

	/* 一共两个包, 全部处理完后没有错误, 就是正确的! */
	if(2 == check_args->mr_ins->pcap_queue_index){
		MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_flip_no_mac_flip", "\033[32mvlan_flip_no_mac_flip() test success!\033[0m\n");
		fprintf(stderr, "\033[32mvlan_flip_no_mac_flip() test success!\033[0m\n");
		sendto_test_result(GTEST_FAKE_MARSIO_SUCC);
		return;
	}
}

static void __fake_marsio_vlan_flip_and_mac_flip_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	const struct pkt_check_args_t *check_args = (struct pkt_check_args_t *)user;
	int raw_pkt_index = check_args->mr_ins->pcap_queue_index - 1; /* 发送一个自增1, 取前一个包验证时先要index减1 */
	int ret;
	const struct ethhdr *raw_eth_hdr = (struct ethhdr *)g_pcap_pkt_queue.pkt_array[raw_pkt_index].raw_pkt_data;
	const struct ethhdr *sapp_feedback_eth_hdr = (struct ethhdr *)data;

	ret =  check_ethernet_pkt_equal(raw_eth_hdr, sapp_feedback_eth_hdr, 1); /* mac地址要翻转 */
	if(ret < 0){
		MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_flip_and_mac_flip","\033[1;31;40mvlan_flip_and_mac_flip(): mac addr is not reverse!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return;
	}

	if(VLAN_UPLINK_ID == g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id){
		/* sapp发出的数据包和原始包vlan id要翻转 */
		if(check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id != VLAN_DOWNLINK_ID){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_and_mac_flip",
					"\033[1;31;40mvlan_flip_and_mac_flip():vlan id is not match, raw vlan id is:%d, sapp set vlan id is:%d!\033[0m\n", 
				   g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id,
				   check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id );
			sendto_test_result(GTEST_SAPP_ERR);
			return;
		}
	}else{
		if(check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id != VLAN_UPLINK_ID){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_and_mac_flip",
					"\033[1;31;40mvlan_flip_and_mac_flip():vlan id is not match, raw vlan id is:%d, sapp set vlan id is:%d!\033[0m\n", 
				   g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id,
				   check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id );
			sendto_test_result(GTEST_SAPP_ERR);
			return;
		}
	}

	/* 一共两个包, 全部处理完后没有错误, 就是正确的! */
	if(2 == check_args->mr_ins->pcap_queue_index){
		MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_flip_and_mac_flip", "\033[32mvlan_flip_and_mac_flip() test success!\033[0m\n");
		sendto_test_result(GTEST_FAKE_MARSIO_SUCC);
		fprintf(stderr, "\033[32mvlan_flip_and_mac_flip() test success!\033[0m\n");
		return;
	}	
}

static void __fake_marsio_vlan_flip_symmetric_mpls_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	const struct pkt_check_args_t *check_args = (struct pkt_check_args_t *)user;
	int raw_pkt_index = check_args->mr_ins->pcap_queue_index - 1; /* 发送一个自增1, 取前一个包验证时先要index减1 */
	int ret;
	const struct ethhdr *raw_eth_hdr = (struct ethhdr *)g_pcap_pkt_queue.pkt_array[raw_pkt_index].raw_pkt_data;
	const struct ethhdr *sapp_feedback_eth_hdr = (struct ethhdr *)data;

	ret =  check_ethernet_pkt_equal(raw_eth_hdr, sapp_feedback_eth_hdr, 1); /* mac地址翻转 */
	if(ret < 0){
		MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_symmetric_mpls","\033[1;31;40mmac addr is not equal!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return;
	}

	if(VLAN_UPLINK_ID == g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id){
		/* sapp发出的数据包和原始包vlan id要翻转 */
		if(check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id != VLAN_DOWNLINK_ID){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_symmetric_mpls","\033[1;31;40mvlan id is not match, raw vlan id is:%d, sapp set vlan id is:%d!\033[0m\n", 
				   g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id,
				   check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id );
			sendto_test_result(GTEST_SAPP_ERR);
			return;
		}
	}else{
		if(check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id != VLAN_UPLINK_ID){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_symmetric_mpls","\033[1;31;40mvlan id is not match, raw vlan id is:%d, sapp set vlan id is:%d!\033[0m\n", 
				   g_pcap_pkt_queue.pkt_array[raw_pkt_index].vlan_id,
				   check_args->mr_ins->pkt_queue.pkt_array[raw_pkt_index].after_sapp_flip_vlan_id );
			sendto_test_result(GTEST_SAPP_ERR);
			return;
		}
	}

	if(raw_eth_hdr->h_proto == htons(ETH_P_MPLS_UC)){ /* 原始包里有mpls就检查, 否则不查 */
		ret =  check_mpls_pkt_equal((struct mesa_mpls_hdr *)((char *)raw_eth_hdr+ sizeof(struct ethhdr)), (struct mesa_mpls_hdr *)(data + sizeof(struct ethhdr)));
		if(ret < 0){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_FATAL, "vlan_flip_symmetric_mpls","\033[1;31;40mmpls addr is not equal!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return;
		}
	}

	/* 一共3个包, 全部处理完后没有错误, 就是正确的! */
	if(3 == check_args->mr_ins->pcap_queue_index){
		MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_flip_symmetric_mpls", "\033[32mmarsio_vlan_flip_symmetric_mpls() test success!\033[0m\n");
		sendto_test_result(GTEST_FAKE_MARSIO_SUCC);
		fprintf(stderr, "\033[32mvlan_flip_symmetric_mpls() test success!\033[0m\n");
		return;
	}		
}


static void __fake_marsio_vlan_mac_flip_inject_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	const struct pkt_check_args_t *check_args = (struct pkt_check_args_t *)user;
	const struct ethhdr *raw_eth_hdr;
	const struct ethhdr *plug_inject_eth_hdr = (struct ethhdr *)data;
	int ret;
	
	static int pkt_index = 0;

	//tcp_inject_vlan_mac_flip.pcap, 第4个包是C2S client hello, 插件会丢弃此包, 并以此包触发, 注入两个新数据包
	//先注入C2S方向的, 与第1个SYN包理论上地址是一样的,
	if(3 == pkt_index){
		raw_eth_hdr = (struct ethhdr *)g_pcap_pkt_queue.pkt_array[0].raw_pkt_data;
		ret = check_ethernet_pkt_equal(raw_eth_hdr, plug_inject_eth_hdr, 1);
		if(ret < 0){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_mac_flip_inject", "\033[1;31;40m ### __fake_marsio_vlan_mac_flip_inject_cb(): index:%d, mac addr error!\033[0m\n", pkt_index);
			fprintf(stderr, "\033[1;31;40m ### __fake_marsio_vlan_mac_flip_inject_cb(): index:%d, mac addr error!\033[0m\n", pkt_index);
			sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}		

		/* sapp发出的数据包和原始包vlan id要翻转 */
		if(check_args->mr_ins->pkt_queue.pkt_array[0].vlan_id == check_args->mr_ins->inject_pkt_buf.after_sapp_flip_vlan_id){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_mac_flip_inject", 
					"\033[1;31;40m ### __fake_marsio_vlan_mac_flip_inject_cb(): index:%d, vlan id error, raw_id:%d, inject id:%d\033[0m\n", 
					pkt_index, 
					check_args->mr_ins->pkt_queue.pkt_array[0].vlan_id,
					check_args->mr_ins->inject_pkt_buf.after_sapp_flip_vlan_id);
			sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
	}

	/* pkt_index=4, 即第5个包, 也就是注入的第2个包, 即S2C方向的, 以SYN/ACK包作为基准比较 */

	/* 别着急! 
	   某个用例会打印下面的错误日志, 但不是BUG!
	   这个测试用例就是应该错的 !!!
	*/
	if(4 == pkt_index){
		raw_eth_hdr = (struct ethhdr *)g_pcap_pkt_queue.pkt_array[1].raw_pkt_data;
		ret = check_ethernet_pkt_equal(raw_eth_hdr, plug_inject_eth_hdr, 1);
		if(ret < 0){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_mac_flip_inject", 
					"\033[1;31;40m @@@ __fake_marsio_vlan_mac_flip_inject_cb(): index:%d, mac addr error!\033[0m\n", pkt_index);
			fprintf(stderr, "\033[1;31;40m ### __fake_marsio_vlan_mac_flip_inject_cb(): index:%d, mac addr error!\033[0m\n", pkt_index);
			sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}	
		
		/* sapp发出的数据包和基准包vlan id要翻转 */
		if(check_args->mr_ins->pkt_queue.pkt_array[1].vlan_id == check_args->mr_ins->inject_pkt_buf.after_sapp_flip_vlan_id){
			MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_mac_flip_inject", 
					"\033[1;31;40m @@@ __fake_marsio_vlan_mac_flip_inject_cb(): index:%d, vlan id error,, raw_id:%d, inject id:%d\033[0m\n", 
					pkt_index,
					check_args->mr_ins->pkt_queue.pkt_array[1].vlan_id,
					check_args->mr_ins->inject_pkt_buf.after_sapp_flip_vlan_id);

			sendto_test_result(GTEST_SAPP_ERR);
			exit(1);
		}
	}

	pkt_index++;

	/* 一共5个包, 全部处理完后没有错误, 就是正确的! */
	if(5 == pkt_index){
		MESA_handle_runtime_log(check_args->mr_ins->log_handle, RLOG_LV_INFO, "vlan_mac_flip_inject", "\033[32mmarsio_vlan_mac_flip_inject() test success!\033[0m\n");
		sendto_test_result(GTEST_FAKE_MARSIO_SUCC);
		fprintf(stderr, "\033[32mmarsio_vlan_mac_flip_inject() test success!\033[0m\n");
		exit(0);
	}	
	
}

/*
TODO:
	这些函数大同小异, 都是检查某个数据包某个字段是否存在、是什么值、是不是反向, 
	抽取公共部分, 增加参数, 共用一个函数实现.
*/	

static pcap_md5_tuple_t fake_marsio_md5_tuple[] = 
{
	{"b621d91181eddfe028dab095df530824",	GTEST_RESULT_NONE, __fake_marsio_vlan_flip_no_mac_flip_cb,		"测试开启vlan flipping, 但是没有mac flipping的回流回注功能"},
	{"5a588633faa677283fa32cd7c5f3cc97",	GTEST_RESULT_NONE, __fake_marsio_vlan_flip_and_mac_flip_cb,	"测试开启vlan flipping, 但是没有mac flipping的回流回注功能"},
	{"50ef8a3004c9460482d8628c8187f533",	GTEST_RESULT_NONE, __fake_marsio_vlan_flip_symmetric_mpls_cb,	"测试开启vlan flipping + symmetric_mpls 0vs1 的回流回注功能"},
	{"04d5ffa60b959efe7a87ea31fd5fecd9",	GTEST_RESULT_NONE, __fake_marsio_vlan_flip_symmetric_mpls_cb,	"测试开启vlan flipping + symmetric_mpls 1vs2 的回流回注功能"},
	{"777460d92d1b4e98ee22cd14139fa772",	GTEST_RESULT_NONE, __fake_marsio_vlan_mac_flip_inject_cb,		"测试开启vlan和mac flipping, 插件主动注入数据包的测试"},
	
	{NULL, GTEST_SAPP_ERR, NULL, NULL}, /* EOF */
};	


static void __pcap_pkt_handle(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	pcap_queue_t *pcap_pkt_queue = (pcap_queue_t *)user;
	//const u_char *eth_dst_addr, *eth_src_addr;
	int route_dir;
	
	pcap_pkt_queue->pkt_array = (marsio_buff_t *)realloc(pcap_pkt_queue->pkt_array, sizeof(marsio_buff_t) * (pcap_pkt_queue->pkt_num + 1));

	memcpy(pcap_pkt_queue->pkt_array[pcap_pkt_queue->pkt_num].raw_pkt_data, data, hdr->caplen);
	pcap_pkt_queue->pkt_array[pcap_pkt_queue->pkt_num].raw_pkt_len = hdr->caplen;
	pcap_pkt_queue->pkt_array[pcap_pkt_queue->pkt_num].by_malloc_need_free = 0;

	//eth_dst_addr = data;
	//eth_src_addr = data + ETH_ALEN;

	route_dir = pcap_replay_route_dir(data);
	if(route_dir < 0){
		printf("can't get route dir!\n");
		abort();
	}
	if(0 == route_dir){ /* 根据mac地址的不同, 分成两个方向up和down, 分别设置不同的vlan id */
		pcap_pkt_queue->pkt_array[pcap_pkt_queue->pkt_num].vlan_id = VLAN_UPLINK_ID;
	}else{
		pcap_pkt_queue->pkt_array[pcap_pkt_queue->pkt_num].vlan_id = VLAN_DOWNLINK_ID;
	}

	///printf("###debug: pcap pkt prepare, index:%d, vlan_id:%d\n", pcap_pkt_queue->pkt_num, pcap_pkt_queue->pkt_array[pcap_pkt_queue->pkt_num].vlan_id);
	//todo ctrlzone
	pcap_pkt_queue->pkt_num++;
}

static int fake_marsio_get_pkt_from_pcap(struct mr_instance * instance)
{
	pcap_t *pcap_handle;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	pcap_handle = pcap_open_offline("dumpfile", pcap_errbuf);
	if(NULL == pcap_handle){
		printf("pcap open %s error, %s\n", "dumpfile", pcap_errbuf );
		return -1;
	}

	memset(&g_pcap_pkt_queue, 0, sizeof(g_pcap_pkt_queue));
	
	pcap_loop(pcap_handle, -1, __pcap_pkt_handle, (u_char *)&g_pcap_pkt_queue);

	/* 完全复制一份pcap queue保存到instance里 */
	memset(&instance->pkt_queue, 0, sizeof(instance->pkt_queue));
	instance->pkt_queue.pkt_array = (marsio_buff_t *)malloc(sizeof(marsio_buff_t) * g_pcap_pkt_queue.pkt_num);
	memcpy(instance->pkt_queue.pkt_array, g_pcap_pkt_queue.pkt_array, sizeof(marsio_buff_t) * g_pcap_pkt_queue.pkt_num);
	instance->pkt_queue.pkt_num = g_pcap_pkt_queue.pkt_num;
	instance->pcap_queue_index = 0;
	
	return 0;
}


/**************************************** fake marsio 对sapp提供的接口  ********************************************/
int marsio_buff_get_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data)
{
	int ret = 0;
	
	switch(type){
		case MR_BUFF_METADATA_VLAN_TCI:
		{
			int *raw_vlan_id = (int *)data;
			*raw_vlan_id = (int)m->vlan_id;
		}
		break;

		default:
			/* 其他字段不支持 */
			ret = -1;
	}

	
	return ret;
}

/*
	mbuff实际是在marsio_recv_burst时给sapp的, 可以将sapp设置的选项和值, 比如vlan_id保存下来.
*/
int marsio_buff_set_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type, void *data, unsigned int sz_data)
{
	int ret = 0;
	
	switch(type){
		case MR_BUFF_METADATA_VLAN_TCI:
		{
			int *new_vlan_id = (int *)data;
			m->after_sapp_flip_vlan_id = (vlan_flipping_tuple_t)(*new_vlan_id);
		}
		break;

		default:
			/* 其他字段不支持 */
			ret = -1;
	}

	return ret;

}

int marsio_buff_unset_metadata(marsio_buff_t *m, enum mr_buff_metadata_type type)
{
	return 0;
}


void marsio_buff_free(struct mr_instance * instance, marsio_buff_t *marsio_buff[],unsigned int nr_mbufs, int socket_id, int thread_id)
{
	if(nr_mbufs > 1){
		printf("marsio_buff_free error!\n");
		marsio_buff[0] = NULL;
		return;
	}
	
	memset(&instance->inject_pkt_buf, 0, sizeof(marsio_buff_t));
	
	return;
}

int marsio_buff_malloc_global(struct mr_instance * instance, marsio_buff_t *marsio_buff[], unsigned int nr_mbufs, int socket_id, int thread_id)
{
	/* 功能测试, 暂时只支持获取1块mbuff内存 */
	if(nr_mbufs > 1){
		printf("marsio_buff_malloc_global error!\n");
		marsio_buff[0] = NULL;
		return -1;
	}	

	marsio_buff[0] = &instance->inject_pkt_buf;
	
	return nr_mbufs;
}

char *marsio_buff_append(marsio_buff_t *m, uint16_t len)
{
	//返回真实的数据缓冲区地址
	return (char *)m->raw_pkt_data;
}


int marsio_option_set(struct mr_instance * instance, marsio_opt_type_t opt_type, void * opt, size_t sz_opt)
{
	return 0;
}


char *marsio_buff_mtod(marsio_buff_t *m)
{
	return (char *)m->raw_pkt_data;
}

uint32_t marsio_buff_datalen(marsio_buff_t *m)
{
	return m->raw_pkt_len;
}

uint32_t marsio_buff_buflen(marsio_buff_t *m)
{
	return m->raw_pkt_len;
}

marsio_buff_t *marsio_buff_clone_with_options(
        struct mr_instance *instance, marsio_buff_t *raw_mbuff, int socket_id, int thread_id, uint16_t options)
{
	marsio_buff_t *new_mbuff;

	new_mbuff = (marsio_buff_t *)calloc(1, sizeof(marsio_buff_t));

	memcpy(new_mbuff->raw_pkt_data, raw_mbuff->raw_pkt_data, raw_mbuff->raw_pkt_len);
	new_mbuff->raw_pkt_len = raw_mbuff->raw_pkt_len;
	
	return new_mbuff;
}


void *marsio_buff_ctrlzone(marsio_buff_t *m, uint8_t id)
{
	return &m->ctrlzone;
}

void marsio_buff_ctrlzone_set(marsio_buff_t *m, uint8_t id, void *ptr_data, uint8_t size)
{
	return;
}

void marsio_buff_set_rehash_index(marsio_buff_t *m, uint32_t hash)
{
	return;
}




int marsio_thread_init(struct mr_instance *instance)
{
	return 0;
}

int marsio_init(struct mr_instance * instance, const char * appsym)
{
	/* 从dumpfile里读取pcap包, 保存到队列中, sapp调用marsio_recv_burst()时传递给sapp  */
	int ret = fake_marsio_get_pkt_from_pcap(instance);
	if(ret < 0){
		printf("get pkt from pcap dumpfile error!\n");
		abort();
	}
	MESA_handle_runtime_log(instance->log_handle, RLOG_LV_INFO, "fake_marsio", "marsio_init() get pkt from pcap succ!");

	gtest_file_md5sum("dumpfile", (char *)g_fake_marsio_pcap_file_md5sum, sizeof(g_fake_marsio_pcap_file_md5sum));

	gtest_sapp_slave_init(); /* 创建一个unix socket接口, 用来发送测试结果 */

	MESA_handle_runtime_log(instance->log_handle, RLOG_LV_INFO, "fake_marsio", "gtest_sapp_slave_init() succ!");
	
	return ret;
}


struct mr_vdev * marsio_open_device(struct mr_instance * instance,
    const char * devsym, unsigned int nr_rxstream, unsigned int nr_txstream)
{
	struct mr_vdev *mrdev = (struct mr_vdev *)malloc(sizeof(struct mr_vdev));

	mrdev->device_name = strdup(devsym);

	mrdev->mrins = instance;

	return mrdev;
}

void marsio_close_device(struct mr_vdev *vdev)
{
	//TODO
	return;
}



struct mr_sendpath * marsio_sendpath_create_by_vdev(struct mr_vdev * dest_device)
{
	struct mr_sendpath *mrsndp = (struct mr_sendpath *)malloc(sizeof(struct mr_sendpath));

	mrsndp->mrins = dest_device->mrins;

	return mrsndp;
}

void marsio_sendpath_destory(struct mr_sendpath * sendpath)
{
	return;
}


int marsio_recv_burst(struct mr_vdev * vdev, queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs)
{
	struct mr_instance *mrins = vdev->mrins;
	//从pcap包里依次读取1个包

	if(mrins->pcap_queue_index >= mrins->pkt_queue.pkt_num){/* pcap队列的包已经全部读取完了, 如果之前的包有错误, 其实走不到这里, 可以退出了 */
		if(GTEST_RESULT_NONE != fake_marsio_default_result_flag){
			MESA_handle_runtime_log(mrins->log_handle, RLOG_LV_INFO, "fake_marsio", "pcap process over, sendto check result:0x%x\n", fake_marsio_default_result_flag);
			sendto_test_result(fake_marsio_default_result_flag); 
			if(fake_marsio_default_result_flag == GTEST_SAPP_SUCC){
				fprintf(stderr, "marsio_recv_burst test success!\n");
			}
		}
		exit(0);
	}

	mbufs[0] = &mrins->pkt_queue.pkt_array[mrins->pcap_queue_index];
	
	mrins->pcap_queue_index++;
	
	return 1; /* 自测试, 每次只取1个包 */
}


int marsio_send_burst(struct mr_sendpath * sendpath,  queue_id_t qid, marsio_buff_t * mbufs[], int nr_mbufs)
{
	/* 这个包是sapp注入的包, 与之前注给sapp的包做对比, 检查各层是否正确, 比如alot模式下, vlan flipping是否翻转, 除此之外, 其他层应该完全一样 */
	int i;

	struct pcap_pkthdr temp_pcap_hdr = {};
	struct pkt_check_args_t check_args = {};

	temp_pcap_hdr.caplen = marsio_buff_datalen(mbufs[0]); /* 自测试, 每次只取1个包 */
	temp_pcap_hdr.len = temp_pcap_hdr.caplen;

	check_args.mr_sndpath = sendpath;
	check_args.mr_ins = sendpath->mrins;
	check_args.mbuff = mbufs[0]; /* 自测试, 每次只取1个包 */
	
	for(i = 0; fake_marsio_md5_tuple[i].pcap_file_md5 != NULL; i++){
		if(strncasecmp((char *)g_fake_marsio_pcap_file_md5sum, (char *)fake_marsio_md5_tuple[i].pcap_file_md5, strlen(fake_marsio_md5_tuple[i].pcap_file_md5)) == 0){
			fake_marsio_default_result_flag = fake_marsio_md5_tuple[i].default_check_result;
			fake_marsio_md5_tuple[i].pcap_callback((unsigned char *)&check_args, &temp_pcap_hdr, (unsigned char *)marsio_buff_mtod(mbufs[0]));
			break;
		}
	}

	/* 此函数内不容易区别哪个是回流回注, 哪个是插件主动造包, 都把注入缓冲区清空, 便于下次比较 */
	memset(&sendpath->mrins->inject_pkt_buf, 0, sizeof(marsio_buff_t));
	
	return 0;
}

void marsio_send_burst_flush(struct mr_sendpath *sendpath, queue_id_t sid)
{
	return;
}


int marsio_send_burst_with_options(
        struct mr_sendpath *sendpath, queue_id_t sid, marsio_buff_t *mbufs[], int nr_mbufs, uint16_t options)
{
	(void)options;
	
	return marsio_send_burst(sendpath, sid, mbufs, nr_mbufs);
}

struct mr_instance * marsio_create(void)
{
	struct mr_instance *mrins = (struct mr_instance *)calloc(1, sizeof(struct mr_instance));

	MESA_handle_runtime_log_creation("./etc/sapp_log.conf");
	mrins->log_handle = MESA_create_runtime_log_handle("./log/fake_marsio.log", RLOG_LV_DEBUG);

	MESA_handle_runtime_log(mrins->log_handle, RLOG_LV_DEBUG, "fake_marsio", "call marsio_create()...\n");
	
	return mrins;
}

int marsio_destory(struct mr_instance *instance)
{
	MESA_handle_runtime_log(instance->log_handle, RLOG_LV_DEBUG, "fake_marsio", "call marsio_destory()...\n");
	
	MESA_destroy_runtime_log_handle(instance->log_handle);

	//TODO, free其他内存
	
	free(instance);
	
	return 0;
}


#ifdef __cplusplus
}
#endif

