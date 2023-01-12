#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
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
#include "stream.h"
#include "gtest_sapp_fun.h"
/*
	除了检查最内层的四元组是否正确, 还要检查底层L2-L3层隧道填充的是否正确,
	sapp通过set_pcap_dumpfile()函数, 事先肯定知道本次测试用例读的是什么格式的pcap包, 
	但是业务插件不知道, 怎么把这个信息传递给插件呢??
      1)靠MESA_get_stream_opt()获取隧道类型?  某些层如vlan, mpls是不算为tunnel的, 而且不同的包地址信息也不太精确.
      2)插件也读取当前dumpfile的md5值, 这些pcap包是根据测试用例精确构造的, 数据包地址信息不会变.
*/


struct inject_pkt_para{
	enum gtest_inject_type inject_type;
	enum sapp_inject_opt inject_opt;
	struct rst_tcp_para rst_para; 
	/*  
	    dir:
	    发送rst包方向, 可选值为[DIR_C2S, DIR_S2C, DIR_DOUBLE], 此值参考:streaminfo->curdir,  
		如果待发送的包与当前包同向, dir = stream->curdir, 
		如果待发送的包与当前包反向, dir = stream->curdir ^ 3, 即反向.
		如果是双向发送, dir = DIR_DOUBLE;
	*/
	unsigned char  send_stream_dir; 	
	const char *payload;
	int payload_len;
};


typedef struct{
	const char *pcap_file_md5sum;
	int (*check_fun)(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
}inject_check_l2_l3_layer_t;



static int g_tun_fd = -1;
static volatile int g_recv_thread_inited = 0;
static volatile int g_recv_tun_rst_flag = 0; /* 0:init; 1:succ; 2:error or timeout */
static char g_recv_tun_rst_buf[256]; /* from ip header, not include mac */

static const unsigned char G_BROADCAST_ADDR[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define USE_TUN_TYPE_FOR_SEND_DEVICE (0) /* 1:使用tun设备作为发包默认网卡, 从ip头开始; 0:使用tap设备, 从mac头开始 */


static int check_send_pkt_a2bf72d3f73142e80de77657c61f62d5(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_9d531337eec3c38c7336cd38ddec296e(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_00765a14b12a6551904be00b54f2189c(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_0e35b157aee65111a9075f5b2dc1a7c8(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_e4357ef2933e139bea72d0f77e6b0d96(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_d4c5e09bba97e72cbc6f04f64439a624(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_5fb19164daeb5e665047f45d88890b0a(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_29589eeca441438807e7606f7006e9e7(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_502e5d3fbcce730493175a491c7102a6(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_98755901f48760e6a5e23fd41b21dd91(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_76b4545432085c74817411bb1ecf450f(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_6be85f33b5eba93fd184bcecf27e41ae(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_0b1d409dcc3987f55465c4c989da1651(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
static int check_send_pkt_62cbdf729199bcca78de9b4944da5256(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);


static inject_check_l2_l3_layer_t g_inject_check_l2_l3_layer_fun[] =
{
	{"a2bf72d3f73142e80de77657c61f62d5", check_send_pkt_a2bf72d3f73142e80de77657c61f62d5}, /* pcap file: for_gtest_only/inject/tcp_rst_with_vlan_single_c2s.pcap */
	{"9d531337eec3c38c7336cd38ddec296e", check_send_pkt_9d531337eec3c38c7336cd38ddec296e}, /* pcap file: for_gtest_only/inject/tcp_rst_with_vlan_pppoe.pcap */
	{"00765a14b12a6551904be00b54f2189c", check_send_pkt_00765a14b12a6551904be00b54f2189c}, /* pcap file: for_gtest_only/inject/tcp_rst_with_mpls_asymmetric_1vs2.pcap */
	{"0e35b157aee65111a9075f5b2dc1a7c8", check_send_pkt_0e35b157aee65111a9075f5b2dc1a7c8}, /* pcap file: for_gtest_only/inject/tcp_rst_with_mpls_asymmetric_0vs2.pcap */
	{"5fb19164daeb5e665047f45d88890b0a", check_send_pkt_5fb19164daeb5e665047f45d88890b0a}, /* pcap file: for_gtest_only/inject/tcp_rst_with_mpls_single_c2s.pcap */
	{"e4357ef2933e139bea72d0f77e6b0d96", check_send_pkt_e4357ef2933e139bea72d0f77e6b0d96}, /* pcap file: for_gtest_only/inject/tcp_rst_with_vpls.pcap */
	{"d4c5e09bba97e72cbc6f04f64439a624", check_send_pkt_d4c5e09bba97e72cbc6f04f64439a624}, /* pcap file: for_gtest_only/inject/tcp_rst_with_double_vlan.pcap */
	{"29589eeca441438807e7606f7006e9e7", check_send_pkt_29589eeca441438807e7606f7006e9e7}, /* pcap file: for_gtest_only/inject/tcp_rst_mpls_vlan_mpls_mxpe_s2c.pcap */
	{"502e5d3fbcce730493175a491c7102a6", check_send_pkt_502e5d3fbcce730493175a491c7102a6}, /* pcap file: for_gtest_only/inject/udp_mpls_vlan_mpls_mxpe_s2c.pcap */
	{"98755901f48760e6a5e23fd41b21dd91", check_send_pkt_98755901f48760e6a5e23fd41b21dd91}, /* pcap file: for_gtest_only/inject/tcp_asymmetric_mpls_vlan_mpls_mxpe_double.pcap */
	{"76b4545432085c74817411bb1ecf450f", check_send_pkt_76b4545432085c74817411bb1ecf450f}, /* pcap file: for_gtest_only/vlan/QinQ_with_http.pcap */
	{"6be85f33b5eba93fd184bcecf27e41ae", check_send_pkt_6be85f33b5eba93fd184bcecf27e41ae}, /* pcap file: for_gtest_only/inject/tcp_rst_packet_sample.pcap */
	{"0b1d409dcc3987f55465c4c989da1651", check_send_pkt_0b1d409dcc3987f55465c4c989da1651}, /* pcap file: for_gtest_only/gtp/gtp_double.pcap */
	{"6aa039f5c2be11ae72ec78346e50ab94", check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94}, /* pcap file: for_gtest_only/inject/tcp_rst_with_l2tp.pcap */
	{"62cbdf729199bcca78de9b4944da5256", check_send_pkt_62cbdf729199bcca78de9b4944da5256}, /* pcap file: for_gtest_only/inject/tcp_rst_with_l2tp_ppp_hdr_compress.pcap */
	{NULL, NULL}
};


extern const void *MESA_net_jump_to_layer(const void *raw_data,  int raw_layer_type, int expect_layer_type);


int get_file_md5sum(const char *filename, char *md5sum_result, int result_len)
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


static int identify_broadcast_multicast_pkt(const struct ethhdr *ehdr)
{
	if(memcmp(G_BROADCAST_ADDR, ehdr->h_dest, 6) == 0){
		return 1;
	}else{
		/* 2017-10-10 lijia add, 组播MAC地址, 通常为局域网内控制类数据包, 如LLMNR, STP等协议, 一般无需处理 */
		if((ehdr->h_dest[0] & 0x01) == 0x01){
			return 1;
		}
		if((0x33 == ehdr->h_dest[0]) && (0x33 == ehdr->h_dest[1])){
			return 1;
		}
	}

	return 0;
}

static /* 把网络传输的地址转换为内存结构, 方便业务插件处理 */
int vlan_addr_net_to_mem(const struct mesa_vlan_detail_hdr *net_vlan_hdr, struct single_layer_vlan_addr *mem_vlan_hdr)
{
	mem_vlan_hdr->VID = htons(net_vlan_hdr->vlan_id_high << 8 | net_vlan_hdr->vlan_id_low);
	mem_vlan_hdr->TPID = net_vlan_hdr->type;
	mem_vlan_hdr->PCP = net_vlan_hdr->priority;
	mem_vlan_hdr->DEI = net_vlan_hdr->del_flag;

	return 0;
}
static int sapp_set_vlan_addr(struct layer_addr_vlan *addr, const unsigned char *vlan_tag) //copy 自sapp
{
	int i;
	const struct mesa_vlan_detail_hdr *net_vhdr;
	int vlan_layer_len = 0;

	memset(addr, 0, sizeof(struct layer_addr_vlan));

	for(i = 0; i < MAX_VLAN_ADDR_LAYER; i++){
		net_vhdr = (struct mesa_vlan_detail_hdr *)vlan_tag;
		//memcpy(&addr->c2s_addr_array[i], vlan_tag, sizeof(struct mesa_vlan_hdr));

		vlan_addr_net_to_mem(net_vhdr, &addr->c2s_addr_array[i]);
		vlan_tag += sizeof(struct mesa_vlan_detail_hdr);
		vlan_layer_len += sizeof(struct mesa_vlan_detail_hdr);
		addr->c2s_layer_num++;
		if(ETH_P_8021Q != ntohs(net_vhdr->type)){
			break;
		}
	}
	
	return vlan_layer_len;
}

/*
	因为有某些单向流存在, 反向注入的包其实并没有地址,
	expect_dir_to_check_result: 使用哪个方向的地址信息用来检测rst包注入结果. 0表示根据inject_paras方向.
*/
static int check_send_pkt_vlan_layer(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, 
			void *raw_ip_pkt, const struct layer_addr_vlan *raw_pkt_vlan_info, UCHAR expect_dir_to_check_result)
{
#define VLAN_ID_MASK		(0x0FFF)	
	struct layer_addr_vlan inject_pkt_vlan_info;
	const void *vlan_layer_hdr;
	//unsigned short inject_vlan_id;
	UCHAR use_which_dir_to_check_result;

	vlan_layer_hdr = MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_MAC, ADDR_TYPE_VLAN);
	if(NULL == vlan_layer_hdr){
		printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:%d, can't found vlan layer!\033[0m\n", inject_paras->send_stream_dir);
		return -1;
	}
	sapp_set_vlan_addr(&inject_pkt_vlan_info, (unsigned char *)vlan_layer_hdr);

	if(0 == expect_dir_to_check_result){
		use_which_dir_to_check_result = inject_paras->send_stream_dir;
	}else{
		use_which_dir_to_check_result = expect_dir_to_check_result;
	}

	if(DIR_C2S == inject_paras->send_stream_dir){
		if(DIR_C2S == use_which_dir_to_check_result){
			if(inject_pkt_vlan_info.c2s_layer_num != raw_pkt_vlan_info->c2s_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:C2S, inject and raw vlan layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_pkt_vlan_info.c2s_addr_array, raw_pkt_vlan_info->c2s_addr_array, sizeof(struct single_layer_vlan_addr) * raw_pkt_vlan_info->c2s_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:C2S,inject and raw vlan layer value is different!\033[0m\n");
				return -1;
			}		
		}else{
			/* 发送的rst包是C2S方向, 但期待用S2C方向的原始包地址验证, 应该是S2C方向的单向流 */
			if(inject_pkt_vlan_info.c2s_layer_num != raw_pkt_vlan_info->s2c_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:C2S, inject and raw vlan layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_pkt_vlan_info.c2s_addr_array, raw_pkt_vlan_info->s2c_addr_array, sizeof(struct single_layer_vlan_addr) * raw_pkt_vlan_info->s2c_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:C2S,inject and raw vlan layer value is different!\033[0m\n");
				return -1;
			}	
		}
	}else{
		/* 当前包的inject_pkt固定取src方向 */
		if(DIR_S2C == use_which_dir_to_check_result){
			if(inject_pkt_vlan_info.c2s_layer_num != raw_pkt_vlan_info->s2c_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:S2C ,inject and raw vlan layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_pkt_vlan_info.c2s_addr_array, raw_pkt_vlan_info->s2c_addr_array, sizeof(struct single_layer_vlan_addr) * raw_pkt_vlan_info->s2c_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:S2C,inject and raw vlan layer value is different!\033[0m\n");
				return -1;
			}
		}else{
			/* 发送的rst包是S2C方向, 但期待用C2S方向的原始包地址验证, 应该是C2S方向的单向流 */
			if(inject_pkt_vlan_info.c2s_layer_num != raw_pkt_vlan_info->c2s_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:S2C,inject and raw vlan layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_pkt_vlan_info.c2s_addr_array, raw_pkt_vlan_info->c2s_addr_array, sizeof(struct single_layer_vlan_addr) * raw_pkt_vlan_info->c2s_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: dir:S2C,inject and raw vlan layer value is different!\033[0m\n");
				return -1;
			}
		}
	}	

	return 0;
}


/*
	pcap包tcp_rst_with_vlan_single_c2s.pcap, md5: a2bf72d3f73142e80de77657c61f62d5, 只有C2S单向流, 
	测双向发送rst时需要关闭asymmetric_addr_layer.
*/
static int check_send_pkt_a2bf72d3f73142e80de77657c61f62d5(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret;
	struct layer_addr_vlan raw_pkt_vlan_info;

	raw_pkt_vlan_info.c2s_layer_num = 1;
	raw_pkt_vlan_info.c2s_addr_array[0].TPID = htons(0x0800);
	raw_pkt_vlan_info.c2s_addr_array[0].PCP = 0; 
	raw_pkt_vlan_info.c2s_addr_array[0].DEI = 0;
	raw_pkt_vlan_info.c2s_addr_array[0].VID = htons(32); 
	
	ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, DIR_C2S);
	if(ret < 0){
		return -1;
	}

	/* 为了避免解析vlan出错, 即vlan_addr_net_to_mem和vlan_addr_mem_to_net都错了, 但最终导致负负得正的效果, 竟然是对的!
	   此处直接验证一下发包的二进制 
	 */
	const char *tun_rcv_pkt_vlan_layer = (char *)tun_rcv_pkt + sizeof(struct ethhdr);  
	const unsigned char c2s_vlan_bin[4] = {0x00,0x20, 0x08, 0x00};
	if(DIR_C2S == inject_paras->send_stream_dir){
		if(memcmp(tun_rcv_pkt_vlan_layer, c2s_vlan_bin, sizeof(c2s_vlan_bin)) != 0){
			return -1;
		}
	}

	return ret;
}


static int check_send_pkt_pppoe_layer(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt, unsigned short raw_session_id, unsigned short ppp_protocol)
{
	const struct mesa_pppoe_session_hdr *inject_pkt_pppoe_hdr;

	inject_pkt_pppoe_hdr = (struct mesa_pppoe_session_hdr *)MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_MAC, ADDR_TYPE_PPPOE_SES);
	if(NULL == inject_pkt_pppoe_hdr){
		printf("\033[1;31;40mcheck_send_pkt_vlan_layer()error: can't found pppoe layer\033[0m\n");
		return -1;
	}	

	if(inject_pkt_pppoe_hdr->session_id != htons(raw_session_id)){
		printf("\033[1;31;40mcheck_send_pkt_pppoe_layer()error: inject pppoe session_id:%x, raw vlan id:%x\033[0m\n", ntohs(inject_pkt_pppoe_hdr->session_id), raw_session_id);
	}

	if(inject_pkt_pppoe_hdr->ppp_protocol != htons(ppp_protocol)){
		printf("\033[1;31;40mcheck_send_pkt_pppoe_layer()error: inject pppoe ppp_protocol:%x, raw vlan id:%x\033[0m\n", ntohs(inject_pkt_pppoe_hdr->ppp_protocol), ppp_protocol);
	}

	return 0;
}

/* pcap : tcp_rst_with_vlan_pppoe.pcap */
static int check_send_pkt_9d531337eec3c38c7336cd38ddec296e(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret;
	struct layer_addr_vlan raw_pkt_vlan_info;

	raw_pkt_vlan_info.c2s_layer_num = 1;
	raw_pkt_vlan_info.c2s_addr_array[0].TPID = htons(0x8864);
	raw_pkt_vlan_info.c2s_addr_array[0].PCP = 3; 
	raw_pkt_vlan_info.c2s_addr_array[0].DEI = 0;
	raw_pkt_vlan_info.c2s_addr_array[0].VID = htons(1476);
	
	ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, 0);
	if(ret < 0){
		return -1;
	}

	ret = check_send_pkt_pppoe_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, 0xb4bc, 0x0021);
	if(ret < 0){
		return -1;
	}

	/* 为了避免解析vlan出错, 即vlan_addr_net_to_mem和vlan_addr_mem_to_net都错了, 但最终导致负负得正的效果, 竟然是对的!
	   此处直接验证一下发包的二进制 
	 */
	const char *tun_rcv_pkt_vlan_layer = (char *)tun_rcv_pkt + sizeof(struct ethhdr);  
	const unsigned char c2s_vlan_bin[4] = {0x65,0xc4, 0x88, 0x64};
	if(DIR_C2S == inject_paras->send_stream_dir){
		if(memcmp(tun_rcv_pkt_vlan_layer, c2s_vlan_bin, sizeof(c2s_vlan_bin)) != 0){
			return -1;
		}
	}
	
	return ret;
}





/*
	因为有某些单向流存在, 反向注入的包其实并没有地址,
	expect_dir_to_check_result: 使用哪个方向的地址信息用来检测rst包注入结果. 0表示根据inject_paras方向.
*/
static int check_send_pkt_mpls_layer(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, 
    void *raw_ip_pkt, const struct layer_addr_mpls *raw_mpls_layer_info, UCHAR expect_dir_to_check_result)
{
	const void *inject_pkt_mpls_hdr;
	struct layer_addr_mpls inject_mpls_layer_info = {};
	UCHAR use_which_dir_to_check_result;

	inject_pkt_mpls_hdr = MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_MAC, ADDR_TYPE_MPLS);
	if(NULL == inject_pkt_mpls_hdr){
		printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir:%d, can't found mpls layer\033[0m\n", inject_paras->send_stream_dir);
		return -1;
	}		

	if(0 == expect_dir_to_check_result){
		use_which_dir_to_check_result = inject_paras->send_stream_dir;
	}else{
		use_which_dir_to_check_result = expect_dir_to_check_result;
	}

	sapp_set_mpls_addr(&inject_mpls_layer_info, (unsigned char *)inject_pkt_mpls_hdr);

	if(DIR_C2S == inject_paras->send_stream_dir){
		if(DIR_C2S == use_which_dir_to_check_result){
			if(inject_mpls_layer_info.c2s_layer_num != raw_mpls_layer_info->c2s_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir C2S inject and raw mpls layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_mpls_layer_info.c2s_addr_array, raw_mpls_layer_info->c2s_addr_array, sizeof(struct single_layer_mpls_addr) * raw_mpls_layer_info->c2s_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir C2S inject and raw mpls layer value is different!\033[0m\n");
				return -1;
			}		

			if(inject_mpls_layer_info.c2s_has_ctrl_word){
				if(inject_mpls_layer_info.c2s_mpls_ctrl_word != raw_mpls_layer_info->c2s_mpls_ctrl_word){
					printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir C2S inject and raw mpls layer src_mpls_ctrl_word is different!\033[0m\n");
					return -1;
				}
			}
		}else{
			/* 发送的rst包是C2S方向, 但期待用S2C方向的原始包地址验证, 应该是S2C方向的单向流 */
			if(inject_mpls_layer_info.c2s_layer_num != raw_mpls_layer_info->s2c_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2c inject and raw mpls layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_mpls_layer_info.c2s_addr_array, raw_mpls_layer_info->s2c_addr_array, sizeof(struct single_layer_mpls_addr) * raw_mpls_layer_info->s2c_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2C inject and raw mpls layer value is different!\033[0m\n");
				return -1;
			}		

			if(inject_mpls_layer_info.c2s_has_ctrl_word){
				if(inject_mpls_layer_info.c2s_mpls_ctrl_word != raw_mpls_layer_info->s2c_mpls_ctrl_word){
					printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error:dir S2C inject and raw mpls layer src_mpls_ctrl_word is different!\033[0m\n");
					return -1;
				}
			}			
		}
	}else{
		if(DIR_S2C == use_which_dir_to_check_result){
			/* 当前包的inject_pkt固定取src方向 */
			if(inject_mpls_layer_info.c2s_layer_num != raw_mpls_layer_info->s2c_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2C inject and raw mpls layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_mpls_layer_info.c2s_addr_array, raw_mpls_layer_info->s2c_addr_array, sizeof(struct single_layer_mpls_addr) * raw_mpls_layer_info->s2c_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2C inject and raw mpls layer value is different!\033[0m\n");
				return -1;
			}	
			if(inject_mpls_layer_info.s2c_has_ctrl_word){
				if(inject_mpls_layer_info.s2c_mpls_ctrl_word != raw_mpls_layer_info->s2c_mpls_ctrl_word){
					printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2C inject and raw mpls layer dst_mpls_ctrl_word is different!\033[0m\n");
					return -1;
				}
			}	
		}else{
			/* 发送的rst包是S2C方向, 但期待用C2S方向的原始包地址验证, 应该是C2S方向的单向流 */
			if(inject_mpls_layer_info.c2s_layer_num != raw_mpls_layer_info->c2s_layer_num){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2C inject and raw mpls layer num is different!\033[0m\n");
				return -1;
			}
			if(memcmp(inject_mpls_layer_info.c2s_addr_array, raw_mpls_layer_info->c2s_addr_array, sizeof(struct single_layer_mpls_addr) * raw_mpls_layer_info->c2s_layer_num) != 0){
				printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2C inject and raw mpls layer value is different!\033[0m\n");
				return -1;
			}		
			
			if(inject_mpls_layer_info.c2s_has_ctrl_word){
				if(inject_mpls_layer_info.c2s_mpls_ctrl_word != raw_mpls_layer_info->c2s_mpls_ctrl_word){
					printf("\033[1;31;40mcheck_send_pkt_mpls_layer()error: dir S2C inject and raw mpls layer src_mpls_ctrl_word is different!\033[0m\n");
					return -1;
				}
			}	
		}
	}

	return 0;
}

static int check_send_pkt_eth_layer(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, 
	void *plug_raw_ip_hdr, const struct layer_addr_mac *raw_eth_layer_info, UCHAR expect_dir_to_check_result)
{
	const struct ethhdr *inject_inner_eth_hdr;

	/* 目前暂时不支持从外层ethernet层直接跳转到内层ethernet层, 迂回一下, 用mpls跳转到内层ethernet */
	inject_inner_eth_hdr = (struct ethhdr *)MESA_net_jump_to_layer((char *)tun_rcv_pkt+sizeof(struct ethhdr), ADDR_TYPE_MPLS, ADDR_TYPE_MAC);
	if(NULL == inject_inner_eth_hdr){
		printf("\033[1;31;40mcheck_send_pkt_eth_layer()error: dir:%d, can't found inner eth layer\033[0m\n", inject_paras->send_stream_dir);
		return -1;
	}

	if(DIR_S2C == expect_dir_to_check_result){
		if(memcmp(inject_inner_eth_hdr->h_source, raw_eth_layer_info->dst_addr.h_source, ETH_ALEN) != 0){
			printf("\033[1;31;40mcheck_send_pkt_eth_layer()error: dir S2C inner eth mac is diff!\033[0m\n");
			return -1;		
		}
		if(memcmp(inject_inner_eth_hdr->h_dest, raw_eth_layer_info->dst_addr.h_dest, ETH_ALEN) != 0){
			printf("\033[1;31;40mcheck_send_pkt_eth_layer()error: dir S2C inner eth mac is diff!\033[0m\n");
			return -1;		
		}		
	}else{
		if(memcmp(inject_inner_eth_hdr->h_source, raw_eth_layer_info->src_addr.h_source, ETH_ALEN) != 0){
			printf("\033[1;31;40mcheck_send_pkt_eth_layer()error: dir C2S inner eth mac is diff!\033[0m\n");
			return -1;	
		}
		if(memcmp(inject_inner_eth_hdr->h_dest, raw_eth_layer_info->src_addr.h_dest, ETH_ALEN) != 0){
			printf("\033[1;31;40mcheck_send_pkt_eth_layer()error: dir C2S inner eth mac is diff!\033[0m\n");
			return -1;		
		}	
	}
	
	return 0;
}


/* pcap file: for_gtest_only/inject/tcp_rst_with_mpls_asymmetric_1vs2.pcap */
static int check_send_pkt_00765a14b12a6551904be00b54f2189c(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret;
	struct layer_addr_mpls raw_mpls_layer_info = {};

	raw_mpls_layer_info.c2s_layer_num = 2;
	raw_mpls_layer_info.c2s_addr_array[0].label = htonl(301632);
	raw_mpls_layer_info.c2s_addr_array[0].experimental = 0;
	raw_mpls_layer_info.c2s_addr_array[0].bottom = 0;
	raw_mpls_layer_info.c2s_addr_array[0].ttl = 63;

	raw_mpls_layer_info.c2s_addr_array[1].label = htonl(794436);
	raw_mpls_layer_info.c2s_addr_array[1].experimental = 0;
	raw_mpls_layer_info.c2s_addr_array[1].bottom = 1;
	raw_mpls_layer_info.c2s_addr_array[1].ttl = 63;	
	
	raw_mpls_layer_info.s2c_layer_num = 1;
	raw_mpls_layer_info.s2c_addr_array[0].label = htonl(0);
	raw_mpls_layer_info.s2c_addr_array[0].experimental = 6;
	raw_mpls_layer_info.s2c_addr_array[0].bottom = 1;
	raw_mpls_layer_info.s2c_addr_array[0].ttl = 251;	

	ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_mpls_layer_info, 0);
	if(ret < 0){
		return -1;
	}

	/* 为了避免解析mpls出错, 即mpls_addr_net_to_mem和mpls_addr_mem_to_net都错了, 但最终导致负负得正的效果, 竟然是对的!
	   此处直接验证一下发包的二进制 
	 */
	const char *tun_rcv_pkt_mpls_layer = (char *)tun_rcv_pkt + sizeof(struct ethhdr);  
	const unsigned char c2s_2layer_mpls_bin[8] = {0x49,0xa4,0x00, 0x3f,0xc1,0xf4,0x41,0x3f};
	const unsigned char s2c_2layer_mpls_bin[4] = {0x00, 0x00, 0x0d, 0xfb};
	if(DIR_C2S == inject_paras->send_stream_dir){
		if(memcmp(c2s_2layer_mpls_bin, tun_rcv_pkt_mpls_layer, sizeof(c2s_2layer_mpls_bin)) != 0){
			return -1;
		}
	}else{
		if(memcmp(s2c_2layer_mpls_bin, tun_rcv_pkt_mpls_layer, sizeof(s2c_2layer_mpls_bin)) != 0){
			return -1;
		}
	}	

	printf("\033[32mcheck pkt mpls layer for 00765a14b12a6551904be00b54f2189c succ.\033[0m\n");
	
	return ret;
}


static int check_send_pkt_0e35b157aee65111a9075f5b2dc1a7c8(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret = 0;
	struct layer_addr_mpls raw_mpls_layer_info = {};

	raw_mpls_layer_info.c2s_layer_num = 2;
	raw_mpls_layer_info.c2s_addr_array[0].label = htonl(482736);
	raw_mpls_layer_info.c2s_addr_array[0].experimental = 0;
	raw_mpls_layer_info.c2s_addr_array[0].bottom = 0;
	raw_mpls_layer_info.c2s_addr_array[0].ttl = 63;

	raw_mpls_layer_info.c2s_addr_array[1].label = htonl(25365);
	raw_mpls_layer_info.c2s_addr_array[1].experimental = 0;
	raw_mpls_layer_info.c2s_addr_array[1].bottom = 1;
	raw_mpls_layer_info.c2s_addr_array[1].ttl = 63;	

	
	raw_mpls_layer_info.s2c_layer_num = 0; /* 非对称, S2C侧没有MPLS层 */
	memset(raw_mpls_layer_info.s2c_addr_array, 0, sizeof(raw_mpls_layer_info.s2c_addr_array));
	raw_mpls_layer_info.s2c_has_ctrl_word = 0;

	if(DIR_C2S == inject_paras->send_stream_dir){
		ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_mpls_layer_info, DIR_C2S);
		if(ret < 0){
			return -1;
		}
	}else{
		/* 非对称MPLS, S2C侧没MPLS层 */
		const struct ethhdr *outer_ehdr = (struct ethhdr *)(tun_rcv_pkt);
		if(ETH_P_8021AD != ntohs(outer_ehdr->h_proto)){
			printf("\033[1;31;40mcheck_send_pkt_0e35b157aee65111a9075f5b2dc1a7c8() error: outer ethernet type is not 0x88A8!\033[0m\n");
			return -1;
		}
		const struct ethhdr *inner_ehdr = (struct ethhdr *)((char *)tun_rcv_pkt + sizeof(struct ethhdr));
		if(ETH_P_IP != ntohs(inner_ehdr->h_proto)){
			printf("\033[1;31;40mcheck_send_pkt_0e35b157aee65111a9075f5b2dc1a7c8() error: inner ethernet type is not 0x0800!\033[0m\n");
			return -1;
		}		
	}

	

	printf("\033[32mcheck pkt mpls layer for 0e35b157aee65111a9075f5b2dc1a7c8 succ.\033[0m\n");

	return ret;
}


/* pcap file: for_gtest_only/inject/tcp_rst_with_mpls_single_c2s.pcap */
static int check_send_pkt_5fb19164daeb5e665047f45d88890b0a(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret = 0;
	struct layer_addr_mpls raw_mpls_layer_info = {};

	raw_mpls_layer_info.c2s_layer_num = 2;
	raw_mpls_layer_info.c2s_addr_array[0].label = htonl(18);
	raw_mpls_layer_info.c2s_addr_array[0].experimental = 5;
	raw_mpls_layer_info.c2s_addr_array[0].bottom = 0;
	raw_mpls_layer_info.c2s_addr_array[0].ttl = 255;

	raw_mpls_layer_info.c2s_addr_array[1].label = htonl(16);
	raw_mpls_layer_info.c2s_addr_array[1].experimental = 5;
	raw_mpls_layer_info.c2s_addr_array[1].bottom = 1;
	raw_mpls_layer_info.c2s_addr_array[1].ttl = 255;	

	raw_mpls_layer_info.c2s_has_ctrl_word = 0;

	ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_mpls_layer_info, DIR_C2S);
	if(ret < 0){
		return -1;
	}

	printf("\033[32mcheck pkt mpls layer for 5fb19164daeb5e665047f45d88890b0a succ.\033[0m\n");

	return ret;	
}

/* pcap file: for_gtest_only/inject/tcp_rst_with_vpls.pcap */
static int check_send_pkt_e4357ef2933e139bea72d0f77e6b0d96(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret = 0;
	struct layer_addr_mpls raw_mpls_layer_info = {};

	raw_mpls_layer_info.c2s_layer_num = 2;
	raw_mpls_layer_info.c2s_addr_array[0].label = htonl(18);
	raw_mpls_layer_info.c2s_addr_array[0].experimental = 0;
	raw_mpls_layer_info.c2s_addr_array[0].bottom = 0;
	raw_mpls_layer_info.c2s_addr_array[0].ttl = 254;

	raw_mpls_layer_info.c2s_addr_array[1].label = htonl(17);
	raw_mpls_layer_info.c2s_addr_array[1].experimental = 0;
	raw_mpls_layer_info.c2s_addr_array[1].bottom = 1;
	raw_mpls_layer_info.c2s_addr_array[1].ttl = 255;	

	raw_mpls_layer_info.c2s_has_ctrl_word = 1;
	raw_mpls_layer_info.c2s_mpls_ctrl_word = htonl(0x000000fe);
	
	raw_mpls_layer_info.s2c_layer_num = 2; 
	raw_mpls_layer_info.s2c_addr_array[0].label = htonl(19);
	raw_mpls_layer_info.s2c_addr_array[0].experimental = 0;
	raw_mpls_layer_info.s2c_addr_array[0].bottom = 0;
	raw_mpls_layer_info.s2c_addr_array[0].ttl = 254;

	raw_mpls_layer_info.s2c_addr_array[1].label = htonl(16);
	raw_mpls_layer_info.s2c_addr_array[1].experimental = 0;
	raw_mpls_layer_info.s2c_addr_array[1].bottom = 1;
	raw_mpls_layer_info.s2c_addr_array[1].ttl = 255;	

	raw_mpls_layer_info.s2c_has_ctrl_word = 1;
	raw_mpls_layer_info.s2c_mpls_ctrl_word = htonl(0x000000ff);

	ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_mpls_layer_info, 0);
	if(ret < 0){
		return -1;
	}

	printf("\033[32mcheck pkt mpls layer for e4357ef2933e139bea72d0f77e6b0d96 succ.\033[0m\n");

	return ret;
}

/* pcap file: tcp_rst_with_double_vlan.pcap */
static int check_send_pkt_d4c5e09bba97e72cbc6f04f64439a624(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret;
	struct layer_addr_vlan raw_pkt_vlan_info = {};
	const struct ethhdr *ehdr = (struct ethhdr *)tun_rcv_pkt;

	if(ntohs(ehdr->h_proto) != ETH_P_8021Q){
		printf("\033[1;31;40mcheck_send_pkt_d4c5e09bba97e72cbc6f04f64439a624() error: ethernet type is not 0x8100!\033[0m\n");
		return -1;
	}	

	raw_pkt_vlan_info.c2s_layer_num = 2;
	raw_pkt_vlan_info.c2s_addr_array[0].TPID = htons(0x8100); 
	raw_pkt_vlan_info.c2s_addr_array[0].PCP = 0; 
	raw_pkt_vlan_info.c2s_addr_array[0].DEI = 0;
	raw_pkt_vlan_info.c2s_addr_array[0].VID = htons(96);

	raw_pkt_vlan_info.c2s_addr_array[1].TPID = htons(0x0800);	
	raw_pkt_vlan_info.c2s_addr_array[1].PCP = 0; 
	raw_pkt_vlan_info.c2s_addr_array[1].DEI = 0;
	raw_pkt_vlan_info.c2s_addr_array[1].VID = htons(64); 


	raw_pkt_vlan_info.s2c_layer_num = 2;
	raw_pkt_vlan_info.s2c_addr_array[0].TPID = htons(0x8100);
	raw_pkt_vlan_info.s2c_addr_array[0].PCP = 0; 
	raw_pkt_vlan_info.s2c_addr_array[0].DEI = 0;
	raw_pkt_vlan_info.s2c_addr_array[0].VID = htons(80); 

	raw_pkt_vlan_info.s2c_addr_array[1].TPID = htons(0x0800);
	raw_pkt_vlan_info.s2c_addr_array[1].PCP = 0; 
	raw_pkt_vlan_info.s2c_addr_array[1].DEI = 0;
	raw_pkt_vlan_info.s2c_addr_array[1].VID = htons(32); 
	
	if(DIR_C2S == inject_paras->send_stream_dir){
		ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, 0);
		if(ret < 0){
			return -1;
		}
	}else{
		ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, 0);
		if(ret < 0){
			return -1;
		}
	}


	/* 为了避免解析vlan出错, 即vlan_addr_net_to_mem和vlan_addr_mem_to_net都错了, 但最终导致负负得正的效果, 竟然是对的!
	   此处直接验证一下发包的二进制 
	 */
	const char *tun_rcv_pkt_vlan_layer = (char *)tun_rcv_pkt + sizeof(struct ethhdr);  
	const unsigned char c2s_vlan_bin[8] = {0x00,0x60, 0x81, 0x00, 0x00,0x40, 0x08, 0x00};
	const unsigned char s2c_vlan_bin[8] = {0x00,0x50, 0x81, 0x00, 0x00,0x20, 0x08, 0x00};
	if(DIR_C2S == inject_paras->send_stream_dir){
		if(memcmp(tun_rcv_pkt_vlan_layer, c2s_vlan_bin, sizeof(c2s_vlan_bin)) != 0){
			return -1;
		}
	}else{
		if(memcmp(tun_rcv_pkt_vlan_layer, s2c_vlan_bin, sizeof(s2c_vlan_bin)) != 0){
			return -1;
		}
	}

	printf("\033[32mcheck pkt vlan layer for d4c5e09bba97e72cbc6f04f64439a624 succ.\033[0m\n");

	return ret;
}

/*
	数据包:tcp_rst_mpls_vlan_mpls_mxpe_s2c.pcap, md5: 29589eeca441438807e7606f7006e9e7, 包括内外两个不同层的MPLS和中间vlan层.
*/
static int check_send_pkt_29589eeca441438807e7606f7006e9e7(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret = 0;
	struct layer_addr_mpls raw_outer_mpls_layer_info = {};
	struct layer_addr_mpls raw_inner_mpls_layer_info = {};

	/* 外层mpls, S2C方向, 存储于dest */
	raw_outer_mpls_layer_info.s2c_layer_num = 2;
	
	raw_outer_mpls_layer_info.s2c_addr_array[0].label = htonl(779408);
	raw_outer_mpls_layer_info.s2c_addr_array[0].experimental = 0; 
	raw_outer_mpls_layer_info.s2c_addr_array[0].bottom = 0;
	raw_outer_mpls_layer_info.s2c_addr_array[0].ttl = 247;
	
	raw_outer_mpls_layer_info.s2c_addr_array[1].label = htonl(262455);
	raw_outer_mpls_layer_info.s2c_addr_array[1].experimental = 0; 
	raw_outer_mpls_layer_info.s2c_addr_array[1].bottom = 1;
	raw_outer_mpls_layer_info.s2c_addr_array[1].ttl = 249;

	raw_outer_mpls_layer_info.s2c_has_ctrl_word = 0;

	ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_outer_mpls_layer_info, DIR_S2C);
	if(ret < 0){
		return -1;
	}

	/* vlan */
	struct layer_addr_vlan raw_pkt_vlan_info;

	raw_pkt_vlan_info.s2c_layer_num = 2;
	raw_pkt_vlan_info.s2c_addr_array[0].TPID = htons(0x8100);
	raw_pkt_vlan_info.s2c_addr_array[0].PCP = 0; 
	raw_pkt_vlan_info.s2c_addr_array[0].DEI = 0;
	raw_pkt_vlan_info.s2c_addr_array[0].VID = htons(333); 

	raw_pkt_vlan_info.s2c_addr_array[1].TPID = htons(0x8847);
	raw_pkt_vlan_info.s2c_addr_array[1].PCP = 0; 
	raw_pkt_vlan_info.s2c_addr_array[1].DEI = 0;
	raw_pkt_vlan_info.s2c_addr_array[1].VID = htons(707); 	

	ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, DIR_S2C);
	if(ret < 0){
		return -1;
	}

	char *inner_eth_hdr = (char *)tun_rcv_pkt + sizeof(struct ethhdr) + 2 * sizeof(struct mesa_mpls_hdr);

	/* 内层mpls */
	raw_inner_mpls_layer_info.s2c_layer_num = 2;
	raw_inner_mpls_layer_info.s2c_addr_array[0].label = htonl(32915);
	raw_inner_mpls_layer_info.s2c_addr_array[0].experimental = 0; 
	raw_inner_mpls_layer_info.s2c_addr_array[0].bottom = 0;
	raw_inner_mpls_layer_info.s2c_addr_array[0].ttl = 254;
	
	raw_inner_mpls_layer_info.s2c_addr_array[1].label = htonl(32847);
	raw_inner_mpls_layer_info.s2c_addr_array[1].experimental = 0; 
	raw_inner_mpls_layer_info.s2c_addr_array[1].bottom = 1;
	raw_inner_mpls_layer_info.s2c_addr_array[1].ttl = 255;

	raw_inner_mpls_layer_info.s2c_has_ctrl_word = 0;

	ret = check_send_pkt_mpls_layer(pstream, inject_paras, inner_eth_hdr, raw_ip_pkt, &raw_inner_mpls_layer_info, DIR_S2C);
	if(ret < 0){
		return -1;
	}

	return ret;
}

/* pcap file: udp_mpls_vlan_mpls_mxpe_s2c.pcap */
static int check_send_pkt_502e5d3fbcce730493175a491c7102a6(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret = 0;
	struct layer_addr_mpls raw_outer_mpls_layer_info = {};
	struct layer_addr_mpls raw_inner_mpls_layer_info = {};

	/* 外层mpls, S2C方向, 存储于dest */
	raw_outer_mpls_layer_info.s2c_layer_num = 2;
	raw_outer_mpls_layer_info.s2c_addr_array[0].label = htonl(779408);
	raw_outer_mpls_layer_info.s2c_addr_array[0].experimental = 0; 
	raw_outer_mpls_layer_info.s2c_addr_array[0].bottom = 0;
	raw_outer_mpls_layer_info.s2c_addr_array[0].ttl = 247;
	
	raw_outer_mpls_layer_info.s2c_addr_array[1].label = htonl(262455);
	raw_outer_mpls_layer_info.s2c_addr_array[1].experimental = 0; 
	raw_outer_mpls_layer_info.s2c_addr_array[1].bottom = 1;
	raw_outer_mpls_layer_info.s2c_addr_array[1].ttl = 249;

	raw_outer_mpls_layer_info.s2c_has_ctrl_word = 0;

	ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_outer_mpls_layer_info, DIR_S2C);
	if(ret < 0){
		return -1;
	}

	/* vlan */
	struct layer_addr_vlan raw_pkt_vlan_info;

	raw_pkt_vlan_info.s2c_layer_num = 2;
	raw_pkt_vlan_info.s2c_addr_array[0].TPID =  htons(0x8100);
	raw_pkt_vlan_info.s2c_addr_array[0].PCP = 0; 
	raw_pkt_vlan_info.s2c_addr_array[0].DEI = 0;
	raw_pkt_vlan_info.s2c_addr_array[0].VID = htons(333);

	raw_pkt_vlan_info.s2c_addr_array[1].TPID = htons(0x8847);
	raw_pkt_vlan_info.s2c_addr_array[1].PCP = 0; 
	raw_pkt_vlan_info.s2c_addr_array[1].DEI = 0;
	raw_pkt_vlan_info.s2c_addr_array[1].VID = htons(707); 


	
	ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, DIR_S2C);
	if(ret < 0){
		return -1;
	}

	char *inner_eth_hdr = (char *)tun_rcv_pkt + sizeof(struct ethhdr) + 2 * sizeof(struct mesa_mpls_hdr);

	/* 内层mpls */
	raw_inner_mpls_layer_info.s2c_layer_num = 2;
	raw_inner_mpls_layer_info.s2c_addr_array[0].label = htonl(32915);
	raw_inner_mpls_layer_info.s2c_addr_array[0].experimental = 0; 
	raw_inner_mpls_layer_info.s2c_addr_array[0].bottom = 0;
	raw_inner_mpls_layer_info.s2c_addr_array[0].ttl = 254;
	
	raw_inner_mpls_layer_info.s2c_addr_array[1].label = htonl(32847);
	raw_inner_mpls_layer_info.s2c_addr_array[1].experimental = 0; 
	raw_inner_mpls_layer_info.s2c_addr_array[1].bottom = 1;
	raw_inner_mpls_layer_info.s2c_addr_array[1].ttl = 255;

	raw_inner_mpls_layer_info.s2c_has_ctrl_word = 0;

	ret = check_send_pkt_mpls_layer(pstream, inject_paras, inner_eth_hdr, raw_ip_pkt, &raw_inner_mpls_layer_info, DIR_S2C);
	if(ret < 0){
		return -1;
	}

	return ret;
}


/* pcap file: tcp_asymmetric_mpls_vlan_mpls_mxpe_double.pcap */
static int check_send_pkt_98755901f48760e6a5e23fd41b21dd91(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret = 0;
	struct layer_addr_mpls raw_outer_mpls_layer_info = {};
	struct layer_addr_mpls raw_inner_mpls_layer_info = {};
	/* 内层ethernet */
	struct layer_addr_mac raw_inner_eth_layer = {0};

	if(DIR_S2C == inject_paras->send_stream_dir){
		/* 外层mpls, S2C方向, 存储于dest */
		raw_outer_mpls_layer_info.s2c_layer_num = 2;
		raw_outer_mpls_layer_info.s2c_addr_array[0].label = htonl(779408);
		raw_outer_mpls_layer_info.s2c_addr_array[0].experimental = 0; 
		raw_outer_mpls_layer_info.s2c_addr_array[0].bottom = 0;
		raw_outer_mpls_layer_info.s2c_addr_array[0].ttl = 247;
		
		raw_outer_mpls_layer_info.s2c_addr_array[1].label = htonl(262455);
		raw_outer_mpls_layer_info.s2c_addr_array[1].experimental = 0; 
		raw_outer_mpls_layer_info.s2c_addr_array[1].bottom = 1;
		raw_outer_mpls_layer_info.s2c_addr_array[1].ttl = 249;

		raw_outer_mpls_layer_info.s2c_has_ctrl_word = 0;

		ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_outer_mpls_layer_info, DIR_S2C);
		if(ret < 0){
			return -1;
		}

		raw_inner_eth_layer.dst_addr.h_source[0] = 0x78;
		raw_inner_eth_layer.dst_addr.h_source[1] = 0x27;
		raw_inner_eth_layer.dst_addr.h_source[2] = 0x58;
		raw_inner_eth_layer.dst_addr.h_source[3] = 0x6f;
		raw_inner_eth_layer.dst_addr.h_source[4] = 0x9f;
		raw_inner_eth_layer.dst_addr.h_source[5] = 0x8d;

		raw_inner_eth_layer.dst_addr.h_dest[0] = 0x78;
		raw_inner_eth_layer.dst_addr.h_dest[1] = 0x27;
		raw_inner_eth_layer.dst_addr.h_dest[2] = 0x58;
		raw_inner_eth_layer.dst_addr.h_dest[3] = 0x59;
		raw_inner_eth_layer.dst_addr.h_dest[4] = 0x52;
		raw_inner_eth_layer.dst_addr.h_dest[5] = 0x97;

		ret = check_send_pkt_eth_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_inner_eth_layer, DIR_S2C);
		if(ret < 0){
			return -1;
		}		

		/* vlan */
		struct layer_addr_vlan raw_pkt_vlan_info = {};

		raw_pkt_vlan_info.s2c_layer_num = 2;
		raw_pkt_vlan_info.s2c_addr_array[0].TPID = htons(0x8100);
		raw_pkt_vlan_info.s2c_addr_array[0].PCP = 0; 
		raw_pkt_vlan_info.s2c_addr_array[0].DEI = 0;
		raw_pkt_vlan_info.s2c_addr_array[0].VID = htons(333); 

		raw_pkt_vlan_info.s2c_addr_array[1].TPID = htons(0x8847);
		raw_pkt_vlan_info.s2c_addr_array[1].PCP = 0; 
		raw_pkt_vlan_info.s2c_addr_array[1].DEI = 0;
		raw_pkt_vlan_info.s2c_addr_array[1].VID = htons(707); 
		
		ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, DIR_S2C);
		if(ret < 0){
			return -1;
		}

		char *inner_eth_hdr = (char *)tun_rcv_pkt + sizeof(struct ethhdr) + 2 * sizeof(struct mesa_mpls_hdr);

		/* 内层mpls */
		raw_inner_mpls_layer_info.s2c_layer_num = 2;
		raw_inner_mpls_layer_info.s2c_addr_array[0].label = htonl(32915);
		raw_inner_mpls_layer_info.s2c_addr_array[0].experimental = 0; 
		raw_inner_mpls_layer_info.s2c_addr_array[0].bottom = 0;
		raw_inner_mpls_layer_info.s2c_addr_array[0].ttl = 254;
		
		raw_inner_mpls_layer_info.s2c_addr_array[1].label = htonl(32847);
		raw_inner_mpls_layer_info.s2c_addr_array[1].experimental = 0; 
		raw_inner_mpls_layer_info.s2c_addr_array[1].bottom = 1;
		raw_inner_mpls_layer_info.s2c_addr_array[1].ttl = 255;

		raw_inner_mpls_layer_info.s2c_has_ctrl_word = 0;

		/* 内层mpls从inner_eth_hdr开始 */
		ret = check_send_pkt_mpls_layer(pstream, inject_paras, inner_eth_hdr, raw_ip_pkt, &raw_inner_mpls_layer_info, DIR_S2C);
		if(ret < 0){
			return -1;
		}
	}else{ ////////////////   DIR_C2S
		/* 外层mpls, C2S方向, 存储于src */
		raw_outer_mpls_layer_info.c2s_layer_num = 1;
		raw_outer_mpls_layer_info.c2s_addr_array[0].label = htonl(266551);
		raw_outer_mpls_layer_info.c2s_addr_array[0].experimental = 0; 
		raw_outer_mpls_layer_info.c2s_addr_array[0].bottom = 1;
		raw_outer_mpls_layer_info.c2s_addr_array[0].ttl = 240;

		raw_outer_mpls_layer_info.c2s_has_ctrl_word = 0;

		/* 外层mpls */
		ret = check_send_pkt_mpls_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_outer_mpls_layer_info, DIR_C2S);
		if(ret < 0){
			return -1;
		}

		raw_inner_eth_layer.src_addr.h_source[0] = 0x78;
		raw_inner_eth_layer.src_addr.h_source[1] = 0x11;
		raw_inner_eth_layer.src_addr.h_source[2] = 0xdc;
		raw_inner_eth_layer.src_addr.h_source[3] = 0x56;
		raw_inner_eth_layer.src_addr.h_source[4] = 0x78;
		raw_inner_eth_layer.src_addr.h_source[5] = 0x90;

		raw_inner_eth_layer.src_addr.h_dest[0] = 0x78;
		raw_inner_eth_layer.src_addr.h_dest[1] = 0x11;
		raw_inner_eth_layer.src_addr.h_dest[2] = 0xdc;
		raw_inner_eth_layer.src_addr.h_dest[3] = 0x44;
		raw_inner_eth_layer.src_addr.h_dest[4] = 0x55;
		raw_inner_eth_layer.src_addr.h_dest[5] = 0x66;

		ret = check_send_pkt_eth_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_inner_eth_layer, DIR_C2S);
		if(ret < 0){
			return -1;
		}		
		
		/* vlan */
		struct layer_addr_vlan raw_pkt_vlan_info = {};
		
		raw_pkt_vlan_info.c2s_layer_num = 2;
		raw_pkt_vlan_info.c2s_addr_array[0].TPID = htons(0x8100);
		raw_pkt_vlan_info.c2s_addr_array[0].PCP = 0; 
		raw_pkt_vlan_info.c2s_addr_array[0].DEI = 0;
		raw_pkt_vlan_info.c2s_addr_array[0].VID = htons(333); 

		raw_pkt_vlan_info.c2s_addr_array[1].TPID = htons(0x8847);
		raw_pkt_vlan_info.c2s_addr_array[1].PCP = 0; 
		raw_pkt_vlan_info.c2s_addr_array[1].DEI = 0;
		raw_pkt_vlan_info.c2s_addr_array[1].VID = htons(707); 
		
		ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, DIR_C2S);
		if(ret < 0){
			return -1;
		}
		
		char *inner_eth_hdr = (char *)tun_rcv_pkt + sizeof(struct ethhdr) + 2 * sizeof(struct mesa_mpls_hdr);
		
		/* 内层mpls */
		raw_inner_mpls_layer_info.c2s_layer_num = 1;
		raw_inner_mpls_layer_info.c2s_addr_array[0].label = htonl(163919);
		raw_inner_mpls_layer_info.c2s_addr_array[0].experimental = 0; 
		raw_inner_mpls_layer_info.c2s_addr_array[0].bottom = 1;
		raw_inner_mpls_layer_info.c2s_addr_array[0].ttl = 240;
		raw_inner_mpls_layer_info.c2s_has_ctrl_word = 0;
		
		ret = check_send_pkt_mpls_layer(pstream, inject_paras, inner_eth_hdr, raw_ip_pkt, &raw_inner_mpls_layer_info, DIR_C2S);
		if(ret < 0){
			return -1;
		}
	}

	printf("check_send_pkt_b827ce6ed04f0cbc76e17bd607f8edd4() succ, send_dir:%d\n", inject_paras->send_stream_dir);

	return ret;
}

/*
	pcap file: for_gtest_only/vlan/QinQ_with_http.pcap
*/
static int check_send_pkt_76b4545432085c74817411bb1ecf450f(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	int ret;
	struct layer_addr_vlan raw_pkt_vlan_info = {};
	const struct ethhdr *ehdr = (struct ethhdr *)tun_rcv_pkt;

	if(ntohs(ehdr->h_proto) != ETH_P_8021AD){
		printf("\033[1;31;40mcheck_send_pkt_76b4545432085c74817411bb1ecf450f() error: ethernet type is not 0x88A8!\033[0m\n");
		return -1;
	}

	raw_pkt_vlan_info.c2s_layer_num = 2;
	raw_pkt_vlan_info.c2s_addr_array[0].TPID = htons(0x8100); 
	raw_pkt_vlan_info.c2s_addr_array[0].PCP = 0; 
	raw_pkt_vlan_info.c2s_addr_array[0].DEI = 0;
	raw_pkt_vlan_info.c2s_addr_array[0].VID = htons(1); 

	raw_pkt_vlan_info.c2s_addr_array[1].TPID = htons(0x0800); 
	raw_pkt_vlan_info.c2s_addr_array[1].PCP = 0; 
	raw_pkt_vlan_info.c2s_addr_array[1].DEI = 0;
	raw_pkt_vlan_info.c2s_addr_array[1].VID = htons(1); 

	if(DIR_C2S == inject_paras->send_stream_dir){
		ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, 0);
		if(ret < 0){
			return -1;
		}
	}else{
		ret = check_send_pkt_vlan_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt, &raw_pkt_vlan_info, 0);
		if(ret < 0){
			return -1;
		}
	}

	printf("\033[32mcheck pkt vlan layer for 76b4545432085c74817411bb1ecf450f succ.\033[0m\n");

	return ret;
}


static int check_send_pkt_6be85f33b5eba93fd184bcecf27e41ae(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	const struct ethhdr *ehdr = (struct ethhdr *)tun_rcv_pkt;

	if(ntohs(ehdr->h_proto) != ETH_P_IP){
		printf("\033[1;31;40mcheck_send_pkt_6be85f33b5eba93fd184bcecf27e41ae() error: ethernet type expect 0x0800, but raw pkt is 0x%x!\033[0m\n", ntohs(ehdr->h_proto));
		return -1;
	}

	printf("\033[32mcheck pkt vlan layer for 6be85f33b5eba93fd184bcecf27e41ae succ.\033[0m\n");

	return 0;
}


/* 
	 pcap file: for_gtest_only/gtp/gtp_double.pcap
	 用于检测GTP包注入的正确性.
*/
static int check_send_pkt_0b1d409dcc3987f55465c4c989da1651(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	const struct gtp_hdr *inject_gtp_hdr;

#if USE_TUN_TYPE_FOR_SEND_DEVICE	
	inject_gtp_hdr = (struct gtp_hdr *)MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_IPV4, ADDR_TYPE_GPRS_TUNNEL);
#else
	inject_gtp_hdr = (struct gtp_hdr *)MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_MAC, ADDR_TYPE_GPRS_TUNNEL);
#endif

	if(NULL == inject_gtp_hdr){
		printf("\033[1;31;40mcheck_send_pkt_0b1d409dcc3987f55465c4c989da1651() error: not jump to gtp layer!\033[0m\n");
		return -1;
	}

	if(inject_gtp_hdr->flags != 0x30){
		printf("\033[1;31;40mcheck_send_pkt_0b1d409dcc3987f55465c4c989da1651() error: gtp hdr flags is not 0x30!\033[0m\n");
		return -1;		
	}
	if(inject_gtp_hdr->msg_type != 0xFF){
		printf("\033[1;31;40mcheck_send_pkt_0b1d409dcc3987f55465c4c989da1651() error: gtp hdr msg type is not 0xFF!\033[0m\n");
		return -1;		
	}	

	if(ntohs(inject_gtp_hdr->len) != 40){ /* rst包, 没有负载 */
		printf("\033[1;31;40mcheck_send_pkt_0b1d409dcc3987f55465c4c989da1651() error: gtp hdr len is not 40!\033[0m\n");
		return -1;		
	}	
	
	if(DIR_C2S == inject_paras->rst_para.dir){
		if(ntohl(inject_gtp_hdr->teid) != 0x1f54d4b5){
			printf("\033[1;31;40mcheck_send_pkt_0b1d409dcc3987f55465c4c989da1651() error: inject C2S gtp hdr teid is not 0x1f54d4b5!\033[0m\n");
			return -1;		
		}			
	}else{
		if(ntohl(inject_gtp_hdr->teid) != 0x0000981b){
			printf("\033[1;31;40mcheck_send_pkt_0b1d409dcc3987f55465c4c989da1651() error: inject S2C gtp hdr teid is not 0x0000981b!\033[0m\n");
			return -1;		
		}	
	}

	printf("\033[32mcheck pkt GTP layer for 0b1d409dcc3987f55465c4c989da1651 succ.\033[0m\n");

	return 0;
}


static int check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	const struct l2tp_hdr_v2 *inject_l2tp_hdr;
	const unsigned short *ptr;

#if USE_TUN_TYPE_FOR_SEND_DEVICE	
	inject_l2tp_hdr = (struct l2tp_hdr_v2 *)MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_IPV4, ADDR_TYPE_L2TP);
#else
	inject_l2tp_hdr = (struct l2tp_hdr_v2 *)MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_MAC, ADDR_TYPE_L2TP);
#endif

	if(NULL == inject_l2tp_hdr){
		printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: not jump to l2tp layer!\033[0m\n");
		return -1;
	}

	if(inject_l2tp_hdr->version != 2){
		printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: l2tp hdr version is not 2!\033[0m\n");
		return -1;
	}

	if(inject_l2tp_hdr->type != 0){
		printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: l2tp hdr type is not 0!\033[0m\n");
		return -1;
	}	

	/* for_gtest_only/inject/tcp_rst_with_l2tp.pcap 的length_present标志位是从SYN包获取的, 以后也没有更新, 并不是触发inject动作的GET包的标志 */
	if(inject_l2tp_hdr->length_present != 1){
		printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: l2tp hdr length_present is not 1!\033[0m\n");
		return -1;
	}	

	ptr = (unsigned short *)((char *)inject_l2tp_hdr + sizeof(struct l2tp_hdr_v2));  /* to length field */	
	if(ntohs(*ptr) != 52){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: l2tp hdr length id is not 52, actual is:%d!\033[0m\n", ntohs(*ptr) );
		return -1;		
	}		

	ptr++;  /* to tunnel id */	
	if(DIR_C2S == inject_paras->rst_para.dir){
		if(ntohs(*ptr) != 28998){
			printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: C2S l2tp hdr tunnel id is not 28998!\033[0m\n");
			return -1;		
		}
	}else{
		if(ntohs(*ptr) != 1){
			printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: S2C l2tp hdr tunnel id is not 1!\033[0m\n");
			return -1;		
		}
	}

	ptr++; /* to session id */	
	if(DIR_C2S == inject_paras->rst_para.dir){
		if(ntohs(*ptr) != 2){
			printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: C2S l2tp hdr session id is not 2!\033[0m\n");
			return -1;		
		}
	}else{
		if(ntohs(*ptr) != 1){
			printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: S2C l2tp hdr session id is not 1!\033[0m\n");
			return -1;		
		}
	}

	ptr++; /* to ppp header */
	const struct mesa_ppp_hdr *inject_ppp_hdr = ( struct mesa_ppp_hdr *)ptr;
	if(inject_ppp_hdr->address != 0xFF){
		printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: ppp hdr address is not 0xFF!\033[0m\n");
		return -1;	
	}
	if(inject_ppp_hdr->control != 0x03){
		printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: ppp hdr control is not 0x03!\033[0m\n");
		return -1;	
	}
	if(ntohs(inject_ppp_hdr->protocol) != 0x0021){
		printf("\033[1;31;40m check_send_pkt_6aa039f5c2be11ae72ec78346e50ab94() error: ppp hdr protocol is not 0x0021!\033[0m\n");
		return -1;	
	}	

	printf("\033[32mcheck pkt L2TP layer for 6aa039f5c2be11ae72ec78346e50ab94 succ.\033[0m\n");

	return 0;
}

static int check_send_pkt_62cbdf729199bcca78de9b4944da5256(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	const struct l2tp_hdr_v2 *inject_l2tp_hdr;
	const unsigned short *ptr;

#if USE_TUN_TYPE_FOR_SEND_DEVICE	
	inject_l2tp_hdr = (struct l2tp_hdr_v2 *)MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_IPV4, ADDR_TYPE_L2TP);
#else
	inject_l2tp_hdr = (struct l2tp_hdr_v2 *)MESA_net_jump_to_layer(tun_rcv_pkt, ADDR_TYPE_MAC, ADDR_TYPE_L2TP);
#endif

	if(NULL == inject_l2tp_hdr){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: not jump to l2tp layer!\033[0m\n");
		return -1;
	}

	if(inject_l2tp_hdr->version != 2){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: l2tp hdr version is not 2!\033[0m\n");
		return -1;
	}

	if(inject_l2tp_hdr->type != 0){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: l2tp hdr type is not 0!\033[0m\n");
		return -1;
	}	

	if(inject_l2tp_hdr->length_present != 1){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: l2tp hdr length_present is not 1!\033[0m\n");
		return -1;
	}	

	ptr = (unsigned short *)((char *)inject_l2tp_hdr + sizeof(struct l2tp_hdr_v2));  /* to length field */	
	if(ntohs(*ptr) != 85){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: C2S l2tp hdr length id is not 1387!\033[0m\n");
		return -1;		
	}	

	ptr++;  /* to tunnel id */	
	if(DIR_C2S == inject_paras->send_stream_dir){
		if(ntohs(*ptr) != 4788){
			printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: C2S l2tp hdr tunnel id is not 4788!\033[0m\n");
			return -1;		
		}
	}else{
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: only support inject C2S pkt!\033[0m\n");
		return -1;		
	}

	ptr++; /* to session id */	
	if(DIR_C2S == inject_paras->send_stream_dir){
		if(ntohs(*ptr) != 51302){
			printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: C2S l2tp hdr session id is not 51302!\033[0m\n");
			return -1;		
		}
	}else{
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: only support inject C2S pkt!\033[0m\n");
		return -1;	
	}

	ptr++; /* to ppp header */
#if 0	
	const struct mesa_ppp_hdr *inject_ppp_hdr = ( struct mesa_ppp_hdr *)ptr;
	if(inject_ppp_hdr->address != 0xFF){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: ppp hdr address is not 0xFF!\033[0m\n");
		return -1;	
	}
	if(inject_ppp_hdr->control != 0x03){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: ppp hdr control is not 0x03!\033[0m\n");
		return -1;	
	}
#endif
	if(*(unsigned char *)ptr != 0x21){
		printf("\033[1;31;40m check_send_pkt_62cbdf729199bcca78de9b4944da5256() error: ppp hdr protocol is not 0x21!\033[0m\n");
		return -1;	
	}	

	printf("\033[32m check_send_pkt_62cbdf729199bcca78de9b4944da5256 succ.\033[0m\n");

	return 0;
}



/*
	除了检查最内层的四元组是否正确, 还要检查底层L2-L3层隧道填充的是否正确,
	sapp通过set_pcap_dumpfile()函数, 事先肯定知道本次测试用例读的是什么格式的pcap包, 
	但是插件不知道当前读的是什么pcap包, 怎么把这个信息传递给插件呢??
      1)靠MESA_get_stream_opt()获取隧道类型?  某些层如vlan, mpls是不算做tunnel的, 而且隧道里的地址值也没法传递, 不太精确.
      2)插件也读取当前dumpfile的md5值, 这些pcap包是根据测试用例精确构造的, md5值是唯一的, 数据包地址信息不会变.

    所以采用第2种方式.
*/
static int check_send_pkt_l2_l3_layer(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	char file_md5sum[33];
	int i, ret = 0;
	int (*check_fun)(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt);
	
	ret = get_file_md5sum("dumpfile", file_md5sum, sizeof(file_md5sum));
	if(ret < 0){
		return -1;
	}

	check_fun = NULL;
	
	for(i = 0; g_inject_check_l2_l3_layer_fun[i].pcap_file_md5sum != NULL; i++){
		if(strncasecmp(g_inject_check_l2_l3_layer_fun[i].pcap_file_md5sum, file_md5sum, 32) == 0){
			check_fun = g_inject_check_l2_l3_layer_fun[i].check_fun;
			break;
		}
	}

	if(check_fun){
		ret = check_fun(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt);
	}else{
		; //no found l2 l3 check fun, maybe hasn't l2 -l3 tunnel layer, go on!
	}

	return ret;
}

static void tun_dev_close(int tun_fd)
{
    if(tun_fd > 0){
        close(tun_fd);
    }
}

int tun_alloc(char *dev, int flags)
{
    assert(dev != NULL);

    struct ifreq ifr;
    int fd, err;

    const char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
		printf("open device tun %s error, %s\n", clonedev, strerror(errno));	
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

    if (*dev != '\0') {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    	printf("ioctl device tun TUNSETIFF %s error, %s\n", clonedev, strerror(errno));
        close(fd);
        return err;
    }

    // 一旦设备开启成功，系统会给设备分配一个名称，对于tun设备，一般为tunX，X为从0开始的编号；
    // 对于tap设备，一般为tapX
    strcpy(dev, ifr.ifr_name);

    return fd;
}


static int tun_dev_create(char *tun_name)
{
	int tun_fd;

	/* 
		TUN设备从IP头部开始, 仅支持IPv4;
		TAP设备从MAC头开始, 支持IPv4和IPv6.
		IFF_NO_PI: Do not provide packet information.
	*/
#if USE_TUN_TYPE_FOR_SEND_DEVICE	
	tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
#else	
	tun_fd = tun_alloc(tun_name, IFF_TAP | IFF_NO_PI);
#endif

	if(tun_fd < 0){
		return -1;
	}

	return tun_fd;
}




/*
	0: is not rst packet, tun设备可能会收到其他报文;
	1: is rst packet, and it's paras is expected.
	-1: is rst packet, and it's paras is not expected.
*/

static int compare_rst_pkt_para_ipv4(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, struct ip *tun_rcv_ip_pkt, struct ip *raw_ip_pkt)
{	
	unsigned short raw_ip_chksum = tun_rcv_ip_pkt->ip_sum;
	char ip_str1[INET_ADDRSTRLEN], ip_str2[INET_ADDRSTRLEN];
	
	/* 注入数据包, 一定要重新计算校验和并检查, 否则注入到链路也过不了网络设备 */
	sendpacket_do_checksum((unsigned char *)tun_rcv_ip_pkt, IPPROTO_IP, sizeof(struct ip));
	if(raw_ip_chksum != tun_rcv_ip_pkt->ip_sum){
		printf("\033[1;31;40mrst packet ip header checksum error!\033[0m\n");
		return -1;
	}

	if(pstream->curdir & inject_paras->send_stream_dir){
		if(tun_rcv_ip_pkt->ip_src.s_addr != raw_ip_pkt->ip_src.s_addr){
			inet_ntop(AF_INET, &raw_ip_pkt->ip_src, ip_str1, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &tun_rcv_ip_pkt->ip_src, ip_str2, INET_ADDRSTRLEN);
			printf("\033[1;31;40mcompare_rst_pkt_para_ipv4():inject packet dir:%d ip header src addr not match, raw:%s, inject:%s!\033[0m\n", inject_paras->send_stream_dir, ip_str1, ip_str2);
			return -1;
		}
		if(tun_rcv_ip_pkt->ip_dst.s_addr != raw_ip_pkt->ip_dst.s_addr){
			inet_ntop(AF_INET, &raw_ip_pkt->ip_dst, ip_str1, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &tun_rcv_ip_pkt->ip_dst, ip_str2, INET_ADDRSTRLEN);		
			printf("\033[1;31;40mcompare_rst_pkt_para_ipv4():inject packet dir:%d ip header dst addr not match, raw:%s, inject:%s!\033[0m\n", inject_paras->send_stream_dir, ip_str1, ip_str2);
			return -1;
		}
	}else{
		if(tun_rcv_ip_pkt->ip_src.s_addr != raw_ip_pkt->ip_dst.s_addr){
			inet_ntop(AF_INET, &raw_ip_pkt->ip_dst, ip_str1, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &tun_rcv_ip_pkt->ip_src, ip_str2, INET_ADDRSTRLEN);			
			printf("\033[1;31;40mcompare_rst_pkt_para_ipv4():inject packet dir:%d ip header src addr not match! raw:%s, inject:%s\033[0m\n", inject_paras->send_stream_dir,ip_str1, ip_str2);
			return -1;
		}
		if(tun_rcv_ip_pkt->ip_dst.s_addr != raw_ip_pkt->ip_src.s_addr){
			inet_ntop(AF_INET, &raw_ip_pkt->ip_src, ip_str1, INET_ADDRSTRLEN);
			inet_ntop(AF_INET, &tun_rcv_ip_pkt->ip_dst, ip_str2, INET_ADDRSTRLEN);				
			printf("\033[1;31;40mcompare_rst_pkt_para_ipv4():inject packet dir:%d ip header dst addr not match! raw:%s, inject:%s\033[0m\n", inject_paras->send_stream_dir,ip_str1, ip_str2);
			return -1;
		}	
	}

	return tun_rcv_ip_pkt->ip_hl * 4;
}


/*
	0: is not rst packet, tun设备可能会收到其他报文;
	1: is rst packet, and it's paras is expected.
	-1: is rst packet, and it's paras is not expected.
*/

static int compare_rst_pkt_para_ipv6(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, struct ip6_hdr *tun_rcv_ip_pkt, struct ip6_hdr *raw_ip_pkt)
{
	if(tun_rcv_ip_pkt->ip6_nxt != 6){
		return 0;
	}

	//TODO

	return sizeof(struct ip6_hdr);
}


static int compare_rst_pkt_para_tcp_layer(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, const struct tcphdr *tun_rst_tcp_h, const struct tcphdr *raw_pkt_tcp_h)
{
	/********* tcp layer check **********/
	

	if(0x14 == inject_paras->rst_para.th_flags){
		if(!((tun_rst_tcp_h->rst == 1) && (tun_rst_tcp_h->ack == 1))){
			return -1;
		}
	}else if(0x4 == inject_paras->rst_para.th_flags){
		if(!((tun_rst_tcp_h->rst == 1) && (tun_rst_tcp_h->ack == 0))){
			return -1;
		}
	}
	
	if(pstream->curdir & inject_paras->send_stream_dir){
		if(tun_rst_tcp_h->source != raw_pkt_tcp_h->source){
			printf("\033[1;31;40mcompare_rst_pkt_para_tcp_layer():rst packet tcp header sport not match!\033[0m\n");
			return -1;
		}
		if(tun_rst_tcp_h->dest != raw_pkt_tcp_h->dest){
			printf("\033[1;31;40mcompare_rst_pkt_para_tcp_layer():rst packet tcp header dport not match!\033[0m\n");
			return -1;
		}		
	}else{
		if(tun_rst_tcp_h->source != raw_pkt_tcp_h->dest){
			printf("\033[1;31;40mcompare_rst_pkt_para_tcp_layer():rst packet tcp header sport not match!\033[0m\n");
			return -1;
		}
		if(tun_rst_tcp_h->dest != raw_pkt_tcp_h->source){
			printf("\033[1;31;40mcompare_rst_pkt_para_tcp_layer():rst packet tcp header dport not match!\033[0m\n");
			return -1;
		}	
	}

	return 1;
}


/*
  inject_paras  : 发送rst包的参数.
  tun_rcv_pkt: 从tun/tap网卡收到的sapp发出的数据包,根据 USE_TUN_TYPE_FOR_SEND_DEVICE 模式不同,可能是IP开始,可能是MAC开始;
  raw_ip_pkt : 插件entry收到的当前包.

  return value:
	0: is not rst packet, tun设备可能会收到其他报文;
	1: is rst packet, and it's paras is expected.
	-1: is rst packet, and it's paras is not expected.
*/
static int check_rst_pkt_para(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *tun_rcv_pkt, void *raw_ip_pkt)
{
	struct tcphdr *tun_rst_tcp_h, *raw_pkt_tcp_h;
	int ip_hdr_len, ret;
	const void *tun_rcv_ip_pkt;

	if(check_send_pkt_l2_l3_layer(pstream, inject_paras, tun_rcv_pkt, raw_ip_pkt) < 0){
		return -1;
	}

	/*
		TODO:
		增加中间隧道协议的比较, 比如GRE, GTP, PPTP, L2TP等.
	*/

#if USE_TUN_TYPE_FOR_SEND_DEVICE /* tun from ip layer */	
	tun_rcv_ip_pkt = tun_rcv_pkt;
#else
	/* 此处用greedy偏移到最内层ip地址, 因为是和plug entry 的a_packet比较 */
	tun_rcv_ip_pkt = MESA_net_jump_to_layer_greedy(tun_rcv_pkt, ADDR_TYPE_MAC, pstream->addr.addrtype);
	if(NULL == tun_rcv_ip_pkt){
		printf("\033[1;31;40mcheck_rst_pkt_para() error, can't jump to ip header!\033[0m\n");
		return -1;
	}
#endif

	/********* ip layer check **********/
	if(ADDR_TYPE_IPV4 == pstream->addr.addrtype){
		ip_hdr_len = compare_rst_pkt_para_ipv4(pstream, inject_paras, (struct ip *)tun_rcv_ip_pkt, (struct ip *)raw_ip_pkt);
	}else{
		ip_hdr_len = compare_rst_pkt_para_ipv6(pstream, inject_paras, (struct ip6_hdr *)tun_rcv_ip_pkt, (struct ip6_hdr *)raw_ip_pkt);
	}
	if(ip_hdr_len <= 0){
		return ip_hdr_len;
	}

	/******* TCP校验和检查, 发送的RST包必须保证校验和正确, 否则对端协议栈不收 *******/
	raw_pkt_tcp_h = (struct tcphdr *)((char *)raw_ip_pkt + ip_hdr_len);
	tun_rst_tcp_h = (struct tcphdr *)((char *)tun_rcv_ip_pkt + ip_hdr_len);

	unsigned short raw_tcp_chksum = tun_rst_tcp_h->check;
	sendpacket_do_checksum((unsigned char *)tun_rcv_ip_pkt, IPPROTO_TCP, sizeof(struct tcphdr));
	if(raw_tcp_chksum != tun_rst_tcp_h->check){
		printf("\033[1;31;40mrst packet tcp header checksum error!\033[0m\n");
		return -1;
	}

	ret = compare_rst_pkt_para_tcp_layer(pstream, inject_paras, tun_rst_tcp_h, raw_pkt_tcp_h);
	if(ret < 0){
		return ret;
	}

	return ret;
}

#if USE_TUN_TYPE_FOR_SEND_DEVICE /* tun from ip layer */
static int identify_is_tcp_rst_pkt(char *a_packet)
{
	const unsigned char *iphdr = (char *)a_packet;
	struct ip *ip4hdr;
	struct ip6_hdr *ip6hdr;
	struct tcphdr *tcp_h;

	if(0x60 == (iphdr[0] & 0xF0)){
		ip6hdr = (struct ip6_hdr *)(iphdr);
		if(ip6hdr->ip6_nxt != IPPROTO_TCP){
			return -1;
		}
		
		tcp_h = (struct tcphdr *)((char *)ip6hdr + sizeof(struct ip6_hdr));
	}else if(0x40 == (iphdr[0] & 0xF0)){
		ip4hdr = (struct ip *)(iphdr);
		if(ip4hdr->ip_p != IPPROTO_TCP){
			return -1;
		}
		
		tcp_h = (struct tcphdr *)((char *)ip4hdr + ip4hdr->ip_hl * 4);
	}else{
		return -1;
	}

	if(tcp_h->rst != 1){
		return -1;
	}

	return 1;
}
#else /* tap from ethernet layer */
static int identify_is_tcp_rst_pkt(char *a_packet)
{
	const unsigned char *iphdr;
	struct ip *ip4hdr;
	struct ip6_hdr *ip6hdr;
	struct tcphdr *tcp_h;

	iphdr = (unsigned char *)MESA_net_jump_to_layer(a_packet, ADDR_TYPE_MAC, ADDR_TYPE_IPV4);
	if(NULL == iphdr){
		iphdr = (unsigned char *)MESA_net_jump_to_layer(a_packet, ADDR_TYPE_MAC, ADDR_TYPE_IPV6);
		if(NULL == iphdr){
			printf("\033[1;31;40midentify_is_tcp_rst_pkt() error, can't jump to ip header!\033[0m\n");
			return -1;
		}
	}

	if(0x60 == (iphdr[0] & 0xF0)){
		ip6hdr = (struct ip6_hdr *)iphdr;
		if(ip6hdr->ip6_nxt != IPPROTO_TCP){
			return -1;
		}
		
		tcp_h = (struct tcphdr *)((char *)ip6hdr + sizeof(struct ip6_hdr));
	}else if(0x40 == (iphdr[0] & 0xF0)){
		ip4hdr = (struct ip *)iphdr;
		if(ip4hdr->ip_p != IPPROTO_TCP){
			return -1;
		}
		
		tcp_h = (struct tcphdr *)((char *)ip4hdr + ip4hdr->ip_hl * 4);
	}else{
		return -1;
	}

	if(tcp_h->rst != 1){
		return -1;
	}

	return 1;
}
#endif

/*
	因为注入模式不一样, 计算payload len方式不同.
	SIO_DEFAULT 只是纯负载, 而SIO_EXCLUDE_THIS_LAYER_HDR包括了当前层的完整IP头部和传输层头部.
*/
static int get_actual_inject_payload_len(struct streaminfo *pstream, struct inject_pkt_para *inject_paras)
{
	int actual_payload_len;
	int iphdr_len;
	int transparent_hdr_len;

	if(ADDR_TYPE_IPV4 == pstream->addr.addrtype){
		iphdr_len = sizeof(struct ip);
	}else{
		iphdr_len = sizeof(struct ip6_hdr);
	}

	if(STREAM_TYPE_TCP == pstream->type){
		transparent_hdr_len = sizeof(struct tcphdr);
	}else{
		transparent_hdr_len = sizeof(struct udphdr);
	}
	

	if(SIO_DEFAULT == inject_paras->inject_opt){
		actual_payload_len = inject_paras->payload_len;
	}else{
		actual_payload_len = inject_paras->payload_len - iphdr_len - transparent_hdr_len;
	}

	/* 计算校验和时要加上传输层头部长度, 只减去ip头部长度 */

	return actual_payload_len;
}

/*
	因为注入模式不一样, 计算payload 起始位置方式不同.
	SIO_DEFAULT 只是纯负载, 而SIO_EXCLUDE_THIS_LAYER_HDR包括了当前层的完整IP头部和传输层头部.
*/
static void *get_actual_inject_payload_hdr(struct streaminfo *pstream, struct inject_pkt_para *inject_paras)
{
	char *actual_payload_hdr;
	int iphdr_len;
	int transparent_hdr_len;

	if(ADDR_TYPE_IPV4 == pstream->addr.addrtype){
		iphdr_len = sizeof(struct ip);
	}else{
		iphdr_len = sizeof(struct ip6_hdr);
	}

	if(STREAM_TYPE_TCP == pstream->type){
		transparent_hdr_len = sizeof(struct tcphdr);
	}else{
		transparent_hdr_len = sizeof(struct udphdr);
	}

	if(SIO_DEFAULT == inject_paras->inject_opt){
		actual_payload_hdr = (char *)inject_paras->payload;
	}else{
		actual_payload_hdr = (char *)inject_paras->payload + iphdr_len + transparent_hdr_len;
	}

	/* 计算校验和时要加上传输层头部长度, 只减去ip头部长度 */

	return actual_payload_hdr;
}



static int check_inject_pkt_payload(struct streaminfo *pstream,void *inject_pkt_from_tap, struct inject_pkt_para *inject_paras)
{
	const void *inject_pkt_iphdr;
	int ip_hdr_len, transport_hdr_len;
	const char *inject_payload;

	const char *actual_payload;
	int actual_payload_len;

	inject_pkt_iphdr = MESA_net_jump_to_layer_greedy(inject_pkt_from_tap, ADDR_TYPE_MAC, pstream->addr.addrtype);
	if(NULL == inject_pkt_iphdr){
		printf("\033[1;31;40mcheck_inject_pkt_payload() error, can't jump to ip header!\033[0m\n");
		return -1;
	}

	/********* ip layer check **********/
	if(ADDR_TYPE_IPV4 == pstream->addr.addrtype){
		ip_hdr_len = ((struct ip *)inject_pkt_iphdr)->ip_hl * 4;
	}else{
		ip_hdr_len = sizeof(struct ip6_hdr);
	}

	if(STREAM_TYPE_TCP == pstream->type){
		struct tcphdr *thdr = (struct tcphdr *)((char *)inject_pkt_iphdr + ip_hdr_len);
		transport_hdr_len = thdr->doff * 4;
	}else{
		transport_hdr_len = sizeof(struct udphdr);
	}

	inject_payload = (char *)inject_pkt_iphdr + ip_hdr_len + transport_hdr_len;
	actual_payload = (char *)get_actual_inject_payload_hdr(pstream, inject_paras);
	actual_payload_len = get_actual_inject_payload_len(pstream, inject_paras);
	
	if(memcmp(inject_payload, actual_payload, actual_payload_len) != 0){
		printf("\033[1;31;40mcheck_inject_pkt_payload() error, payload is diff!\033[0m\n");
		return -1;
	}

	return 0;
}



static int check_inject_pkt(struct streaminfo *pstream, void *inject_pkt_from_tap, void *raw_ip_pkt, struct inject_pkt_para *inject_paras)
{
	struct tcphdr *tun_rst_tcp_h, *raw_pkt_tcp_h;
	struct udphdr *tun_udp_h;
	int ip_hdr_len, ret = 0;
	const void *tun_rcv_ip_pkt;
	unsigned char ip_protocol;
	int actual_payload_len;

	if(check_send_pkt_l2_l3_layer(pstream, inject_paras, inject_pkt_from_tap, raw_ip_pkt) < 0){
		return -1;
	}

#if USE_TUN_TYPE_FOR_SEND_DEVICE /* tun from ip layer */	
	tun_rcv_ip_pkt = inject_pkt_from_tap;
#else
	/* 此处用greedy偏移到最内层ip地址, 因为是和plug entry 的a_packet比较, 直接用pstream->addr.addrtype, 方便同时兼顾ipv4,ipv6 */
	tun_rcv_ip_pkt = MESA_net_jump_to_layer_greedy(inject_pkt_from_tap, ADDR_TYPE_MAC, pstream->addr.addrtype);
	if(NULL == tun_rcv_ip_pkt){
		printf("\033[1;31;40m check_inject_pkt() error, can't jump to inner addr_type:%d header!\033[0m\n", pstream->addr.addrtype);
		return -1;
	}
#endif

	/********* ip layer check **********/
	if(ADDR_TYPE_IPV4 == pstream->addr.addrtype){
		const struct ip *i4hdr = (struct ip *)tun_rcv_ip_pkt;
		ip_protocol = i4hdr->ip_p;
		ip_hdr_len = compare_rst_pkt_para_ipv4(pstream, inject_paras, (struct ip *)tun_rcv_ip_pkt, (struct ip *)raw_ip_pkt);
	}else{
		const struct ip6_hdr *i6hdr = (struct ip6_hdr *)tun_rcv_ip_pkt;
		ip_protocol = i6hdr->ip6_nxt;		
		ip_hdr_len = compare_rst_pkt_para_ipv6(pstream, inject_paras, (struct ip6_hdr *)tun_rcv_ip_pkt, (struct ip6_hdr *)raw_ip_pkt);
	}
	if(ip_hdr_len <= 0){
		return ip_hdr_len;
	}

	if(inject_paras->inject_type & GINJECT_TYPE_TCP){
		if(ip_protocol != IPPROTO_TCP){
			printf("\033[1;31;40mcheck_inject_pkt() error, ip protocol is not tcp!\033[0m\n");
			return -1;			
		}
		/******* TCP校验和检查, 发送的RST包必须保证校验和正确, 否则对端协议栈不收 *******/
		raw_pkt_tcp_h = (struct tcphdr *)((char *)raw_ip_pkt + ip_hdr_len);
		tun_rst_tcp_h = (struct tcphdr *)((char *)tun_rcv_ip_pkt + ip_hdr_len);

		/* 此处要先把数据包的里checksum先存起来 */
		unsigned short raw_tcp_chksum = tun_rst_tcp_h->check;
		actual_payload_len = get_actual_inject_payload_len(pstream, inject_paras);
		sendpacket_do_checksum((unsigned char *)tun_rcv_ip_pkt, IPPROTO_TCP, actual_payload_len + sizeof(struct tcphdr));
		if(raw_tcp_chksum != tun_rst_tcp_h->check){
			printf("\033[1;31;40mcheck_inject_pkt() error, packet tcp header checksum error!\033[0m\n");
			return -1;
		}

		if(GINJECT_TCP_RST == inject_paras->inject_type){
			ret = compare_rst_pkt_para_tcp_layer(pstream, inject_paras, tun_rst_tcp_h, raw_pkt_tcp_h);
			if(ret < 0){
				printf("\033[1;31;40mcheck_inject_pkt() error,compare_rst_pkt_para_tcp_layer() error!\033[0m\n");
				return -1;
			}
		}
	}else if(inject_paras->inject_type & GINJECT_TYPE_UDP){
		if(ip_protocol != IPPROTO_UDP){
			printf("\033[1;31;40mcheck_inject_pkt() error, ip protocol is not udp!\033[0m\n");
			return -1;			
		}	
		tun_udp_h = (struct udphdr *)((char *)tun_rcv_ip_pkt + ip_hdr_len);
		if(tun_udp_h->check != 0){
			/* 此处要先把数据包的里checksum先存起来 */
			unsigned short raw_udp_chksum = tun_udp_h->check;
			actual_payload_len = get_actual_inject_payload_len(pstream, inject_paras);
			
			sendpacket_do_checksum((unsigned char *)tun_rcv_ip_pkt, IPPROTO_UDP, actual_payload_len + sizeof(struct udphdr));
			if(raw_udp_chksum != tun_udp_h->check){
				printf("\033[1;31;40mcheck_inject_pkt() error, packet udp header checksum error!\033[0m\n");
				return -1;
			}
		}
	}
	
	if(inject_paras->payload_len > 0){
		ret = check_inject_pkt_payload(pstream, inject_pkt_from_tap, inject_paras);
	}
	
	return ret;
}


/*
	初始化时新建一个线程用于接收tun/tap网卡的数据包, 
	注意tap/tun网卡up之后, 可能会有广播、组播包被系统协议栈自动发出, 并不是sapp的测试包, 需要过滤.
*/
static void *tun_recv_thread(void *arg)
{
	char pkt_buf[256];
	int ret = -2;

	g_recv_thread_inited = 1;
	
	while(g_recv_thread_inited){
		while(g_recv_tun_rst_flag != 0){ //处理线程发送完成完成会设成0
			usleep(1000);
		}
		ret = read(g_tun_fd, pkt_buf, sizeof(pkt_buf));
		if(ret < 0){
			usleep(1000 * 100);
			ret = -2;
			continue;
		}else if(0 == ret){ //EOF
			g_recv_tun_rst_flag = 2;
			return NULL;
		}else{
			if(identify_broadcast_multicast_pkt((struct ethhdr *)pkt_buf) != 0){
				printf("recv broadcast or multicast pkt, ignore!\n");
				if(g_recv_thread_inited == 0)return NULL;
				continue;
			}else{			
				memcpy(g_recv_tun_rst_buf, pkt_buf, ret);
				g_recv_tun_rst_flag = 1;
			}
		}
	}

	if(-2 == ret){
		printf("\033[1;31;40mnot recv any packet from tun dev!\033[0m\n");
		g_recv_tun_rst_flag = 2;
	}

	return NULL;
}

/* 不希望收到数据包, 理论上就不应该发出来的用例
    1: 收到了数据包;
    0: timeout时间后, 没有收到数据包;
*/
static int __expect_no_pkt(int timeout)
{
	int has_recv_pkt = 0;
	time_t last_time = time(NULL);

	while(last_time + timeout < time(NULL)){
		if(1 == g_recv_tun_rst_flag){
			has_recv_pkt = 1;
			break;
		}
		usleep(1000);
	}

	return has_recv_pkt;
}

/*
	这个插件注定是要失败的, 需要一些特殊判断, 所以没有使用MESA_rst_tcp_test_case_c2s()函数.
*/
extern "C" char gtp_single_reverse_send_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	struct inject_pkt_para inject_paras = {};

	inject_paras.rst_para.th_flags = TH_RST|TH_ACK;
	inject_paras.rst_para.rst_pkt_num = 1;
	inject_paras.rst_para.dir = pstream->curdir ^ 0x3; /* 反向发包 */
	//inject_paras.send_stream_dir = pstream->curdir ^ 0x3;
	inject_paras.rst_para.signature_seed1 = 65535;
	inject_paras.rst_para.signature_seed2 = 13;

	while(0 == g_recv_thread_inited){ /* 接收线程还未初始化成功, 先不要发包 */
		usleep(100);
	}
	
	ret = MESA_rst_tcp(pstream, &inject_paras.rst_para, sizeof(struct rst_tcp_para));
	g_recv_tun_rst_flag = 0;
	if(ret >= 0){
		printf("\033[1;31;40mMESA_rst_tcp() success! but expect error, not support inject reverse gtp packet for singel stream!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}else{
		/* 即便返回失败, 也在收包卡上检查一下 */
		if(__expect_no_pkt(2) != 0){
			printf("\033[1;31;40mMESA_rst_tcp() success, has recv pkt!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;			
		}else{
			printf("\033[32msingle_reverse_send_entry test succ!\033[0m\n");
			sendto_test_result(GTEST_SAPP_SUCC);	
		}
	}

	return APP_STATE_DROPME;
}


/*
	发送C2S方向的包.
*/
static int MESA_rst_tcp_test_case_c2s(struct streaminfo *pstream, void *a_packet)
{
	struct inject_pkt_para inject_paras = {};

	inject_paras.rst_para.th_flags = 0x4;
	inject_paras.rst_para.rst_pkt_num = 1;
	inject_paras.rst_para.dir = DIR_C2S;
	inject_paras.send_stream_dir = DIR_C2S;
	inject_paras.rst_para.signature_seed1 = 0;
	inject_paras.rst_para.signature_seed2 = 0;

	while(0 == g_recv_thread_inited){ /* 接收线程还未初始化成功, 先不要发包 */
		usleep(100);
	}

	if(MESA_rst_tcp(pstream, &inject_paras.rst_para, sizeof(struct rst_tcp_para)) < 0){
		printf("\033[1;31;40mMESA_rst_tcp() C2S error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	while(g_recv_tun_rst_flag != 2){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	if(check_rst_pkt_para(pstream, &inject_paras, g_recv_tun_rst_buf, a_packet) < 0){
		printf("\033[1;31;40mcheck_rst_packet() C2S error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	g_recv_tun_rst_flag = 0;
    
	return 0;
}

/*
	发送S2C方向的包.
*/
static int MESA_rst_tcp_test_case_s2c(struct streaminfo *pstream, void *a_packet)
{
	struct inject_pkt_para inject_paras;
	time_t last_time;
	
	inject_paras.rst_para.th_flags = 0x14;
	inject_paras.rst_para.rst_pkt_num = 1;
	inject_paras.rst_para.dir = DIR_S2C;
	inject_paras.send_stream_dir = DIR_S2C;
	inject_paras.rst_para.signature_seed1 = 65535;
	inject_paras.rst_para.signature_seed2 = 11;
	

	while(0 == g_recv_thread_inited){ /* 接收线程还未初始化成功, 先不要发包 */
		usleep(100);
	}

	if(MESA_rst_tcp(pstream, &inject_paras.rst_para, sizeof(struct rst_tcp_para)) < 0){
		printf("\033[1;31;40mMESA_rst_tcp() S2C error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	last_time = time(NULL);
	while(0 == g_recv_tun_rst_flag){
		usleep(1000);
		if(last_time + 3 < time(NULL)){ /* 调用发包函数, 超过3秒还没收到, 肯定是有问题了 */
			g_recv_tun_rst_flag = 2;
			break;
		}
	}
	
	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	if(check_rst_pkt_para(pstream, &inject_paras, g_recv_tun_rst_buf, a_packet) < 0){
		printf("\033[1;31;40mcheck_rst_packet() S2C error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	g_recv_tun_rst_flag = 0;
    
	return 0;
}

/*
	发送S2C方向的包.
*/
static int MESA_inject_udp_test_case_s2c(struct streaminfo *pstream, void *a_packet)
{
	struct inject_pkt_para inject_paras = {};

	inject_paras.inject_type = GINJECT_UDP_PAYLOAD;
	inject_paras.inject_opt = SIO_DEFAULT;
	inject_paras.send_stream_dir = DIR_S2C;
	inject_paras.payload = GINJECT_TEST_PAYLOAD;
	inject_paras.payload_len = strlen(GINJECT_TEST_PAYLOAD);

	while(0 == g_recv_thread_inited){ /* 接收线程还未初始化成功, 先不要发包 */
		usleep(100);
	}

	if(MESA_inject_pkt(pstream, GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), a_packet, pstream->routedir) < 0){
		printf("\033[1;31;40mMESA_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	while((g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}
	
	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	if(check_inject_pkt(pstream, g_recv_tun_rst_buf, a_packet, &inject_paras) < 0){
		printf("\033[1;31;40mcheck_rst_packet() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	g_recv_tun_rst_flag = 0;
    
	return 0;
}

extern "C" char MESA_rst_tcp_plug_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}

	if(MESA_rst_tcp_test_case_c2s(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}
	
	if(MESA_rst_tcp_test_case_s2c(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}
	
	printf("\033[32mMESA_rst_tcp_plug_entry test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

extern "C" char MESA_rst_tcp_plug_c2s_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}

	if(MESA_rst_tcp_test_case_c2s(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}

	printf("\033[32mMESA_rst_tcp_plug_entry test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


extern "C" char MESA_rst_tcp_plug_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}
	
	if(MESA_rst_tcp_test_case_s2c(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}

	printf("\033[32mMESA_rst_tcp_plug_entry test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

extern "C" char MESA_inject_udp_plug_s2c_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}
	
	if(MESA_inject_udp_test_case_s2c(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}

	printf("\033[32mMESA_rst_tcp_plug_entry test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}

extern "C" char MESA_rst_tcp_plug_entry_in_double_dir(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}

	/* 非对称协议反向发包肯定失败, 等stream成为双向流时, sapp已经获取了底层双向地址, 然后再发包 */
	if(DIR_DOUBLE != pstream->dir){
		return APP_STATE_GIVEME;
	}

	if(MESA_rst_tcp_test_case_c2s(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}
	
	if(MESA_rst_tcp_test_case_s2c(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}
	
	printf("\033[32mMESA_rst_tcp_plug_entry test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


static int MESA_kill_tcp_test_check_pkt(struct streaminfo *pstream, struct inject_pkt_para *inject_paras, void *a_packet)
{
	while((g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	if(check_rst_pkt_para(pstream, inject_paras, g_recv_tun_rst_buf, a_packet) < 0){
		printf("\033[1;31;40mcheck_rst_packet() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}
	g_recv_tun_rst_flag = 0;
	
	return 0;
}

/*
	发送C2S方向的包.
*/
extern "C" int MESA_kill_tcp_test(struct streaminfo *pstream, void *a_packet)
{
	int ret;
	struct inject_pkt_para inject_paras;

	if(MESA_kill_tcp(pstream, a_packet) < 0){
		printf("\033[1;31;40mMESA_kill_tcp() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	inject_paras.rst_para.th_flags = 0x14;
	inject_paras.rst_para.rst_pkt_num = 1;
	inject_paras.send_stream_dir = pstream->curdir;
	inject_paras.rst_para.signature_seed1 = 0;
	inject_paras.rst_para.signature_seed2 = 0;

	ret = MESA_kill_tcp_test_check_pkt(pstream, &inject_paras, a_packet);
	if(ret < 0){
		printf("\033[1;31;40mMESA_kill_tcp_test_check_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	inject_paras.rst_para.th_flags = 0x14;
	inject_paras.rst_para.rst_pkt_num = 1;
	inject_paras.send_stream_dir = pstream->curdir ^ DIR_DOUBLE;
	inject_paras.rst_para.signature_seed1 = 0;
	inject_paras.rst_para.signature_seed2 = 0;

	ret = MESA_kill_tcp_test_check_pkt(pstream, &inject_paras, a_packet);
	if(ret < 0){
		printf("\033[1;31;40mMESA_kill_tcp_test_check_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}	

	printf("\033[32mMESA_kill_tcp_test() test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	
	
	return APP_STATE_GIVEME;
}



extern "C" char MESA_kill_tcp_plug_entry_in_double_dir(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}

	if(DIR_DOUBLE != pstream->dir){
		return APP_STATE_GIVEME;
	}

	if(MESA_kill_tcp_test(pstream, a_packet) < 0){
		return APP_STATE_DROPME;
	}
	
	printf("\033[32mMESA_rst_tcp_plug_entry test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_DROPME;
}


/*
	发送TCP负载包.
*/
extern "C" int sapp_inject_tcp_payload_c2s(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct inject_pkt_para inject_paras = {};

	if(pstream->curdir != DIR_C2S){
		printf("MESA_inject_tcp_payload_c2s(): recv pkt, but curdir not C2S!\n");
		return APP_STATE_GIVEME;
	}

	if(sapp_inject_pkt(pstream, SIO_DEFAULT, GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), pstream->routedir) < 0){
		printf("\033[1;31;40mMESA_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	while((g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	inject_paras.inject_type = GINJECT_TCP_PAYLOAD;
	inject_paras.inject_opt = SIO_DEFAULT;
	inject_paras.send_stream_dir = DIR_C2S;
	inject_paras.payload = GINJECT_TEST_PAYLOAD;
	inject_paras.payload_len = strlen(GINJECT_TEST_PAYLOAD);

	if(check_inject_pkt(pstream,  g_recv_tun_rst_buf, a_packet, &inject_paras) < 0){
		printf("\033[1;31;40mcheck_rst_packet() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	printf("\033[32mMESA_inject_tcp_payload_c2s test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}

/*
	发送TCP负载包.
*/
extern "C" int sapp_inject_tcp_payload_s2c(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct inject_pkt_para inject_paras = {};

	if(pstream->curdir != DIR_C2S){
		printf("sapp_inject_tcp_payload_s2c(): recv pkt, but curdir not C2S!\n");
		return APP_STATE_GIVEME;
	}

	if(sapp_inject_pkt(pstream, SIO_DEFAULT, GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), pstream->routedir) < 0){
		printf("\033[1;31;40m sapp_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	while((g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	inject_paras.inject_type = GINJECT_TCP_PAYLOAD;
	inject_paras.inject_opt = SIO_DEFAULT;
	inject_paras.send_stream_dir = DIR_S2C;
	inject_paras.payload = GINJECT_TEST_PAYLOAD;
	inject_paras.payload_len = strlen(GINJECT_TEST_PAYLOAD);

	if(check_inject_pkt(pstream,  g_recv_tun_rst_buf, a_packet, &inject_paras) < 0){
		printf("\033[1;31;40mcheck_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	printf("\033[32m sapp_inject_tcp_payload_s2c test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}


/*
	发送TCP负载包.
*/
extern "C" int sapp_inject_udp_payload_c2s(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	struct inject_pkt_para inject_paras = {};

	if(a_packet == NULL){
		printf("sapp_inject_udp_payload_c2s(): a_packet is NULL!\n");
		return APP_STATE_GIVEME;
	}

	if(pstream->curdir != DIR_C2S){
		printf("MESA_inject_tcp_payload_c2s(): recv pkt, but curdir not C2S!\n");
		return APP_STATE_GIVEME;
	}

	if(sapp_inject_pkt(pstream, SIO_DEFAULT, GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), pstream->routedir) < 0){
		printf("\033[1;31;40mMESA_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	while((g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	inject_paras.inject_type = GINJECT_UDP_PAYLOAD;
	inject_paras.inject_opt = SIO_DEFAULT;
	inject_paras.send_stream_dir = DIR_C2S;
	inject_paras.payload = GINJECT_TEST_PAYLOAD;
	inject_paras.payload_len = strlen(GINJECT_TEST_PAYLOAD);

	if(check_inject_pkt(pstream,  g_recv_tun_rst_buf, a_packet, &inject_paras) < 0){
		printf("\033[1;31;40mcheck_rst_packet() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	printf("\033[32mMESA_inject_tcp_payload_c2s test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}


extern "C" int MESA_inject_tcp_payload_c2s(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{

	struct inject_pkt_para inject_paras = {};

	if(pstream->curdir != DIR_C2S){
		printf("MESA_inject_tcp_payload_c2s(): recv pkt, but curdir not C2S!\n");
		return APP_STATE_GIVEME;
	}

	if(MESA_inject_pkt(pstream,  GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), a_packet, pstream->routedir) < 0){
		printf("\033[1;31;40mMESA_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	while((g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}
	
	inject_paras.inject_type = GINJECT_TCP_PAYLOAD;
	inject_paras.inject_opt = SIO_DEFAULT;
	inject_paras.send_stream_dir = DIR_C2S;
	inject_paras.payload = GINJECT_TEST_PAYLOAD;
	inject_paras.payload_len = strlen(GINJECT_TEST_PAYLOAD);

	if(check_inject_pkt(pstream,  g_recv_tun_rst_buf, a_packet, &inject_paras) < 0){
		printf("\033[1;31;40mcheck_rst_packet() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	printf("\033[32mMESA_inject_tcp_payload_c2s test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}


extern "C" int MESA_inject_tcp_payload_s2c(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{

	struct inject_pkt_para inject_paras = {};

	if(pstream->curdir != DIR_C2S){
		printf("MESA_inject_tcp_payload_s2c(): recv pkt, but curdir not C2S!\n");
		return APP_STATE_GIVEME;
	}

	if(MESA_inject_pkt(pstream,  GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD), a_packet, pstream->routedir) < 0){
		printf("\033[1;31;40mMESA_inject_pkt() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	while((g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}
	
	inject_paras.inject_type = GINJECT_TCP_PAYLOAD;
	inject_paras.inject_opt = SIO_DEFAULT;
	inject_paras.send_stream_dir = DIR_S2C;
	inject_paras.payload = GINJECT_TEST_PAYLOAD;
	inject_paras.payload_len = strlen(GINJECT_TEST_PAYLOAD);

	if(check_inject_pkt(pstream,  g_recv_tun_rst_buf, a_packet, &inject_paras) < 0){
		printf("\033[1;31;40mcheck_inject_packet() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;
	}

	printf("\033[32mMESA_inject_tcp_payload_s2c test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}


static int plug_inject_payload_test(struct streaminfo *pstream, void *a_packet, enum sapp_inject_opt inj_opt, unsigned char inject_stream_dir, void *payload, int payload_len)
{
	struct inject_pkt_para inject_paras = {};
	struct streaminfo_private *pstream_pr = (struct streaminfo_private *)pstream;
	unsigned char inject_route_dir;

	if(inject_stream_dir == DIR_C2S){
		inject_route_dir = pstream_pr->stream_c2s_route_dir;
	}else{
		inject_route_dir = pstream_pr->stream_c2s_route_dir ^ 1;
	}

	if(sapp_inject_pkt(pstream, inj_opt, payload, payload_len, inject_route_dir) < 0){
		printf("\033[1;31;40mplug_inject_payload_test() error!\033[0m\n");
		return -1;
	}

	while((0 == g_recv_tun_rst_flag) && (g_recv_tun_rst_flag != 2)){
		usleep(1000);
	}

	if(2 == g_recv_tun_rst_flag){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	inject_paras.inject_type = GINJECT_TCP_PAYLOAD;
	inject_paras.inject_opt = inj_opt;
	inject_paras.send_stream_dir = inject_stream_dir;
	inject_paras.payload = (char *)payload;
	inject_paras.payload_len = payload_len;
	

	if(check_inject_pkt(pstream,  g_recv_tun_rst_buf, a_packet, &inject_paras) < 0){
		printf("\033[1;31;40mplug_inject_payload_test() error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	/* 处理完当前包后清空标志位, 接收线程才会收下一个包 */
	g_recv_tun_rst_flag = 0;

	return 0;
}

extern "C" char inject_gtp_payload_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	
	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}
	
	if(a_packet == NULL)return APP_STATE_GIVEME;

	ret = plug_inject_payload_test(pstream, a_packet, SIO_DEFAULT, DIR_C2S, (void *)GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));
	if(ret < 0){
		printf("\033[1;31;40minject_gtp_payload_tcp_entry() C2S error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}

	ret = plug_inject_payload_test(pstream, a_packet, SIO_DEFAULT, DIR_S2C, (void *)GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));
	if(ret < 0){
		printf("\033[1;31;40minject_gtp_payload_tcp_entry() S2C error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}	
	
	printf("\033[32minject_gtp_payload_tcp_entry() test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}


extern "C" char inject_only_for_l2tp_tunnel_entry_c2s(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	unsigned short tunnel_type = STREAM_TUNNLE_NON;
	int ret, opt_len = sizeof(short);
	
	ret = MESA_get_stream_opt(pstream, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_len);
	if((ret < 0) || (tunnel_type != STREAM_TUNNLE_L2TP)){
		return APP_STATE_DROPME;
	}

	sapp_inject_udp_payload_c2s(pstream, pme, thread_seq, a_packet);

	return APP_STATE_GIVEME;
}

/*************************************

    TODO: inject_xxx这些系列函数很多功能类似, 没必要分这么多函数, 没有封装好, 待合并整理.....

**************************************/
extern "C" char inject_raw_ip_pkt_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;

	/* 即符合gtp_double_for_inject_payload.pcap的C2S方向注入的内层原始IP包十六进制 */
	const static unsigned char raw_ip_pkt_c2s[] = 
	{
	  0x45, 0x00,
	  0x00, 0x58, 0xfb, 0x54, 0x40, 0x00, 0x4f, 0x06,
	  0x9f, 0x90, 0x64, 0x53, 0x9a, 0xe7, 0x11, 0x86,
	  0x7f, 0xfa, 0xd8, 0x3d, 0x01, 0xbb, 0x36, 0x42,
	  0x8c, 0x2b, 0xa8, 0x85, 0x60, 0x59, 0x50, 0x18,
	  0x04, 0x89, 0xfc, 0x2a, 0x00, 0x00, 0x61, 0x62,
	  0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
	  0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
	  0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
	  0x2d, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	  0x38, 0x39, 0x30, 0x2d, 0x21, 0x40, 0x23, 0x24,
	  0x25, 0x5e, 0x26, 0x2a, 0x28, 0x29
	};


	const static unsigned char raw_ip_pkt_s2c[] = 
	{
	  0x45, 0x00, 0x00, 0x58, 0x48, 0x80,
	  0x40, 0x00, 0x56, 0x06, 0x4b, 0x65, 0x11, 0x86,
	  0x7f, 0xfa, 0x64, 0x53, 0x9a, 0xe7, 0x01, 0xbb,
	  0xd8, 0x3d, 0xa8, 0x85, 0x60, 0x59, 0x36, 0x42,
	  0x8c, 0x2b, 0x50, 0x18, 0x04, 0x0c, 0xfc, 0xa7,
	  0x00, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
	  0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
	  0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
	  0x77, 0x78, 0x79, 0x7a, 0x2d, 0x31, 0x32, 0x33,
	  0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2d,
	  0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a,
	  0x28, 0x29
	};	
	
	if(a_packet == NULL){

		return APP_STATE_GIVEME;		
	}

	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}

	ret = plug_inject_payload_test(pstream, a_packet,SIO_EXCLUDE_THIS_LAYER_HDR, DIR_C2S, (void *)raw_ip_pkt_c2s, sizeof(raw_ip_pkt_c2s));
	if(ret < 0){
		printf("\033[1;31;40minject_gtp_payload_tcp_entry() C2S error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}

	ret = plug_inject_payload_test(pstream, a_packet, SIO_EXCLUDE_THIS_LAYER_HDR, DIR_S2C, (void *)raw_ip_pkt_s2c, sizeof(raw_ip_pkt_s2c));
	if(ret < 0){
		printf("\033[1;31;40minject_gtp_payload_tcp_entry() S2C error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}	
	
	printf("\033[32minject_gtp_payload_tcp_entry() test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}

extern "C" char inject_raw_ipv4_exclude_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	unsigned char ipv4_raw_pkt_c2s[1500] = {}; 
	unsigned char ipv4_raw_pkt_s2c[1500] = {}; 
	struct ip *c2s_ip4hdr, *s2c_i4hdr;
	struct tcphdr *c2s_thdr, *s2c_thdr;

	c2s_ip4hdr = (struct ip *)ipv4_raw_pkt_c2s;
	s2c_i4hdr = (struct ip *)ipv4_raw_pkt_s2c;

	if(OP_STATE_PENDING == pstream->opstate){
		c2s_ip4hdr->ip_v = 4;
		c2s_ip4hdr->ip_hl = 5;
		c2s_ip4hdr->ip_len = htons(strlen(GINJECT_TEST_PAYLOAD)+sizeof(struct tcphdr)+sizeof(struct ip));
		c2s_ip4hdr->ip_ttl = 128;
		c2s_ip4hdr->ip_p = IPPROTO_TCP;
		c2s_ip4hdr->ip_src.s_addr = pstream->addr.tuple4_v4->saddr;
		c2s_ip4hdr->ip_dst.s_addr = pstream->addr.tuple4_v4->daddr;
		sendpacket_do_checksum((unsigned char *)ipv4_raw_pkt_c2s, IPPROTO_IP, sizeof(struct ip));

		s2c_i4hdr->ip_v = 4;
		s2c_i4hdr->ip_hl = 5;
		s2c_i4hdr->ip_len = htons(strlen(GINJECT_TEST_PAYLOAD)+sizeof(struct tcphdr)+sizeof(struct ip));
		s2c_i4hdr->ip_ttl = 128;
		s2c_i4hdr->ip_p = IPPROTO_TCP;
		s2c_i4hdr->ip_src.s_addr = pstream->addr.tuple4_v4->daddr;
		s2c_i4hdr->ip_dst.s_addr = pstream->addr.tuple4_v4->saddr;
		sendpacket_do_checksum((unsigned char *)ipv4_raw_pkt_s2c, IPPROTO_IP, sizeof(struct ip));
		
		c2s_thdr = (struct tcphdr *)(ipv4_raw_pkt_c2s + sizeof(struct ip));
		s2c_thdr = (struct tcphdr *)(ipv4_raw_pkt_s2c + sizeof(struct ip));

		c2s_thdr->doff = 5;
		c2s_thdr->window = 100;
		s2c_thdr->doff = 5;
		s2c_thdr->window = 200;
		
		c2s_thdr->source = pstream->addr.tuple4_v4->source;
		c2s_thdr->dest = pstream->addr.tuple4_v4->dest;

		s2c_thdr->source = pstream->addr.tuple4_v4->dest;
		s2c_thdr->dest = pstream->addr.tuple4_v4->source;
		
		memcpy(ipv4_raw_pkt_c2s+sizeof(struct ip)+sizeof(struct tcphdr), GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));
		memcpy(ipv4_raw_pkt_s2c+sizeof(struct ip)+sizeof(struct tcphdr), GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));

		sendpacket_do_checksum((unsigned char *)ipv4_raw_pkt_c2s, IPPROTO_TCP, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr));
		sendpacket_do_checksum((unsigned char *)ipv4_raw_pkt_s2c, IPPROTO_TCP, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr));

		/* wait for run_recv_thread init success. */
		while(0 == g_recv_thread_inited){
			usleep(1);
		}

		ret = plug_inject_payload_test(pstream, a_packet,SIO_EXCLUDE_THIS_LAYER_HDR, DIR_C2S, (void *)ipv4_raw_pkt_c2s, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr)+sizeof(struct ip));
		if(ret < 0){
			printf("\033[1;31;40m inject_raw_ipv4_exclude_tcp_entry() C2S error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}

		ret = plug_inject_payload_test(pstream, a_packet, SIO_EXCLUDE_THIS_LAYER_HDR, DIR_S2C, (void *)ipv4_raw_pkt_s2c, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr)+sizeof(struct ip));
		if(ret < 0){
			printf("\033[1;31;40m inject_raw_ipv4_exclude_tcp_entry() S2C error!\033[0m\n");
			sendto_test_result(GTEST_SAPP_ERR);
			return APP_STATE_DROPME;		
		}	
		
		printf("\033[32m inject_raw_ipv4_exclude_tcp_entry() test succ!\033[0m\n");
		sendto_test_result(GTEST_SAPP_SUCC);	
	}

	return APP_STATE_GIVEME;
}


extern "C" char inject_raw_ipv6_pkt_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;

	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}

	ret = plug_inject_payload_test(pstream, a_packet,SIO_DEFAULT, DIR_C2S, (void *)GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));
	if(ret < 0){
		printf("\033[1;31;40minject_ipv6_pkt_tcp_entry() C2S error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}

	ret = plug_inject_payload_test(pstream, a_packet, SIO_DEFAULT, DIR_S2C, (void *)GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));
	if(ret < 0){
		printf("\033[1;31;40minject_ipv6_pkt_tcp_entry() S2C error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}	
	
	printf("\033[32minject_ipv6_pkt_tcp_entry() test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}


extern "C" char inject_raw_ipv6_exclude_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq, void *a_packet)
{
	int ret;
	unsigned char ipv6_raw_pkt_c2s[1500] = {}; 
	unsigned char ipv6_raw_pkt_s2c[1500] = {}; 

	struct ip6_hdr *c2s_ip6hdr, *s2c_ip6hdr;
	struct tcphdr *c2s_thdr, *s2c_thdr;

	c2s_ip6hdr = (struct ip6_hdr *)ipv6_raw_pkt_c2s;
	s2c_ip6hdr = (struct ip6_hdr *)ipv6_raw_pkt_s2c;

	c2s_ip6hdr->ip6_vfc = 0x60;
	c2s_ip6hdr->ip6_plen = htons(strlen(GINJECT_TEST_PAYLOAD)+sizeof(struct tcphdr));
	c2s_ip6hdr->ip6_nxt = IPPROTO_TCP;
	c2s_ip6hdr->ip6_hlim = 128;
	memset(&c2s_ip6hdr->ip6_src, 0x11, sizeof(struct in6_addr));
	memset(&c2s_ip6hdr->ip6_dst, 0xFF, sizeof(struct in6_addr));

	s2c_ip6hdr->ip6_vfc = 0x60;
	s2c_ip6hdr->ip6_plen = htons(strlen(GINJECT_TEST_PAYLOAD)+sizeof(struct tcphdr));
	s2c_ip6hdr->ip6_nxt = IPPROTO_TCP;
	s2c_ip6hdr->ip6_hlim = 128;
	memset(&s2c_ip6hdr->ip6_src, 0xFF, sizeof(struct in6_addr));
	memset(&s2c_ip6hdr->ip6_dst, 0x11, sizeof(struct in6_addr));

	c2s_thdr = (struct tcphdr *)(ipv6_raw_pkt_c2s + sizeof(struct ip6_hdr));
	s2c_thdr = (struct tcphdr *)(ipv6_raw_pkt_s2c + sizeof(struct ip6_hdr));

	c2s_thdr->doff = 5;
	c2s_thdr->window = 100;
	s2c_thdr->doff = 5;
	s2c_thdr->window = 200;
	
	memcpy(ipv6_raw_pkt_c2s+sizeof(struct ip6_hdr)+sizeof(struct tcphdr), GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));
	memcpy(ipv6_raw_pkt_s2c+sizeof(struct ip6_hdr)+sizeof(struct tcphdr), GINJECT_TEST_PAYLOAD, strlen(GINJECT_TEST_PAYLOAD));

	sendpacket_do_checksum((unsigned char *)ipv6_raw_pkt_c2s, IPPROTO_TCP, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr));
	sendpacket_do_checksum((unsigned char *)ipv6_raw_pkt_s2c, IPPROTO_TCP, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr));

	/* wait for run_recv_thread init success. */
	while(0 == g_recv_thread_inited){
		usleep(1);
	}

	ret = plug_inject_payload_test(pstream, a_packet,SIO_EXCLUDE_THIS_LAYER_HDR, DIR_C2S, (void *)ipv6_raw_pkt_c2s, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr)+sizeof(struct ip6_hdr));
	if(ret < 0){
		printf("\033[1;31;40minject_ipv6_pkt_tcp_entry() C2S error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}

	ret = plug_inject_payload_test(pstream, a_packet, SIO_EXCLUDE_THIS_LAYER_HDR, DIR_S2C, (void *)ipv6_raw_pkt_s2c, strlen(GINJECT_TEST_PAYLOAD) + sizeof(struct tcphdr)+sizeof(struct ip6_hdr));
	if(ret < 0){
		printf("\033[1;31;40minject_ipv6_pkt_tcp_entry() S2C error!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return APP_STATE_DROPME;		
	}	
	
	printf("\033[32minject_ipv6_pkt_tcp_entry() test succ!\033[0m\n");
	sendto_test_result(GTEST_SAPP_SUCC);	

	return APP_STATE_GIVEME;
}


static int inject_setup_env(const char *tun_name)
{
	char shell_cmd[NAME_MAX] = {};
		
	snprintf(shell_cmd, NAME_MAX, "ifconfig %s 169.254.169.169/16 up", tun_name);
	if(system(shell_cmd) != 0){
		printf("\033[1;31;40minject_setup_env() error: add ip address to %s failed!\033[0m\n", tun_name);
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	snprintf(shell_cmd, NAME_MAX, "arp -s 169.254.1.1 00:11:22:33:44:55");
	if(system(shell_cmd) != 0){
		printf("\033[1;31;40minject_setup_env() error: add static arp to %s failed, %s\033[0m\n", tun_name, strerror(errno));
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	snprintf(shell_cmd, NAME_MAX, "arp -s 169.254.254.254 00:11:22:33:44:66");
	if(system(shell_cmd) != 0){
		printf("\033[1;31;40minject_setup_env() error: add static arp to %s failed, %s\033[0m\n", tun_name, strerror(errno));
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}	

	return 0;
}

pthread_t g_tun_thread_pid;
extern "C" int MESA_rst_tcp_test_init_v4(void)
{
	char tun_name[NAME_MAX] = {};
	
	if(gtest_sapp_slave_init() < 0){
		return -1;
	}

	g_tun_fd = tun_dev_create(tun_name);
	if(g_tun_fd < 0){
		printf("\033[1;31;40mMESA_rst_tcp_test_init_v4() error: create tun device failed!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	if(inject_setup_env(tun_name) < 0){
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;		
	}

	pthread_create(&g_tun_thread_pid, NULL, tun_recv_thread, NULL);

	return 0;
}

extern "C" int MESA_rst_tcp_test_init_v6(void)
{
	char tun_name[NAME_MAX] = {};
	char shell_cmd[NAME_MAX] = {};
	pthread_t pid;
	
	if(gtest_sapp_slave_init() < 0){
		return -1;
	}

	g_tun_fd = tun_dev_create(tun_name);
	if(g_tun_fd < 0){
		printf("\033[1;31;40mMESA_rst_tcp_test_init() error: create tun device failed!\033[0m\n");
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	snprintf(shell_cmd, NAME_MAX, "ifconfig %s inet6 add 2001:da8:205:1::254/64 up", tun_name);
	if(system(shell_cmd) < 0){
		printf("\033[1;31;40mMESA_rst_tcp_test_init_v6() error: add ip address to %s failed!\033[0m\n", tun_name);
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}

	snprintf(shell_cmd, NAME_MAX, "ip -6 neigh add 2001:da8:205:1::102  lladdr 00:00:02:03:01:02 dev %s", tun_name);
	if(system(shell_cmd) < 0){
		printf("\033[1;31;40mMESA_rst_tcp_test_init_v6() error: add ip 6 neigh to %s failed!\033[0m\n", tun_name);
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}	
	
	snprintf(shell_cmd, NAME_MAX, "ip -6 neigh add 2001:da8:205:1::210  lladdr 00:00:02:03:02:10 dev %s", tun_name);
	if(system(shell_cmd) < 0){
		printf("\033[1;31;40mMESA_rst_tcp_test_init_v6() error: add ip 6 neigh to %s failed!\033[0m\n", tun_name);
		sendto_test_result(GTEST_SAPP_ERR);
		return -1;
	}	

	pthread_create(&pid, NULL, tun_recv_thread, NULL);

	return 0;
}


extern "C" void gtest_sapp_inject_plug_destory(void)
{
	g_recv_tun_rst_flag = 0;
	g_recv_thread_inited = 0;
	pthread_join(g_tun_thread_pid, NULL);
	tun_dev_close(g_tun_fd);
	return;
}
