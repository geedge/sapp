#include "sapp_api.h"
#include "sapp_private_api.h"


static int test_tcp_flow_id = -1;
static unsigned short phony_protocol_plugid; 


#define TEST_NETWORK_FLOW  1
#define TEST_SAPP_API		   1



#if TEST_SAPP_API
char phony_biz_test(stSessionInfo* session_info,  void **pme, int thread_seq,struct streaminfo *a_stream,const void *a_packet)
{
	printf("I am biz plug, from pro info: %s\n", session_info->buf);
	

	return APP_STATE_GIVEME;
}

void phony_protocol_funstat(unsigned long long protflag)
{

}

long long phony_protocol_flag_change(char* flag_str)
{
	return 0xFFFF;
}

void phony_protocol_get_plugid(unsigned short plugid)
{
	phony_protocol_plugid= plugid;
}

/* 模拟解析层, 靠配置文件PLUGNAME=xxx识别 */
char phony_protocol_test(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	stSessionInfo stinfo;
	static void *biz_pme = NULL;

	memset(&stinfo, 0, sizeof(stSessionInfo));

	stinfo.plugid = phony_protocol_plugid;
	stinfo.session_state = SESSION_STATE_PENDING;
	stinfo.buf = "hello, lijia!\n";
	stinfo.buflen = strlen("hello, lijia!\n");
	stinfo.prot_flag = 0xFFFF;

	printf("I am protocol plug\n");
	PROT_PROCESS(&stinfo, &biz_pme, thread_seq, a_tcp, a_packet);

	return APP_STATE_GIVEME;
}


char print_vxlan_info(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct vxlan_info vinfo;
	int opt_val_len = sizeof(vinfo);
	int ret;

	if(OP_STATE_PENDING == a_tcp->opstate || OP_STATE_CLOSE == a_tcp->opstate){
		ret = MESA_get_stream_opt(a_tcp, MSO_STREAM_VXLAN_INFO, &vinfo, &opt_val_len);
		if(ret < 0){
			printf("get vxlan info error!\n");
		}else{
			printf("OPSTATE:%d, tuple4:%s, vxlan info:\n", a_tcp->opstate, printaddr(&a_tcp->addr, thread_seq));
			printf("\tencap_type:%d\n", vinfo.encap_type);
			printf("\tntrance_id:%d\n", vinfo.entrance_id);
			printf("\tdev_id:%d\n", vinfo.dev_id);
			printf("\tlink_id:%d\n", vinfo.link_id);
			printf("\tlink_dir:%d\n", vinfo.link_dir);

			printf("\tinner_smac:%s\n", vinfo.inner_smac);
			printf("\tinner_dmac:%s\n", vinfo.inner_dmac);
		}
	}

	return APP_STATE_DROPME;
}


char print_stream_tunnel_type(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	unsigned short tunnel_type = 0;
	int opt_val_len = sizeof(short);

	MESA_get_stream_opt(a_tcp, MSO_STREAM_TUNNEL_TYPE, &tunnel_type, &opt_val_len);
	if(tunnel_type != 0){
		printf("stream tunnel type:%d\n", tunnel_type);
	}

	return APP_STATE_DROPME;
}
char test_get_this_layer_header(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)get_this_layer_header(a_tcp);

	printf("iphdr:%p, ip->v=%d, ip->hl=%d, ip->len=%u\n", ip4hdr, ip4hdr->ip_v, ip4hdr->ip_hl*4, ntohs(ip4hdr->ip_len));

	return APP_STATE_GIVEME;
}

static void test_get_tcp_opts_show_detail(struct tcp_option *opt_array, int optnum)
{
	int i;

	for(i = 0; i < optnum; i++){
		if(opt_array[i].len > 0){
			printf("\ttype:%d, len:%d, value:%llu\n", opt_array[i].type, opt_array[i].len, opt_array[i].long_value);
		}else{
			printf("\ttype:%d, len:%d,  no value\n", opt_array[i].type, opt_array[i].len);
		}	
	}
}


char test_get_pkt_tcp_opts(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcp_option to[20];
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	const struct mesa_tcp_hdr *tcph;
	int ret;

	if(NULL == a_packet){
		return APP_STATE_DROPME;
	}

	if(ADDR_TYPE_IPV4 == a_tcp->addr.addrtype){
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + iph->ip_hl *4);
	}else{
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + 40);
	}
	
	ret = MESA_get_tcp_pkt_opts((const struct tcphdr *)tcph, to, 20);
	if(ret > 0){
		printf("MESA_get_tcp_pkt_opts OK:\n");
		test_get_tcp_opts_show_detail(to, ret);
	}

	return APP_STATE_GIVEME;
}


static void test_get_tcp_opts_show_ext_detail(struct tcp_option_ext *opt_array, int optnum)
{
	int i;

	for(i = 0; i < optnum; i++){
		if(opt_array[i].len > 0){
			printf("\ttype:%d, len:%d, value:%llu\n", opt_array[i].type, opt_array[i].len, opt_array[i].long_value);
		}else{
			printf("\ttype:%d, len:%d,  no value\n", opt_array[i].type, opt_array[i].len);
		}	
	}
}

char test_get_pkt_tcp_opts_ext(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcp_option_ext to[32];
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	const struct mesa_tcp_hdr *tcph;
	int ret;

	if(NULL == a_packet){
		return APP_STATE_DROPME;
	}

	if(ADDR_TYPE_IPV4 == a_tcp->addr.addrtype){
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + iph->ip_hl *4);
	}else{
		tcph = (const struct mesa_tcp_hdr * )((char *)a_packet + 40);
	}
	
	ret = MESA_get_tcp_pkt_opts_ext((const struct tcphdr *)tcph, to, 32);
	if(ret > 0){
		printf("MESA_get_tcp_pkt_opts_ext OK:\n");
		test_get_tcp_opts_show_ext_detail(to, ret);
	}

	return APP_STATE_GIVEME;
}
/* 测试单向流统计 */
char test_tcp_uni_stream_stats(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *raw_pdetail;
	struct tcp_flow_stat *tflow_project;
	
	if(-1 == test_tcp_flow_id){
		test_tcp_flow_id = project_customer_register("tcp_flow_stat", "struct");
		if(-1 == test_tcp_flow_id){
			printf("'tcp_flow_stat' is disable, no statistics\n");
		}
	}
	
	if(OP_STATE_CLOSE == a_tcp->opstate){
		if(DIR_DOUBLE == a_tcp->dir){
			/* 只看单向流 */
			return APP_STATE_DROPME;
		}

		raw_pdetail=(struct tcpdetail *)a_tcp->pdetail;
		printf("from-detail: server pkt=%d, count=%d, client pkt=%d, count=%d\n",
			raw_pdetail->serverpktnum,   raw_pdetail->serverbytes,
			raw_pdetail->clientpktnum,    raw_pdetail->clientbytes);

		if(test_tcp_flow_id != -1){
			/* 2015-12-29 lijia add */
			tflow_project = (struct tcp_flow_stat *)project_req_get_struct(a_tcp, test_tcp_flow_id);
			if(tflow_project){
				printf("from-project: server pkt=%u, count=%lu, client pkt=%u, count=%lu\n",
					tflow_project->C2S_data_pkt,tflow_project->C2S_data_byte,
					tflow_project->S2C_data_pkt, tflow_project->S2C_data_byte);		
			}
		}
		
		if((raw_pdetail->serverbytes && raw_pdetail->clientbytes) == 0){
			printf("stream-detail: %s\n", printaddr(&a_tcp->addr, thread_seq));
		}

		if((tflow_project->C2S_data_byte && tflow_project->S2C_data_byte) == 0){
			printf("stream-project: %s\n", printaddr(&a_tcp->addr, thread_seq));
		}
		
	}

	return APP_STATE_GIVEME;
}


char test_get_stream_tcp_opts(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct tcp_option *opt_array;
	int opt_num = 8;
	int ret;

	unsigned int isn = -1;
	int len = sizeof(int);
	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_C2S, &isn, &len);	
	if(ret >= 0){
		printf("MESA_get_stream_opt() MSO_TCP_ISN_C2S, %u!\n", isn);
	}else{
		printf("MESA_get_stream_opt() MSO_TCP_ISN_C2S error!\n");
		abort();
	}
	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_S2C, &isn, &len);	
	if(ret >= 0){
		printf("MESA_get_stream_opt() MSO_TCP_ISN_S2C, %u!\n", isn);
	}else{
		printf("MESA_get_stream_opt() MSO_TCP_ISN_S2C error!\n");
		abort();
	}
	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_SYN_OPT, &opt_array, &opt_num);
	if(ret >= 0){
		printf("stream:%p, SYN-OPTS:\n", a_tcp);
		test_get_tcp_opts_show_detail(opt_array, opt_num);
	}else{
		printf("MESA_get_stream_opt() MSO_TCP_SYN_OPT error!\n");
	}

	ret = MESA_get_stream_opt(a_tcp, MSO_TCP_SYNACK_OPT, &opt_array, &opt_num);
	if(ret >= 0){
		printf("stream:%p, SYNACK-OPTS:\n", a_tcp);
		test_get_tcp_opts_show_detail(opt_array, opt_num);
	}else{
		printf("MESA_get_stream_opt() MSO_TCP_SYNACK_OPT error!\n");
	}	

	return APP_STATE_DROPME;
}


char test_set_stream_timeout(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	int ret;
	unsigned short tout_val;
	unsigned char close_reason;
	int opt_len;
	
	if(pstream->opstate== OP_STATE_PENDING){
		/* 
			for test, port 11111=timeout=11s, port 22222=timeout=22s, 
			测试用nc产生3个udp流量, 端口分别为11111, 22222, 33333,
			等11s之后, 11111应该结束,
			22s之后, 22222应该结束,
			33333按照默认全局超时淘汰时间, 如果不设全局超时淘汰, 应该不会结束(dumpfile模式除外).
		*/
		if((pstream->addr.tuple4_v4->source == ntohs(11111))
		|| (pstream->addr.tuple4_v4->dest == ntohs(11111))){
			tout_val = 11;
			ret = MESA_set_stream_opt(pstream, MSO_TIMEOUT, &tout_val, sizeof(short));
			if(ret < 0){
				printf("stream:%p, MESA_set_stream_opt error:\n", pstream);
				return APP_STATE_DROPME;
			}			
		}

		if((pstream->addr.tuple4_v4->source == ntohs(22222))
		|| (pstream->addr.tuple4_v4->dest == ntohs(22222))){
			tout_val = 22;
			ret = MESA_set_stream_opt(pstream, MSO_TIMEOUT, &tout_val, sizeof(short));
			if(ret < 0){
				printf("stream:%p, MESA_set_stream_opt error:\n", pstream);
				return APP_STATE_DROPME;
			}			
		}		
	}

	if(pstream->opstate== OP_STATE_CLOSE){
		opt_len = sizeof(char);
		ret = MESA_get_stream_opt(pstream, MSO_STREAM_CLOSE_REASON, &close_reason, &opt_len);
		if(ret >= 0){
			printf("stream: %p %s closed, reason: %d!\n", pstream, printaddr(&pstream->addr, thread_seq), close_reason);
		}else{
			printf("stream: %p %s closed!\n", pstream, printaddr(&pstream->addr, thread_seq));
		}
	}

	return APP_STATE_GIVEME;	
}

char test_sapp_get_platform_opt(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	unsigned long long totpkt, totbyte, rand_num;
	int opt_len;
	char time_str[32];

	opt_len = sizeof(long long);
	sapp_get_platform_opt(SPO_TOTAL_RCV_PKT, &totpkt, &opt_len);

	sapp_get_platform_opt(SPO_TOTAL_RCV_BYTE, &totbyte, &opt_len);

	opt_len = 32;
	sapp_get_platform_opt(SPO_CURTIME_STRING, time_str, &opt_len);

	opt_len = sizeof(long long );
	sapp_get_platform_opt(SPO_RAND_NUMBER, &rand_num, &opt_len);

	printf("tot recv pkt by sapp_get_platform_opt is:%llu\n", totpkt);

	printf("tot recv byte by sapp_get_platform_opt is:%llu\n", totbyte);

	printf("curtime-str by sapp_get_platform_opt is:%s\n", time_str);

	printf("randnum by sapp_get_platform_opt is:%llu\n", rand_num);

	return APP_STATE_GIVEME;
}

int test_sapp_get_device_opt(const char *device)
{
	int ret;
	unsigned char dev_mac[6];
	unsigned int dev_ipaddr;
	int dev_mtu;
	int opt_len;

	opt_len = 6;
	ret = sapp_get_device_opt(device, SDO_MAC_ADDR, dev_mac, &opt_len);
	if(ret < 0){
		printf("sapp_get_device_opt->%s : SDO_MAC_ADDR error!\n ", device);
	}else{
		printf("sapp_get_device_opt->%s : SDO_MAC_ADDR: %02x, %02x, %02x, %02x, %02x, %02x\n", device, dev_mac[0],dev_mac[1],dev_mac[2],dev_mac[3],dev_mac[4],dev_mac[5]);
	}

	opt_len = 4;
	ret = sapp_get_device_opt(device, SDO_IPV4_ADDR, &dev_ipaddr, &opt_len);
	if(ret < 0){
		printf("sapp_get_device_opt->%s : SDO_IPV4_ADDR error!\n ",device);
	}else{
		char ipstr[16];
		inet_ntop(AF_INET, &dev_ipaddr, ipstr,16);
		printf("sapp_get_device_opt->%s : SDO_IPV4_ADDR: %s\n", device, ipstr);
	}
	opt_len = 4;
	ret = sapp_get_device_opt(device, SDO_MTU, &dev_mtu, &opt_len);	
	if(ret < 0){
		printf("sapp_get_device_opt->%s : SDO_MTU error!\n ", device);
	}else{
		printf("sapp_get_device_opt->%s : SDO_MTU: %d\n", device, dev_mtu);
	}
}

#endif


#if TEST_NETWORK_FLOW
static int check_ipv4_hdr(const struct mesa_ip4_hdr * iph)
{
	int tot_len = ntohs(iph->ip_len);
	
	if (tot_len < (int)sizeof(struct mesa_ip4_hdr) 
		|| iph->ip_hl < 5 
		|| iph->ip_v != 4 
		|| tot_len < iph->ip_hl << 2){	
		return -1;
	}

	switch(iph->ip_p){
		case IPPROTO_IPIP:
		case IPPROTO_ICMP:
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_IPV6:
		case IPPROTO_GRE:
			break;

		default:
			return -1;
	}

	return 0;
}

char testIPFragApp_1(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	static int testcount;
	printf("ip_frag_entry test %d\n",testcount++);
	return APP_STATE_GIVEME;
}

char testIPApp_1(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	static int testcount;
	printf("ip_entry test %d\n",testcount++);
	return APP_STATE_GIVEME;
}

char testIPv6App_1(struct streaminfo *pstream,unsigned char routedir, int thread_seq,void *a_packet)
{
	static int testcount;
	printf("ip_v6 test %d\n",testcount++);
	return APP_STATE_GIVEME;
}

static int test_udp_flow_id = -1;
char testudpApp_1(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct udpdetail *pdetail=(struct udpdetail *)pstream->pdetail;
	struct udp_flow_stat *plug_stat;
	char no_use[65536];

	if(-1 == test_udp_flow_id){
		test_udp_flow_id = project_customer_register(PROJECT_REQ_UDP_FLOW, "struct");
		if(-1 == test_udp_flow_id){
			printf("'udp_flow_stat' is disable, no statistics\n");
		}
	}

        if(pstream->opstate== OP_STATE_PENDING)
        {
test_set_stream_timeout(pstream, pme, thread_seq, a_packet);        
        	plug_stat = (struct udp_flow_stat *)malloc(sizeof(struct udp_flow_stat));
        	memset(plug_stat, 0, sizeof(struct udp_flow_stat));
                *pme=plug_stat;
        }

        plug_stat = (struct udp_flow_stat *)(*pme);

	if(pdetail->datalen > 0){
		if(DIR_C2S == pstream->curdir){
			plug_stat->C2S_byte += pdetail->datalen;
			plug_stat->C2S_pkt++;
		}else{
			plug_stat->S2C_byte += pdetail->datalen;
			plug_stat->S2C_pkt++;
		}
		memcpy(no_use, pdetail->pdata, pdetail->datalen);
	}

	if(pstream->opstate==OP_STATE_CLOSE)
	{
		if(pdetail != NULL){
			printf("%20s: %s, ", "UdpallstreaM-inter", printaddr(&(pstream->addr),	pstream->threadnum));
			printf("server-pkt=%u, server-count=%lu, client-pkt=%u, client-count=%lu, datalen=%u, ",
				pdetail->serverpktnum, pdetail->serverbytes,
				pdetail->clientpktnum,pdetail->clientbytes, pdetail->datalen);
			printf("total-pkt=%d, ", pdetail->serverpktnum + pdetail->clientpktnum);
			printf("total-count=%u\n", pdetail->serverbytes + pdetail->clientbytes);       
		}
		
		printf("%20s: %s, ", "udpallstream-plug", printaddr(&(pstream->addr),	pstream->threadnum));
		printf("server-pkt=%u, server-count=%lu, client-pkt=%u, client-count=%lu, datalen=%u, ",
			plug_stat->C2S_pkt,plug_stat->C2S_byte,
			plug_stat->S2C_pkt,plug_stat->S2C_byte, pdetail->datalen);
		printf("total-pkt=%d, ", plug_stat->C2S_pkt + plug_stat->S2C_pkt);
		printf("total-count=%u\n", plug_stat->C2S_byte+plug_stat->S2C_byte);
                free(*pme);

		struct udp_flow_stat *flow_project = (struct udp_flow_stat *)project_req_get_struct(pstream, test_udp_flow_id);
		if(flow_project != NULL){
			printf("%20s: %s, ", "UdpallstreaM-project", printaddr(&(pstream->addr),	pstream->threadnum));
			printf("server-pkt=%u, server-count=%lu, client-pkt=%u, client-count=%lu, datalen=%u, ",
				flow_project->C2S_pkt,flow_project->C2S_byte,
				flow_project->S2C_pkt,flow_project->S2C_byte, pdetail->datalen);
			printf("total-pkt=%d, ", flow_project->C2S_pkt + flow_project->S2C_pkt);
			printf("total-count=%u\n", flow_project->C2S_byte+flow_project->S2C_byte);       
		}
	}
	return APP_STATE_GIVEME;
	
}

char testudpApp_2(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct udpdetail *pdetail=(struct udpdetail *)pstream->pdetail;
	if(pdetail->clientpktnum >10)
		return APP_STATE_DROPME;
	else 
		return APP_STATE_GIVEME;
	
}

char testtcpApp_1(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;

	if(pdetail->clientpktnum >3)
		return APP_STATE_DROPME;
	else 
		return APP_STATE_GIVEME;
}	

char tcp_data_dump(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	char sip_str[20], dip_str[20];
	char file_name[128];
	if(pstream->opstate== OP_STATE_PENDING){
		inet_ntop(AF_INET, &pstream->addr.tuple4_v4->saddr, sip_str, 20);
		inet_ntop(AF_INET, &pstream->addr.tuple4_v4->daddr, dip_str, 20);
		snprintf(file_name, 128, "%s_%u_%s_%u.T%ld.dump", 
				sip_str, ntohs(pstream->addr.tuple4_v4->source), 
				dip_str, ntohs(pstream->addr.tuple4_v4->dest),
				(long)time(NULL)); 
		*pme = malloc(sizeof(void *));
		*pme = fopen(file_name, "w+");		
	}

	if(NULL == *pme){
		assert(0);
	}
	if(pstream->ptcpdetail->datalen > 0){
		fwrite(pstream->ptcpdetail->pdata, pstream->ptcpdetail->datalen, 1, *pme);
	}

	if(pstream->opstate== OP_STATE_CLOSE){
		fclose(*pme);
	}

	return APP_STATE_GIVEME;
}

char test_print_mac(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{

	if(pstream->opstate== OP_STATE_PENDING)
	{
		printf("tcpstream: %s, ",printaddr(&(pstream->addr),	pstream->threadnum));
		while(pstream){
			if(pstream->addr.addrtype == ADDR_TYPE_MAC){
				struct layer_addr_mac *mac_addr = (struct layer_addr_mac *)pstream->addr.mac;
				printf("smac: %02x-%02x-%02x-%02x-%02x-%02x,  dmac: %02x-%02x-%02x-%02x-%02x-%02x\n",
				         mac_addr->src_mac[0], mac_addr->src_mac[1], mac_addr->src_mac[2], 
				         mac_addr->src_mac[3], mac_addr->src_mac[4], mac_addr->src_mac[5], 
				         mac_addr->dst_mac[0], mac_addr->dst_mac[1], mac_addr->dst_mac[2], 
				         mac_addr->dst_mac[3], mac_addr->dst_mac[4], mac_addr->dst_mac[5]);
				break;
			}else{
				pstream = pstream->pfather;
			}
		}
	}

        return APP_STATE_GIVEME;
}



char testtcpApp_2(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *raw_pdetail=(struct tcpdetail *)pstream->pdetail;
	struct tcp_flow_stat *plug_stat;
	char addr_str_buf[1024];

	if(-1 == test_tcp_flow_id){
		test_tcp_flow_id = project_customer_register("tcp_flow_stat", "struct");
		if(-1 == test_tcp_flow_id){
			printf("'tcp_flow_stat' is disable, no statistics\n");
		}
	}
	
	if(pstream->opstate== OP_STATE_PENDING)
	{
test_set_stream_timeout(pstream, pme, thread_seq, a_packet);   
		plug_stat = (struct tcp_flow_stat *)calloc(1, sizeof(struct tcp_flow_stat));
		*pme = plug_stat;
	}
	plug_stat = (struct tcp_flow_stat *)(*pme);
	
	if(raw_pdetail->datalen > 0){
		if(DIR_C2S == pstream->curdir){
			plug_stat->C2S_data_byte += raw_pdetail->datalen;
			plug_stat->C2S_data_pkt++;
		}else{
			plug_stat->S2C_data_byte += raw_pdetail->datalen;
			plug_stat->S2C_data_pkt++;
		}
	}
	
	if(pstream->opstate== OP_STATE_CLOSE)
	{	
		printf("%17s: %s, ","tcpstream-plug", printaddr(&(pstream->addr),	pstream->threadnum));
		//printf("%17s: %s, ","tcpstream-plug", printaddr_r(&(pstream->addr),	addr_str_buf, 1024));
		printf("opstate=%d, server pkt=%d, count=%d, client pkt=%d, count=%d\n",
			pstream->opstate,
			raw_pdetail->serverpktnum,   raw_pdetail->serverbytes,
			raw_pdetail->clientpktnum,    raw_pdetail->clientbytes);
		free(plug_stat);

		/* 2015-12-29 lijia add */
		struct tcp_flow_stat *tflow_inter = ((struct tcpdetail_private *)pstream->pdetail)->flow_stat;
		if(tflow_inter){
			printf("%17s: %s, ","TcpstreaM-inter", printaddr(&(pstream->addr),	pstream->threadnum));
			printf("opstate=%d, server pkt=%u, count=%lu, client pkt=%u, count=%lu\n",
				pstream->opstate,
				tflow_inter->C2S_data_pkt,tflow_inter->C2S_data_byte,
				tflow_inter->S2C_data_pkt, tflow_inter->S2C_data_byte);		
		}

		if(test_tcp_flow_id != -1){
			/* 2015-12-29 lijia add */
			struct tcp_flow_stat *tflow_project = (struct tcp_flow_stat *)project_req_get_struct(pstream, test_tcp_flow_id);
			if(tflow_project){
				printf("%17s: %s, ", "TcpstreaM-project", printaddr(&(pstream->addr),	pstream->threadnum));
				printf("opstate=%d, server pkt=%u, count=%lu, client pkt=%u, count=%lu\n",
					pstream->opstate,
					tflow_project->C2S_data_pkt,tflow_project->C2S_data_byte,
					tflow_project->S2C_data_pkt, tflow_project->S2C_data_byte);		
			}
		}
	}
        return APP_STATE_GIVEME;
}

static int test_tcpall_flow_id = -1;

char testtcpApp_allpkt(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	struct tcp_flow_stat *tcpallflow;

	if(-1 == test_tcpall_flow_id){
		test_tcpall_flow_id = project_customer_register("tcp_flow_stat", "struct");
		if(-1 == test_tcpall_flow_id){
			printf("'tcp_flow_stat' is disable, no statistics\n");
		}		
	}
	
	if(pstream->pktstate== OP_STATE_PENDING)
	{
		*pme=(void *)malloc(sizeof(struct tcp_flow_stat));
		tcpallflow= (struct tcp_flow_stat *)*pme;
		memset(tcpallflow, 0, sizeof(struct tcp_flow_stat));
	}

	tcpallflow= (struct tcp_flow_stat *)*pme;

	if(a_packet != NULL){
		if(DIR_C2S == pstream->curdir){
			tcpallflow->C2S_all_byte += pdetail->datalen;
			tcpallflow->C2S_all_pkt++;
		}else{
			tcpallflow->S2C_all_byte += pdetail->datalen;
			tcpallflow->S2C_all_pkt++;
		}  		
	}

	if(pstream->pktstate== OP_STATE_CLOSE)
	{	
		printf("%20s: %s, ", "tcpallstream-plug", printaddr(&(pstream->addr),	pstream->threadnum));
		//printf("index=%d,state=%d ",*(int*)((char *)(pstream)-8),*(char *)((char *)(pstream)-4));
		printf("out:%d, pktstate=%d, opstate=%d, server-pkt=%u, server-count=%lu, client-pkt=%u, client-count=%lu, ",
		pdetail_pr->link_state,pstream->pktstate,pstream->opstate,
		tcpallflow->C2S_all_pkt, tcpallflow->C2S_all_byte,
		tcpallflow->S2C_all_pkt, tcpallflow->S2C_all_byte);
		printf("total-pkt=%u, ", tcpallflow->C2S_all_pkt + tcpallflow->S2C_all_pkt);
		printf("total-count=%lu\n", tcpallflow->C2S_all_byte + tcpallflow->S2C_all_byte);
		free(*pme);

		/* 2015-12-29 lijia add */
		struct tcp_flow_stat *tflow_inter = pdetail_pr->flow_stat;
		if(tflow_inter){
			printf("%20s: %s, ", "TcpallstreaM-inter", printaddr(&(pstream->addr),	pstream->threadnum));
			printf("out:%d, pktstate=%d, opstate=%d, server-pkt=%u, server-count=%lu, client-pkt=%u, client-count=%lu, ",
				pdetail_pr->link_state,pstream->pktstate,pstream->opstate,
				tflow_inter->C2S_all_pkt,tflow_inter->C2S_all_byte,
				tflow_inter->S2C_all_pkt, tflow_inter->S2C_all_byte);	
			printf("total-pkt=%u, ", tflow_inter->C2S_all_pkt + tflow_inter->S2C_all_pkt);
			printf("total-count=%lu\n", tflow_inter->C2S_all_byte + tflow_inter->S2C_all_byte);				
		}


		if(-1 != test_tcpall_flow_id){
			/* 2015-12-29 lijia add */
			struct tcp_flow_stat *tflow_project = (struct tcp_flow_stat *)project_req_get_struct(pstream, test_tcpall_flow_id);
			if(tflow_project){
				printf("%20s: %s, ", "TcpallstreaM-project", printaddr(&(pstream->addr),	pstream->threadnum));
				printf("out:%d, pktstate=%d, opstate=%d, server-pkt=%u, server-count=%lu, client-pkt=%u, client-count=%lu, ",
					pdetail_pr->link_state,pstream->pktstate,pstream->opstate,
					tflow_project->C2S_all_pkt,tflow_project->C2S_all_byte,
					tflow_project->S2C_all_pkt, tflow_project->S2C_all_byte);	
				printf("total-pkt=%u, ", tflow_project->C2S_all_pkt + tflow_project->S2C_all_pkt);
				printf("total-count=%lu\n", tflow_project->C2S_all_byte + tflow_project->S2C_all_byte);				
			}
		}
	}
        return APP_STATE_GIVEME;
}

char tcpall_valid_after_kill(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	unsigned char mopt = 1;

	MESA_kill_tcp(pstream, a_packet);
	
	if(pstream->pktstate== OP_STATE_PENDING){
		if(MESA_set_stream_opt(pstream, MSO_TCPALL_VALID_AFTER_KILL, &mopt, sizeof(mopt)) < 0){
			abort();
		}
	}

	return testtcpApp_allpkt(pstream, pme, thread_seq, a_packet);
}

struct stream_static
{
   int pktnum;
   int iplen;
   int payloadlen;
};

char test_allpkt_v4_len(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet,char checklen)
{
        struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
        struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	struct ip *this_iphdr =(struct ip *) a_packet;
	struct	tcphdr *this_tcphdr =NULL;
	struct udphdr *udph =NULL;
	int datalen, iplen;
	struct stream_static *p=NULL;
	char type=pstream->type;
	char opstate;
	int isprint=1;

	if(a_packet && (check_ipv4_hdr((const struct mesa_ip4_hdr *)this_iphdr) < 0)){
		return APP_STATE_GIVEME;
	}
	if(type==STREAM_TYPE_TCP)
		opstate=pstream->pktstate;
	else
		opstate=pstream->opstate;
        if(opstate== OP_STATE_PENDING)
        {
                *pme=(void *)malloc(sizeof(struct stream_static));
                p=(struct stream_static *)(*pme);
                memset(p,0,sizeof(struct stream_static));
		
        }
        else
        {
                p=(struct stream_static *)(*pme);
        }

	if(this_iphdr!=NULL)
	{
		iplen = ntohs (this_iphdr->ip_len);
		if(this_iphdr->ip_p== IPPROTO_TCP)
		{
			this_tcphdr = (struct tcphdr *) ((char *)a_packet + 4 * this_iphdr->ip_hl);
			datalen = iplen - 4 * this_iphdr->ip_hl - 4 * this_tcphdr->doff;
		}
		else
		{
			udph = (struct udphdr *) ((char*)a_packet +4 * this_iphdr->ip_hl );
			datalen = ntohs (udph->len)- sizeof (struct udphdr);
		}
		p->payloadlen+=datalen;
		p->pktnum++;
		p->iplen+=iplen;
 	}
        if(opstate== OP_STATE_CLOSE)
        {
		if(checklen)
		{
		 if(((pdetail->serverbytes+pdetail->clientbytes) != (p->payloadlen))
			||((pdetail->serverpktnum+pdetail->clientpktnum)!=(p->pktnum)))
		  isprint=1;
		 else
		  isprint=0;
        	}
		if(isprint==1)
		{
		  if(type==STREAM_TYPE_TCP) 
			printf("tcpallstream:");
		  else 
			printf("udpallstream:");
		 printf(" %s ",printaddr(&(pstream->addr),  pstream->threadnum));
                //printf("index=%d,state=%d ",*(int*)((char *)(pstream)-8),*(char *)((char *)(pstream)-4));
                printf("out:%d,pktstate=%d,opstate=%d,server pkt=%d, count=%d,client pkt=%d,count=%d, datalen=%d,lostlen=%d",
                pdetail_pr->link_state,pstream->pktstate,pstream->opstate,pdetail->serverpktnum,pdetail->serverbytes,
                pdetail->clientpktnum,pdetail->clientbytes,pdetail->datalen,pdetail->lostlen);
                printf(" \t total pkt= %d,datalen=%d",(p->pktnum),p->payloadlen);
                printf("\n");
		}
                free(*pme);
        }
        return APP_STATE_GIVEME;
}

char test_allpkt_stream(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
  return test_allpkt_v4_len(pstream,pme, thread_seq,a_packet,0);
}

char test_allpkt_stream_checklen(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
  return test_allpkt_v4_len(pstream,pme, thread_seq,a_packet,1);
}

char testtcpApp_takeover(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;

	if(pdetail->clientpktnum >3)
	{
		tcp_set_single_stream_takeoverflag(pstream, TCP_TAKEOVER_STATE_FLAG_ON);
	}

	
        return APP_STATE_GIVEME;
}

static char test_project_read_ipv4_frag_list(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	raw_ipfrag_list_t *frag_head, *tmp;
	
	if(0 == __init_flag){
		project_id = project_customer_register("ipv4_frag_list", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			printf("test_project_add error, 'ipv4_frag_list' is not enable!\n");
			exit(0);
		}
		__init_flag = 1;
	}
	
	if(OP_STATE_DATA == pstream->opstate){
		frag_head = (raw_ipfrag_list_t *)project_req_get_struct(pstream, project_id);		
		if(frag_head){
			printf("stream-%p frag len: ", pstream);
			while(frag_head){
				tmp = frag_head->next;
				printf("%d, ",  frag_head->pkt_len);
				frag_head = tmp;
			}
			printf("\n");
		}
	}

	return APP_STATE_GIVEME;
}

static void __test_project_cb(int thread_seq, void *project_req_value)
{
	return;
}

static void print_tuple4(struct streaminfo *stream)
{
	if(ADDR_TYPE_IPV4 == stream->addr.addrtype){
		char ip1[16], ip2[16];
		struct stream_tuple4_v4 *tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.paddr);
		inet_ntop(AF_INET, &tuple_v4->saddr, ip1, 16);
		inet_ntop(AF_INET, &tuple_v4->daddr, ip2, 16);
		printf("tuple4_v4 is:%s:%u -- %s:%u\n", ip1, ntohs(tuple_v4->source),
			 ip2, ntohs(tuple_v4->dest));
	}else{
		char ip1[128], ip2[128];
		struct stream_tuple4_v6 *tuple_v6 = (struct stream_tuple4_v6 *)(stream->addr.paddr);;
		inet_ntop(AF_INET6, tuple_v6->saddr, ip1, 128);
		inet_ntop(AF_INET6, tuple_v6->daddr, ip2, 128);
		printf("tuple4_v6 is:%s:%u -- %s:%u\n", ip1, ntohs(tuple_v6->source),
			 ip2, ntohs(tuple_v6->dest));
	}

}

/* 返回值 1:是自己的包  0:不是自己的包  -1:输入数据错误 */
static int check_rst_ip_new (unsigned int dip_net_order,unsigned short dport_net_order, unsigned short ipid_host_order, 
					unsigned short win_host_order, int iMaxRandVal, int iRandKey)
{

	if((iMaxRandVal -ipid_host_order + dip_net_order%iRandKey) % iRandKey != 0){
		return 0;
	}

	if((iMaxRandVal -win_host_order + dport_net_order%iRandKey) % iRandKey != 0){
		return 0;
	}
	
	return 1;
}

/* 返回值 1:是自己的包  0:不是自己的包  -1:输入数据错误 */
static int check_rst_ip_old (unsigned int sip_net_order, unsigned int dip_net_order, unsigned short ipid, 
					unsigned short window, int iMaxRandVal, int iRandKey)
{
        unsigned short window_compute;
        if (sip_net_order == INADDR_NONE) {
                fprintf (stderr, "source IP wrong.\n");
                return -1;
        }
        if (dip_net_order == INADDR_NONE) {
                fprintf (stderr, "destination IP wrong.\n");
                return -1;
        }

        if (window == 0)
                return 0;

        if ((iMaxRandVal - ipid + sip_net_order%window)%iRandKey != 0) // 必须整除才行
                return 0;
        int val = (iMaxRandVal - ipid + sip_net_order%window)/iRandKey;
        window_compute = (unsigned short)(val+dip_net_order%iRandKey);
        if (window == 0 )
                return 0;
        if (window == 1 ) {
                if (window_compute == 0 || window_compute == 1 )
                        return 1;
        }
        if (window == window_compute) { // 若相等，则表明可能是自己产生的
                return 1;
        }
        return 0;
}

static char test_rst_pkt(struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *void_pkt)
{
	const raw_pkt_t *real_raw_pkt = (const raw_pkt_t *)void_pkt;
	const struct mesa_ip4_hdr *ip4_hdr;
	const struct mesa_tcp_hdr *tcp_hdr;

	ip4_hdr = (const struct mesa_ip4_hdr *)MESA_net_jump_to_layer((const void *)real_raw_pkt->raw_pkt_data, real_raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if(NULL == ip4_hdr){
		return 1;
	}
	
	tcp_hdr = (const struct mesa_tcp_hdr *)((char *)ip4_hdr + ip4_hdr->ip_hl * 4);
	if((tcp_hdr->th_flags & TH_RST) == 0){
		return 1;
	}

	if(check_rst_ip_old(ip4_hdr->ip_src.s_addr, ip4_hdr->ip_dst.s_addr, ntohs(ip4_hdr->ip_id),ntohs(tcp_hdr->th_win), 65535, 13) == 1){
		printf("@@@MESA RST pkt!\n");
	}else{
		printf("### recv RST, but not MESA RST pkt!\n");
	}

	return 1;
}



char test_ipv4_frag(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv4_hdr)
{
	static long ip_pkt_tot = 0;
	const struct mesa_ip4_hdr *ip4hdr = (const struct mesa_ip4_hdr *)ipv4_hdr;
	unsigned short offset, flags;
	
	/*See, is this a fragment*/
	offset = ntohs(ip4hdr->ip_off);
	flags = offset & ~IPv4_FRAG_OFFSET;
	offset &= IPv4_FRAG_OFFSET;

	
	if(((flags & IPv4_FRAG_MF) != 0) || (offset != 0)) {
		//printf("recv a ipv4 frag pkt!\n");
	}

	/* ffff.pcap, 5698811 */
	ip_pkt_tot++;
	if(ip_pkt_tot > 5680000){
		printf("recv ip pkt tot:%ld\n", ip_pkt_tot);
	}
	
	return APP_STATE_GIVEME;	
}

char test_ipv6_frag(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,  const void *ipv4_hdr)
{
	printf("recv a ipv6 frag pkt!\n");
	return APP_STATE_GIVEME;	
}


char test_layer_addr_prefix_ntop(const struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char addr_ntop_str_r[4096];
	char *addr_ntop_str;
	const char *addr_type_ntop_str;
	const struct streaminfo *tmp = stream;
	
	if(OP_STATE_PENDING == stream->opstate){

		while(tmp != NULL){
			addr_type_ntop_str = layer_addr_prefix_ntop(tmp);
			printf("%s ",  addr_type_ntop_str);		
			tmp = tmp->pfather;
		}
		printf("\n");
	}
	return APP_STATE_GIVEME;
}


char test_get_rawpkt_options(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int ret;
	int gdev_ip;
	int vxlan_id;
	int vpn_id;
	unsigned short vxlan_sport;
	unsigned char service_id;
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_GDEV_IP, &gdev_ip);
	if(ret >= 0){
		char tmp_ip_str[32];
		inet_ntop(AF_INET, &gdev_ip, tmp_ip_str, 32);
		printf("[debug], test_get_rawpkt_options get gdev-ip:%s\n", tmp_ip_str);
	}else{
		printf("[error], test_get_rawpkt_options GDEV_IP error\n");
	}

	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_ID, &vxlan_id);
	if(ret >= 0){
		printf("[debug], test_get_rawpkt_options get vlan-id:%d\n", vxlan_id);
	}else{
		printf("[error], test_get_rawpkt_options VXLAN_ID error\n");
	}

	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_VPNID, &vpn_id);
	if(ret >= 0){
		printf("[debug], test_get_rawpkt_options get VPNID:%d\n", ntohl(vpn_id)); /* to host order */
	}else{
		printf("[error], test_get_rawpkt_options VPNID error\n");
	}
	
	service_id = vxlan_id_map_to_service_id(ntohl(vxlan_id));
	printf("service id from vxlan_id: %u\n", service_id);
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_SPORT, &vxlan_sport);
	if(ret >= 0){
		printf("[debug], test_get_rawpkt_options get sport:%u\n", ntohs(vxlan_sport));
	}else{
		printf("[error], test_get_rawpkt_options VXLAN_SPORT error\n");
	}

	service_id = vxlan_sport_map_to_service_id(ntohs(vxlan_sport));
	printf("service id from sport: %u\n", service_id);
	
	return APP_STATE_GIVEME;
}



char test_inet_addr_list_addr(const struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int ret;
	char addr_list_str[4096];
	char addr_list_str_recover[4096];
	struct streaminfo recover_stream[32];
	
	if(OP_STATE_CLOSE == stream->opstate){
		ret = stream_addr_list_ntop(stream, addr_list_str, 4096);
		if(ret < 0){
			printf("stream_addr_list_ntop ret = %d\n", ret);
			assert(0);
		}
		printf("    raw-addr-list len is:\t%d, value:\t%s\n", ret, addr_list_str);
		ret = stream_addr_list_pton(addr_list_str, recover_stream, sizeof(struct streaminfo)*32, stream->threadnum);
		if(ret < 0){
			printf("stream_addr_list_pton ret = %d\n", ret);
			assert(0);
		}		

		assert(thread_seq == recover_stream[0].threadnum);

		ret =  stream_addr_list_ntop(recover_stream, addr_list_str_recover, 4096);
		if(ret < 0){
			printf("stream_addr_list_ntop ret = %d\n", ret);
			assert(0);
		}		
		printf("recover-addr-list len is:\t%d, value:\t%s\n", ret, addr_list_str_recover);

		if(strncasecmp(addr_list_str, addr_list_str_recover, 4096) != 0){
			printf("stream_addr_list not name!\n");
		}
	}

	return APP_STATE_GIVEME;
}

char test_kill_tunnel_ip_entry( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	char ret = APP_STATE_GIVEME;
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	
	switch(a_packet->ip_p){
		case IPPROTO_GRE:
		case IPPROTO_IPIP:
		case IPPROTO_IPV6:
		case IPPROTO_ESP:
		case IPPROTO_AH:
		case IPPROTO_L2TPV3:
			ret |= APP_STATE_DROPPKT;
		break;

		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMP:
		break;

		default:
			ret |= APP_STATE_DROPPKT;
		break;
	}

	return ret;
}

char test_kill_tunnel(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char kill_flag = 0;
	char ret = APP_STATE_GIVEME;
	
	if(stream->pfather->addr.addrtype != ADDR_TYPE_MAC) {
		if(STREAM_TYPE_TCP == stream->type){
			MESA_kill_tcp(stream, raw_pkt);
		}
		kill_flag = 1;
	}

	if(STREAM_TYPE_OPENVPN == stream->pfather->type){
		if(STREAM_TYPE_TCP == stream->type){
			MESA_kill_tcp(stream, raw_pkt);
		}
		kill_flag = 1;
	}

	if(kill_flag){
		ret |= APP_STATE_DROPPKT;
	}

	return ret;
}

char test_kill_connection( struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char ip1[16], ip2[16];
	struct stream_tuple4_v4 *tuple_v4;

	if(OP_STATE_DATA != stream->opstate){ /* 只在DATA状态调用KILL */
		return APP_STATE_GIVEME;
	}

	tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.tuple4_v4);
	
	// for test MESA_kill_tcp
	//if((0xC0A80A9F) == ntohl(tuple_v4->daddr)
	 //|| (0xC0A80A9F) == ntohl(tuple_v4->saddr))
	{
		if(1){
			inet_ntop(AF_INET, &tuple_v4->saddr, ip1, 16);
			inet_ntop(AF_INET, &tuple_v4->daddr, ip2, 16);
			MESA_kill_connection((struct streaminfo *)stream, raw_pkt);
			printf("Kill connection: ,%s:%u -- %s:%u\n", ip1, ntohs(tuple_v4->source),
				 ip2, ntohs(tuple_v4->dest));
		}
	}
	
	return APP_STATE_GIVEME;
}


char test_kill_tcp_syn_ack(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	//struct layer_addr *tuple;
	char ip1[16], ip2[16];
	struct stream_tuple4_v4 *tuple_v4;

	if(OP_STATE_DATA != stream->opstate){
		return APP_STATE_GIVEME;
	}
	
	tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.paddr);
	
	// for test MESA_kill_tcp
		if(1){
			inet_ntop(AF_INET, &tuple_v4->saddr, ip1, 16);
			inet_ntop(AF_INET, &tuple_v4->daddr, ip2, 16);
			MESA_kill_tcp_synack(stream, raw_pkt);
			printf("Send fake SYN/ACK: ,%s:%u -- %s:%u\n", ip1, ntohs(tuple_v4->source),
				 ip2, ntohs(tuple_v4->dest));
		}
	
	return APP_STATE_GIVEME;
}

char test_send_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	struct ip *iphdr;
	if(OP_STATE_DATA != stream->opstate){
		return APP_STATE_GIVEME;
	}

	iphdr = (struct ip *)raw_pkt;
	if(iphdr->ip_v != 4){
		printf("not ipv4!\n");
	}
	MESA_sendpacket_ethlayer(stream->threadnum, (char *)raw_pkt-14, 14+ntohs(iphdr->ip_len), 0);

	return APP_STATE_GIVEME;
}

char test_send_iplayer_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	//struct ip *iphdr;
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_data[] = 
	{
		0x45,0x00,0x00,0x54,0x00,0x00,0x40,0x00,
		0x40,0x01,0x19,0xF9,0x0A,0x0A,0x06,0x6C,
		0x0A,0x00,0x06,0x3B,
		0x08,0x00,0xC2,0x6A,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x22,0x5C,0x06,
		0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

	MESA_sendpacket_iplayer(stream->threadnum, (char *)snd_pkt_data, sizeof(snd_pkt_data), 0);

	return APP_STATE_GIVEME;
}

char test_sendfake_ipv4_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	/* ICMP request, from 10.10.6.108 to 10.0.6.59 */
	char snd_pkt_payload[] = 
	{
		0x08,0x00,0xD9,0x71,0x18,0x8B,0x00,0x07,
		0xE5,0xB8,0xA8,0x54,0x00,0x00,0x00,0x00,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
	};

	MESA_fakepacket_send_ipv4(stream->threadnum, 128, 1, 0x0A0A066C, 0x0A00063B, 
							snd_pkt_payload, sizeof(snd_pkt_payload), 0);

	return APP_STATE_GIVEME;
}

char test_sendfake_tcp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	MESA_fakepacket_send_tcp(stream->threadnum, 0x0A0A066C, 0x0A00063B, 0x1111,0x2222,
							0x12345678, 0x87654321, 0x10, "TCP payload test", strlen("TCP payload test"), 0);	
	return APP_STATE_GIVEME;
}

char test_sendfake_udp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	MESA_fakepacket_send_udp(stream->threadnum, 0x0A0A066C, 0x0A00063B, 0x1111,0x2222,
							"UDP payload test", strlen("UDP payload test"), 0);	
	return APP_STATE_GIVEME;
}


char test_inject_tcp_pkt(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	char fake_http_data[] = "HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=UTF-8\r\nContent-Language: zh-CN\r\nContent-Length: 32\r\nDate: Tue, 09 Sep 2014 08:21:07 GMT\r\n\r\n<html><head>hahaha</head></html>";
	//struct layer_addr *tuple;
	char ip1[16], ip2[16];
	struct stream_tuple4_v4 *tuple_v4;

	if(OP_STATE_CLOSE == stream->opstate){
		return APP_STATE_DROPME;
	}

	tuple_v4 = (struct stream_tuple4_v4 *)(stream->addr.paddr);
	
	// for test MESA_kill_tcp
	//if(((0xC0A80A9F) == ntohl(tuple_v4->daddr) || (0xC0A80A9F) == ntohl(tuple_v4->saddr))
	 //&& ((80 == ntohs(tuple_v4->source)) ||(80 == ntohs(tuple_v4->dest))))
	 {
		//if(DIR_C2S == stream->curdir)
		{
			inet_ntop(AF_INET, &tuple_v4->saddr, ip1, 16);
			inet_ntop(AF_INET, &tuple_v4->daddr, ip2, 16);
			MESA_inject_pkt(stream, fake_http_data, strlen(fake_http_data), raw_pkt, stream->routedir^1);
			printf("MESA inject : ,%s:%u -- %s:%u\n", ip1, ntohs(tuple_v4->source),
				 ip2, ntohs(tuple_v4->dest));
		}
	}
	
	return APP_STATE_DROPME;
}

char test_20140731(struct streaminfo *pstream,void **pme, int thread_seq,const void *raw_pkt)
{
	static int __tot_c2s_pkt = 0;
	static int __tot_s2c_pkt = 0;
	static int __tot_s2c_len = 0;
	static int __tot_c2s_len = 0;
	struct tcpdetail *a_tcp = (struct tcpdetail *)pstream->pdetail;

	/* 2014-07-31, lijia add for test, 设置不同的unorder值, 最终获取的数据可能不一样 */
	tcp_set_single_stream_max_unorder(pstream, DIR_DOUBLE, 1);

	if(a_tcp->datalen <= 0){
		return APP_STATE_GIVEME;
	}
	
	if(DIR_C2S == pstream->curdir){
		__tot_c2s_pkt++;	
		__tot_c2s_len += a_tcp->datalen;	
	}else{
		__tot_s2c_pkt++;	
		__tot_s2c_len += a_tcp->datalen;	
	}

	printf("tot pkt: C2S:%6d, S2C:%6d\n", __tot_c2s_pkt, __tot_s2c_pkt);
	printf("tot len: C2S:%6d, S2C:%6d\n\n", __tot_c2s_len, __tot_s2c_len);

	return APP_STATE_GIVEME;
}


char test_project_add(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	char *pro_value = (char *)"test project!";

	if(0 == __init_flag){
		project_id = project_producer_register("test_project", PROJECT_VAL_TYPE_STRUCT, __test_project_cb);
		if(project_id < 0){
			printf("test_project_add error, 'test_project' is not enable!\n");
			exit(0);
		}
		__init_flag = 1;
	}
	
	if(OP_STATE_PENDING == pstream->opstate){
		project_req_add_struct(pstream, project_id, pro_value);		
	}

	return APP_STATE_GIVEME;
}

char test_project_read(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	char *pro_value;
	
	if(0 == __init_flag){
		project_id = project_customer_register("test_project", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			printf("test_project_add error, 'test_project' is not enable!\n");
			exit(0);
		}
		__init_flag = 1;
	}
	
	if(OP_STATE_DATA == pstream->opstate){
		pro_value = (char *)project_req_get_struct(pstream, project_id);	
		printf("### get project : %s\n", pro_value);
	}

	return APP_STATE_GIVEME;
}


char test_project_read_ipv6_frag_list(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	static int __init_flag = 0;
	static int project_id;
	raw_ipfrag_list_t *frag_head, *tmp;
	
	if(0 == __init_flag){
		project_id = project_customer_register("ipv6_frag_list", PROJECT_VAL_TYPE_STRUCT);
		if(project_id < 0){
			printf("test_project_add error, 'ipv6_frag_list' is not enable!\n");
			exit(0);
		}
		__init_flag = 1;
	}
	
	if(OP_STATE_DATA == pstream->opstate){
		frag_head = (raw_ipfrag_list_t *)project_req_get_struct(pstream, project_id);		
		if(frag_head){
			printf("stream-%p frag len: ", pstream);
			while(frag_head){
				tmp = frag_head->next;
				printf("%d, ",  frag_head->pkt_len);
				frag_head = tmp;
			}
			printf("\n");
		}
	}

	return APP_STATE_GIVEME;
}

void print_stream_list(const struct streaminfo *pstream)
{
	int i, level = 1;
	const struct streaminfo *pfather;
	while(pstream){
		pfather = pstream->pfather;
		for(i = 0; i < level; i++){
			printf("    ");
		}
		printf("stream:%p, stream-type:%d, addr-type:%d\n", pstream, pstream->type, pstream->addr.addrtype);
		pstream = pfather;
		level++;
	}

	return;
}

char test_proxy_cb(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	struct tcpdetail *a_tcp;
	//int addr_type;
	//void *tuple4;
	//int project_req_id;
	long stream_id;

	if(OP_STATE_PENDING == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
		//printf("######### %p, %x\n", a_tcp->pdata, ((char *)a_tcp->pdata)[0]);
		//print_tuple4(pstream);
		printf("into test_proxy_cb----------\n");
		print_stream_list(pstream);
		write(1, a_tcp->pdata, a_tcp->datalen);
		//printf("test_tcp_cb-pending: stream:%p, %s, len:%d\n", pstream, printaddr(&pstream->addr, pstream->threadnum), a_tcp->datalen);
	}else if (OP_STATE_DATA == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
		//printf("test_tcp_cb-data: %s, len:%d\n", printaddr(&pstream->addr, pstream->threadnum), a_tcp->datalen );
	}else if(OP_STATE_CLOSE == pstream->opstate){
		printf("test_tcp_cb-close: strem %s\n", printaddr(&pstream->addr, pstream->threadnum));
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}

char test_tcp_cb(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	struct tcpdetail *a_tcp;
	//int addr_type;
	//void *tuple4;

	if(OP_STATE_PENDING == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
		//printf("######### %p, %x\n", a_tcp->pdata, ((char *)a_tcp->pdata)[0]);
		//print_tuple4(pstream);
		printf("test_tcp_cb-pending: stream:%p, %s, len:%d\n", pstream, printaddr(&pstream->addr, pstream->threadnum), a_tcp->datalen);
		
		//printf("cb(): recv a new tcp connection, %p, streamid is %ld, total stream num is:%ld!\n", pstream, stream_id, ++stream_num);
		//printf("cb(): recv %d data from %p!\n", a_tcp->datalen, pstream);
	}else if (OP_STATE_DATA == pstream->opstate){
		a_tcp = (struct tcpdetail *)pstream->pdetail;
		//printf("cb(): recv %d data from %p!\n", a_tcp->datalen, pstream);
		//write(1, a_tcp->pdata, a_tcp->datalen);
		//print_tuple4(pstream);
		//printf("test_tcp_cb-data: %s, len:%d\n", printaddr(&pstream->addr, pstream->threadnum), a_tcp->datalen );
	}else if(OP_STATE_CLOSE == pstream->opstate){
		printf("test_tcp_cb-close: strem %s\n", printaddr(&pstream->addr, pstream->threadnum));
		//print_tuple4(pstream);
		return APP_STATE_DROPME;
	}

	return APP_STATE_GIVEME;
}

char test_udp_cb(struct streaminfo *pstream,void **pme, int thread_seq,const void *a_packet)
{
	if(OP_STATE_PENDING == pstream->opstate){
		printf("udp-pending: %s\n", printaddr(&pstream->addr, pstream->threadnum));
	}else if (OP_STATE_DATA == pstream->opstate){
		//printf("udp-data: %s\n", printaddr(&pstream->addr, pstream->threadnum));
	}else if(OP_STATE_CLOSE == pstream->opstate){
		printf("udp-close: %s\n", printaddr(&pstream->addr, pstream->threadnum));
		return APP_STATE_DROPME;
	}
	
	return APP_STATE_GIVEME;
}

void test_project_tcp_free_cb(int thread_seq, void *project_req_value)
{
//	printf(" ### test_project_tcp_free_cb()\n");
	free(project_req_value);
}

char test_project(struct streaminfo *pstream,void **pme, int thread_seq,const raw_pkt_t *raw_pkt)
{
	static int project_id = -999;
	void *value;

	if(-999 == project_id){
		project_id = project_producer_register("test_project", "struct", test_project_tcp_free_cb);
		if(project_id < 0){
			printf("project_producer_register 'test_project' fail!\n");
		}else{
//			printf("project_req_register OK, id = %d!\n", project_id);
		}
	}

	if(OP_STATE_PENDING == pstream->opstate){
		value = malloc(100);
		strncpy((char *)value, "hello, project", 100);
//		printf("add project %p value\n", pstream);
		project_req_add_struct(pstream, project_id, value);
	}else{
		value = (void *)project_req_get_struct(pstream, 	project_id);
 		printf("get progect %p value is:%s\n", pstream, (char *)value);
	}
	
	return APP_STATE_GIVEME;
}


char test_project_terminal_tag(struct streaminfo *pstream,void **pme, int thread_seq,const raw_pkt_t *raw_pkt)
{
	static int project_id = -123;
	char *value;

	if(-123 == project_id){
		project_id = project_customer_register("terminal_tag", "struct");
		if(project_id < 0){
			printf("project_customer_register 'terminal_tag' fail!\n");
		}else{
//			printf("project_req_register OK, id = %d!\n", project_id);
		}
	}

	if(OP_STATE_DATA== pstream->opstate){
		value = (char *)project_req_get_struct(pstream, 	project_id);
		if(value){
 			printf("get terminal_tag %p value is:%s\n", pstream, value);
 		}else{
			printf("can't get terminal_tag %p \n", pstream);
 		}
	}
	
	return APP_STATE_GIVEME;
}

char print_udp_checksum(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	if(NULL == a_packet){
		return APP_STATE_GIVEME;
	}
	
	const struct mesa_ip4_hdr *iph = (const struct mesa_ip4_hdr *)a_packet;
	const struct mesa_udp_hdr *udph = (struct mesa_udp_hdr *)((char *)a_packet + iph->ip_hl * 4);	

	printf("%u\n", udph->uh_sum);

	return APP_STATE_GIVEME;
}
int test_pkt_handle(const unsigned char *data, int datalen, int dir, int thread_num)
{
	printf("tid:%d, recv a new pkt!\n", thread_num);

	return 0;
}

static int __checkip4pkt(const struct mesa_ip4_hdr * iph)
{
	int tot_len = ntohs(iph->ip_len);
	
	if (tot_len < (int)sizeof(struct mesa_ip4_hdr) 
		|| iph->ip_hl < 5 
		|| iph->ip_v != 4 
		|| tot_len < iph->ip_hl << 2){	
		return -1;
	}

	switch(iph->ip_p){
		case IPPROTO_IPIP:
		case IPPROTO_ICMP:
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_IPV6:
		case IPPROTO_GRE:
			break;

		default:
			return -1;
	}

	return 0;
}

static int __checkip6pkt(const struct mesa_ip6_hdr * iph)
{
	if((iph->ip6_flags[0] & 0xF0) != 0x60){
		return -1;
	}
	
	switch(iph->ip6_nxt_hdr){
		case  NEXTHDR_HOP			:  
		case  NEXTHDR_TCP			:  
		case  NEXTHDR_UDP			:  
		case  NEXTHDR_IPV6			:
		case  NEXTHDR_ROUTING		:  
		case  NEXTHDR_FRAGMENT	:
		case  NEXTHDR_ESP			:  
		case  NEXTHDR_AUTH		:
		case  NEXTHDR_ICMP			:
		case  NEXTHDR_NONE		:
		case  NEXTHDR_DEST			:
		case  NEXTHDR_MOBILITY	:
			break;

		default:
			return -1;
	}

	return 0;
}

char test_jump_layer(struct streaminfo *f_stream,unsigned char routedir,int thread_seq, const void *arg)
{
	const raw_pkt_t *raw_pkt = ((struct streaminfo_private*)f_stream)->raw_pkt;

	if(NULL == raw_pkt){
		return 0;
	}

#if 0
	const struct mesa_arp_hdr *arphdr = (const struct mesa_arp_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, ADDR_TYPE_ARP);
	if(arphdr){
		printf("jump to ARP OK!\n");
	}
#endif

#if 0
	const struct mesa_ip4_hdr * iphdr = (const struct mesa_ip4_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, ADDR_TYPE_IPV4);
	if(iphdr){
		if(__checkip4pkt(iphdr) < 0){
			assert(0);
		}else{
			printf("%s:%d: jump to ipv4 OK!\n", __FILE__, __LINE__);
		}
	}
#endif

#if 0
	const struct mesa_ip6_hdr * ip6hdr = (const struct mesa_ip6_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, ADDR_TYPE_IPV6);
	if(ip6hdr){
		if(__checkip6pkt(ip6hdr) < 0){
			assert(0);
		}else{
			printf("jump to ipv6 OK!\n");
		}
	}
#endif

#if 0
	const struct mesa_udp_hdr * udphdr =  (const struct mesa_udp_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, ADDR_TYPE_UDP);
	if(udphdr){
		printf("jump to UDP OK!\n");
	}	
#endif

#if 0
	const struct mesa_tcp_hdr * tcphdr =  (const struct mesa_tcp_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, ADDR_TYPE_TCP);
	if(tcphdr){
		printf("jump to TCP OK!\n");
	}	
#endif

	const struct mesa_ip4_hdr * iphdr, *iphdr_greedy;
	const struct mesa_ip6_hdr * ip6hdr, *ip6hdr_greedy;
	char ipsrc[64], ipdst[64];
	char ipsrc_greedy[64], ipdst_greedy[64];

	ipsrc[0] = '\0';
	ipdst[0] = '\0';
	ipsrc_greedy[0] = '\0';
	ipdst_greedy[0] = '\0';

	iphdr = (const struct mesa_ip4_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if(iphdr){
		inet_ntop(AF_INET, &iphdr->ip_src.s_addr, ipsrc, 64);
		inet_ntop(AF_INET, &iphdr->ip_dst.s_addr, ipdst, 64);
	}
	iphdr_greedy = (const struct mesa_ip4_hdr *)MESA_net_jump_to_layer_greedy(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V4);
	if(iphdr_greedy){
		inet_ntop(AF_INET, &iphdr_greedy->ip_src.s_addr, ipsrc_greedy, 64);
		inet_ntop(AF_INET, &iphdr_greedy->ip_dst.s_addr, ipdst_greedy, 64);
	}
	if(iphdr || iphdr_greedy){
		printf("jump to ip4hdr:%s-%s, greedy jump ip4hdr:%s-%s\n", ipsrc, ipdst, ipsrc_greedy, ipdst_greedy);
	}

	ipsrc[0] = '\0';
	ipdst[0] = '\0';
	ipsrc_greedy[0] = '\0';
	ipdst_greedy[0] = '\0';

	ip6hdr = (const struct mesa_ip6_hdr *)MESA_net_jump_to_layer(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V6);
	if(ip6hdr){
		inet_ntop(AF_INET6, &ip6hdr->ip6_src, ipsrc, 64);
		inet_ntop(AF_INET6, &ip6hdr->ip6_dst, ipdst, 64);
	}
	ip6hdr_greedy = (const struct mesa_ip6_hdr *)MESA_net_jump_to_layer_greedy(raw_pkt->raw_pkt_data, raw_pkt->low_layer_type, __ADDR_TYPE_IP_PAIR_V6);
	if(ip6hdr_greedy){
		inet_ntop(AF_INET6, &ip6hdr_greedy->ip6_src, ipsrc_greedy, 64);
		inet_ntop(AF_INET6, &ip6hdr_greedy->ip6_dst, ipdst_greedy, 64);
	}
	if(ip6hdr || ip6hdr_greedy){
		printf("jump to ip6hdr:%s-%s, greedy jump ip6hdr:%s-%s\n", ipsrc, ipdst, ipsrc_greedy, ipdst_greedy);
	}

	return APP_STATE_GIVEME;
}

char test_get_opt_from_rawpkt( const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt, void **pme)
{
	void *this_layer_hdr = NULL, *raw_pkt_hdr = NULL;
	int tot_len = -1, this_layer_remain_len = -1;

	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_DATA, &raw_pkt_hdr);
	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_TOT_LEN, &tot_len);
	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_THIS_LAYER_HDR, &this_layer_hdr);	
	get_opt_from_rawpkt(raw_pkt, RAW_PKT_GET_THIS_LAYER_REMAIN_LEN, &this_layer_remain_len);

	printf("get opt from rawpkt: totlen:%d, remain_len:%d, raw_hdr:%p, this_hader:%p\n",
		tot_len, this_layer_remain_len, raw_pkt_hdr, this_layer_hdr);

	return APP_STATE_GIVEME;	
}

char test_get_rawpkt_opt_from_streaminfo(struct streaminfo *f_stream,unsigned char routedir,int thread_seq, const void *voidpkt)
{
	void *this_layer_hdr = NULL, *raw_pkt_hdr = NULL;
	int tot_len = -1, this_layer_remain_len = -1;
	int ret;

	ret = get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_DATA, &raw_pkt_hdr);
	if(ret == 1){
		raw_ipfrag_list_t *tlist = raw_pkt_hdr;
		while(tlist){
			printf("pkt len:%d\n", tlist->pkt_len);
			tlist = tlist->next;
		}
	}
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_TOT_LEN, &tot_len);
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_THIS_LAYER_HDR, &this_layer_hdr);	
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_THIS_LAYER_REMAIN_LEN, &this_layer_remain_len);

	printf("get opt from rawpkt: totlen:%d, remain_len:%d, raw_hdr:%p, this_hader:%p\n",
		tot_len, this_layer_remain_len, raw_pkt_hdr, this_layer_hdr);
	int gdev_ip = 0;
	char gdev_ip_str[32];
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_GDEV_IP, &gdev_ip);
	inet_ntop(AF_INET, &gdev_ip, gdev_ip_str, 32);

	int link_id;
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_ID, &link_id);
	
	unsigned short vxlan_sport = 0;
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_SPORT, &vxlan_sport);
	
	unsigned char link_dir = 0;
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_LINK_DIR, &link_dir);

	char gdev_mac[6], local_mac[6];
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_OUTER_GDEV_MAC, gdev_mac);
	get_rawpkt_opt_from_streaminfo(f_stream, RAW_PKT_GET_VXLAN_OUTER_LOCAL_MAC, local_mac);

	printf("get vxlan opt from rawpkt:  gdev_ip:%s, vxlan_link_id:%d, sport:%u, link_dir:%d, smac:%02x-%02x-%02x-%02x-%02x-%02x, dmac:%02x-%02x-%02x-%02x-%02x-%02x \n", 
		 gdev_ip_str, ntohl(link_id), ntohs(vxlan_sport), link_dir,
		 gdev_mac[0], gdev_mac[1], gdev_mac[2], gdev_mac[3], gdev_mac[4], gdev_mac[5],
		 local_mac[0], local_mac[1], local_mac[2],  local_mac[3], local_mac[4], local_mac[5]);

	return APP_STATE_GIVEME;	
}

char UDP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	//test_project_add(a_tcp,pme,thread_seq,a_packet);
	
	testudpApp_1(a_tcp,pme,thread_seq,a_packet);

	//test_allpkt_stream(a_tcp,pme,thread_seq,a_packet);
	//test_project_read_ipv4_frag_list(a_tcp,pme,thread_seq,a_packet);
	
	return APP_STATE_GIVEME;
}

typedef struct{
	FILE *dump_fp_c2s;
	FILE *dump_fp_s2c;	
	unsigned int first_seq_c2s;
	unsigned int first_seq_s2c;	
}tcp_dump_t;

/* 2015-03-25 lijia add */
char TCP_ALL_DUMP(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
if(NULL == a_packet){
	return APP_STATE_GIVEME;
}

	tcp_dump_t *tdump;
	struct tcpdetail *pdetail=(struct tcpdetail *)a_tcp->pdetail;
	struct mesa_ip4_hdr *iphdr = (struct mesa_ip4_hdr *)a_packet;
	struct mesa_tcp_hdr *tcphdr = (struct mesa_tcp_hdr *)((char *)a_packet + iphdr->ip_hl * 4);
	unsigned int this_seq;
	int this_data_len = ntohs(iphdr->ip_len) - (iphdr->ip_hl << 2) - (tcphdr->th_off<<2);
	char *this_data = (char *)a_packet + (iphdr->ip_hl << 2) + (tcphdr->th_off<<2);

	if(a_tcp->pktstate== OP_STATE_PENDING){
		tdump = (tcp_dump_t *)calloc(1, sizeof(tcp_dump_t));
		tdump->dump_fp_c2s = fopen("dumpfile.tcpraw.C2S.data", "w+");
		if(NULL == tdump->dump_fp_c2s){
			assert(0);
		}
		tdump->dump_fp_s2c = fopen("dumpfile.tcpraw.S2C.data", "w+");
		if(NULL == tdump->dump_fp_s2c){
			assert(0);
		}		
		*pme = tdump;
	}

	tdump = (tcp_dump_t *)(*pme);
	this_seq = ntohl(tcphdr->th_seq);
	
	if(0 == tdump->first_seq_c2s){
		if(tcphdr->th_flags == TH_SYN){
			tdump->first_seq_c2s = ntohl(tcphdr->th_seq);
		}
	}
	
	if(0 == tdump->first_seq_s2c){
		if(tcphdr->th_flags == (TH_SYN|TH_ACK)){
			tdump->first_seq_s2c = ntohl(tcphdr->th_seq);
		}
	}

	if(this_data_len > 0){
		if(DIR_C2S == a_tcp->curdir){
			assert(this_seq >= tdump->first_seq_c2s);
			fseek(tdump->dump_fp_c2s, this_seq - tdump->first_seq_c2s, SEEK_SET);
			fwrite(this_data, this_data_len, 1, tdump->dump_fp_c2s);
		}else{
			assert(this_seq >= tdump->first_seq_s2c);
			fseek(tdump->dump_fp_s2c,  this_seq - tdump->first_seq_s2c, SEEK_SET);
			fwrite(this_data, this_data_len, 1, tdump->dump_fp_s2c);
		}
	}
	

	if(a_tcp->pktstate == OP_STATE_CLOSE){
		fclose(tdump->dump_fp_c2s);
		fclose(tdump->dump_fp_s2c);
		free(tdump);
	}

	return APP_STATE_GIVEME;
}

struct test_tcp_lost{
	unsigned int seq_next_c2s;
	unsigned int seq_next_s2c;	
};

char TEST_TCP_LOST(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	struct test_tcp_lost *tcp_status;
	const struct mesa_ip4_hdr *ipv4_hdr;
	const struct mesa_tcp_hdr *tcp_hdr;
	int ret, len;
	const char *pkt_raw_data;
	unsigned int actual_data_seq;
	
	if(a_tcp->opstate== OP_STATE_PENDING){
		*pme = malloc(sizeof(struct test_tcp_lost ));
		tcp_status = (struct test_tcp_lost  *)*pme;
		len = sizeof(int);
		ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_C2S, &tcp_status->seq_next_c2s, &len);
		if(ret < 0){ /* not create by SYN */
			free(*pme);
			return APP_STATE_DROPME;
		}
		ret = MESA_get_stream_opt(a_tcp, MSO_TCP_ISN_S2C, &tcp_status->seq_next_s2c, &len);
		if(ret < 0){ /* not create by SYN */
			free(*pme);
			return APP_STATE_DROPME;
		}
		tcp_status->seq_next_c2s += 1; /* plus SYN flag */
		tcp_status->seq_next_s2c += 1; /* plus SYN flag */
	}

	tcp_status = (struct test_tcp_lost  *)*pme;

	if(a_tcp->ptcpdetail->lostlen > 0){
		printf("%s lost len:%d\n", printaddr(&a_tcp->addr, a_tcp->threadnum), a_tcp->ptcpdetail->lostlen);
	}

	if(a_tcp->ptcpdetail->datalen > 0){
		ipv4_hdr = (const struct mesa_ip4_hdr *)a_packet;
		tcp_hdr = (const struct mesa_tcp_hdr *)((char *)ipv4_hdr + ipv4_hdr->ip_hl * 4);
		pkt_raw_data = (char *)tcp_hdr + tcp_hdr->th_off * 4; /* 数据包原始数据指针 */
		/* 由于重传追加数据等原因, 平台给插件的数据a_tcp->ptcpdetail->pdata并不一定等于pkt_raw_data, 可能向后偏移了 */
		actual_data_seq = ntohl(tcp_hdr->th_seq) + ((char *)a_tcp->ptcpdetail->pdata - pkt_raw_data);

		printf("stream:%s, dir:%d, pkt-seq:%u, actual-data-seq:%u\n", printaddr(&a_tcp->addr, a_tcp->threadnum),a_tcp->curdir, ntohl(tcp_hdr->th_seq),  actual_data_seq);
		
		if(DIR_C2S == a_tcp->curdir){
			/* 本次实际序号 == 由上次计算得出的理论应该到达序号 + 本次计算得出的丢包长度 */
			if(actual_data_seq != tcp_status->seq_next_c2s + a_tcp->ptcpdetail->lostlen){
				printf("\033[41mstream:%s,  seq check fail!\033[0m\n", printaddr(&a_tcp->addr, a_tcp->threadnum));
				//assert(0);
				goto err_exit;
			}
			/* 下一个期待的序号是: 当前实际序号 + 实际数据长度 */
			tcp_status->seq_next_c2s = actual_data_seq + a_tcp->ptcpdetail->datalen;
		}else{
			if(actual_data_seq  != tcp_status->seq_next_s2c + a_tcp->ptcpdetail->lostlen){
				printf("\033[41mstream:%s,  seq check fail!\033[0m\n", printaddr(&a_tcp->addr, a_tcp->threadnum));
				//assert(0);
				goto err_exit;
			}
			/* 下一个期待的序号是: 当前实际序号 + 实际数据长度 */
			tcp_status->seq_next_s2c = actual_data_seq + a_tcp->ptcpdetail->datalen;
		}
	}
	
	if(a_tcp->opstate == OP_STATE_CLOSE){
		printf("\033[32mstream %s check SUCC!\033[0m\n", printaddr(&a_tcp->addr, a_tcp->threadnum));
		free(*pme);
	}
	
	return APP_STATE_GIVEME;

err_exit:
	free(*pme);
	return APP_STATE_DROPME;
}

char TCP_ENTRY_ALL(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return testtcpApp_allpkt(a_tcp,pme,thread_seq,a_packet);
	//return test_allpkt_stream(a_tcp,pme,thread_seq,a_packet);
}

typedef struct  {
	unsigned int magic;
	unsigned short version_major;
	unsigned short version_minor;
	unsigned int thiszone;	/* gmt to local correction */
	unsigned int sigfigs;	/* accuracy of timestamps */
	unsigned int snaplen;	/* max length saved portion of each pkt */
	unsigned int linktype;	/* data link type (LINKTYPE_*) */
}pcap_file_hdr_t;

typedef struct {
	unsigned int tv_sec;	/* time stamp */
	unsigned int tv_usec;	/* time stamp */
	unsigned int caplen;	/* length of portion present */
	unsigned int len;	/* length this packet (off wire) */
}pcap_pkt_hdr_t;

static const pcap_file_hdr_t test_pcap_file_hdr = 
{
	0xA1B2C3D4,
	0x0002, 
	0x0004,
	0,
	0,
	0xFFFF,
	1
};

static unsigned char test_pcap_phony_mac_hdr[14] = 
{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 
	0x12, 0x23, 0x34, 0x56, 0x67, 0x78,
	0x08, 0x00
};

char TCP_ALL_DUMP_PCAP_PKT(struct streaminfo *pstream,  void **pme, int thread_seq,void *a_packet)
{
	FILE *fp;
	pcap_pkt_hdr_t pcap_pkt_hdr;
	struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)a_packet;
	
	if(OP_STATE_PENDING == pstream->pktstate){
		char tmp_file[32];
		snprintf(tmp_file, 32, "%p.pcap", pstream);
		FILE *fp = fopen(tmp_file, "a+");
		if(NULL == fp){
			printf("fopen ./%p.pcap error!\n", tmp_file);
			return APP_STATE_DROPME;
		}
		fwrite(&test_pcap_file_hdr, sizeof(pcap_file_hdr_t), 1, fp);
		*pme = fp;
	}else if(OP_STATE_CLOSE == pstream->pktstate){
		fclose(*pme);
		return APP_STATE_DROPME;
	}

	fp = (FILE *)(*pme);

	if(a_packet){
		pcap_pkt_hdr.caplen = ntohs(ip4hdr->ip_len) + 14;
		pcap_pkt_hdr.len = ntohs(ip4hdr->ip_len) + 14;
		fwrite(&pcap_pkt_hdr, sizeof(pcap_pkt_hdr_t), 1, fp);
		fwrite(test_pcap_phony_mac_hdr, 14, 1, fp);
		fwrite(a_packet, ntohs(ip4hdr->ip_len), 1, fp);
		fflush(fp);
	}

	return APP_STATE_GIVEME;
}
char IPV4_PKT_DUMP( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	FILE *fp;
	int iphl = a_packet->ip_hl*4;
	int payload_len = ntohs(a_packet->ip_len) - iphl;

	fp = fopen("ipv4_dump.pcap", "w+");

	fwrite((char *)a_packet + iphl, payload_len, 1, fp);


	fclose(fp);

	return APP_STATE_GIVEME;
}

char IPV6_PKT_DUMP( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct mesa_ip6_hdr* a_packet)
{
	FILE *fp;
	int iphl = sizeof(struct mesa_ip6_hdr);
	int payload_len = ntohs(a_packet->ip6_payload_len);

	fp = fopen("ipv6_dump.pcap", "w+");

	fwrite((char *)a_packet + iphl, payload_len, 1, fp);

	fclose(fp);

	return APP_STATE_GIVEME;
}

char KILL_STREAM_FEEDBACK(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	char pkt_buf[1500];
	int pkt_len = 1500;
	int ret;
	FILE *fp;
	pcap_file_hdr_t pfile_hdr;
	pcap_pkt_hdr_t pkt_hdr;

	if((80 != ntohs(a_tcp->addr.ipv4->source)) && (80 != ntohs(a_tcp->addr.ipv4->dest))){
		return APP_STATE_GIVEME;
	}

	if(a_packet != NULL){	
		ret = MESA_kill_tcp_feedback(a_tcp, a_packet, pkt_buf, &pkt_len);
		if(1500 == pkt_len){
			printf("MESA_kill_tcp_feedback error!\n");
		}else{
			memset(&pfile_hdr, 0, sizeof(pfile_hdr));
			memset(&pkt_hdr, 0, sizeof(pkt_hdr));
			pfile_hdr.magic = 0xA1B2C3D4;
			pfile_hdr.version_major = 2;
			pfile_hdr.version_minor = 4;
			pfile_hdr.linktype = 1;
			pfile_hdr.snaplen = 65535;

			pkt_hdr.caplen = pkt_len;
			pkt_hdr.len = pkt_len;

			fp = fopen("feedback.pcap", "w+");
			fwrite(&pfile_hdr, sizeof(pcap_file_hdr_t), 1, fp);
			fwrite(&pkt_hdr, sizeof(pcap_pkt_hdr_t), 1, fp);
			fwrite(pkt_buf, pkt_len, 1, fp);
			fclose(fp);
		}
	}
	return APP_STATE_GIVEME;
}


char KILL_STREAM_SYNACK(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	MESA_kill_tcp_synack(a_tcp, a_packet);
	return APP_STATE_GIVEME;
}

char SLEEP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	usleep(1);
	return APP_STATE_GIVEME;
}

char KILL_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	MESA_kill_connection(a_tcp, a_packet);
	return APP_STATE_GIVEME | APP_STATE_DROPPKT;
}

char TEST_STREAM(struct streaminfo *stream,  void **pme, int thread_seq,void *a_packet)
{
	const char *data;
	int datalen;
	static char __tmp_use[65535];

	if(STREAM_TYPE_TCP == stream->type){
		data = (const char *)stream->ptcpdetail->pdata;
		datalen = stream->ptcpdetail->datalen;
	}else{
		data = (const char *)stream->pudpdetail->pdata;
		datalen = stream->pudpdetail->datalen;
	}

	if(data){
		assert(datalen <= 65535);
		memcpy(__tmp_use, data, datalen);
		memcpy(__tmp_use, stream->addr.paddr, stream->addr.addrlen);
	}

	return APP_STATE_GIVEME;
}

char KEEP_STREAM(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_GIVEME;
}

char TCP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	//test_project_add(a_tcp,pme,thread_seq,a_packet);
	
	testtcpApp_2(a_tcp,pme,thread_seq,a_packet);

	//test_project_read_ipv4_frag_list(a_tcp,pme,thread_seq,a_packet);

	return APP_STATE_GIVEME;
}

char IP_FRAG_ENTRY( struct streaminfo *stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	static int call_times = 0;
	
	printf("ip_frag_entry, times:%d\n", ++call_times);

	if(PKT_TYPE_IP_FRAG_LAST & stream->addr.pktipfragtype){
		printf("recv last ip frag pkt!\n");
		return APP_STATE_GIVEME | APP_STATE_DROPPKT;
	}
	
	return APP_STATE_GIVEME;
}

enum anti_flood_stat_type{
	ANTI_FLOOD_TCP_SYN = 0, 
	ANTI_FLOOD_UDP_DNS,
	ANTI_FLOOD_UDP_NTP,
	ANTI_FLOOD_IP_FRAG,
};
static unsigned long long anti_flood_stat[MAX_THREAD_NUM][8];
static time_t last_log_time;
//extern int g_packet_io_thread_num;
//extern time_t g_CurrentTime;
static void anti_flood_stat_log(void)
{
	FILE *fp;
	int tseq;
	int tot_thread_count;
	int opt_len = sizeof(int);

	sapp_get_platform_opt(SPO_THREAD_COUNT, &tot_thread_count, &opt_len);

	unsigned long long tmp_anti_flood_stat[8];
	memset(tmp_anti_flood_stat, 0, sizeof(tmp_anti_flood_stat));
	
	for(tseq =0; tseq < tot_thread_count; tseq++){
		tmp_anti_flood_stat[ANTI_FLOOD_TCP_SYN] += anti_flood_stat[tseq][ANTI_FLOOD_TCP_SYN];
		tmp_anti_flood_stat[ANTI_FLOOD_UDP_DNS] += anti_flood_stat[tseq][ANTI_FLOOD_UDP_DNS];
		tmp_anti_flood_stat[ANTI_FLOOD_UDP_NTP] += anti_flood_stat[tseq][ANTI_FLOOD_UDP_NTP];
		tmp_anti_flood_stat[ANTI_FLOOD_IP_FRAG] += anti_flood_stat[tseq][ANTI_FLOOD_IP_FRAG];
	}

	fp = fopen("./log/anti_flood_stat.log", "w+");

	fprintf(fp, "tcp_syn\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_TCP_SYN]);
	fprintf(fp, "udp_dns\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_UDP_DNS]);
	fprintf(fp, "udp_ntp\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_UDP_NTP]);
	fprintf(fp, "ip_frag\t %llu\n", tmp_anti_flood_stat[ANTI_FLOOD_IP_FRAG]);

	fclose(fp);
}

char ANTI_FLOOD_STAT_IP_FRAG_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	anti_flood_stat[thread_seq][ANTI_FLOOD_IP_FRAG]++;
	return APP_STATE_GIVEME;
}

char ANTI_FLOOD_STAT_IP_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	const struct mesa_ip4_hdr *ip4hdr = (struct mesa_ip4_hdr *)a_packet;
	const struct mesa_tcp_hdr *tcphdr;
	const struct mesa_udp_hdr *udphdr;

	time_t cur_time;
	int opt_len = sizeof(cur_time);

	sapp_get_platform_opt(SPO_CURTIME_TIMET, &cur_time, &opt_len);

	if(IPPROTO_TCP == ip4hdr->ip_p){
		tcphdr = (const struct mesa_tcp_hdr *)((char *)a_packet + ip4hdr->ip_hl*4);
		if(TH_SYN == tcphdr->th_flags){ 
			anti_flood_stat[thread_seq][ANTI_FLOOD_TCP_SYN]++;
		}
	}else if(IPPROTO_UDP == ip4hdr->ip_p){
		udphdr = (const struct mesa_udp_hdr *)((char *)a_packet + ip4hdr->ip_hl*4);
		if(53 == ntohs(udphdr->uh_sport) || 53 == ntohs(udphdr->uh_dport)){
			anti_flood_stat[thread_seq][ANTI_FLOOD_UDP_DNS]++;
		}else if(123 == ntohs(udphdr->uh_sport) || 123 == ntohs(udphdr->uh_dport)){
			anti_flood_stat[thread_seq][ANTI_FLOOD_UDP_NTP]++;
		}
	}

	if(0 == thread_seq){
		if(cur_time > last_log_time){
			last_log_time = cur_time;
			anti_flood_stat_log();
		}	
	}

	return  APP_STATE_GIVEME;
}

char IP_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	return testIPApp_1(f_stream,routedir,thread_seq,a_packet);
}

char IPv6_ENTRY(const struct streaminfo *pstream,unsigned char routedir,int thread_seq,const void *ipv6_hdr)
{
	printf("into IPv6_ENTRY()!\n");
	return APP_STATE_GIVEME;
}

char IPv6_RAW_ENTRY(const struct streaminfo *pstream, const void *this_hdr, const void *raw_pkt)
{
	printf("into IPv6_RAW_ENTRY()!\n");
	return APP_STATE_GIVEME;
}

char POLLING_ENTRY(struct streaminfo *stream,  void **pme, int thread_seq,void *a_packet)
{
	return APP_STATE_GIVEME;	
}

#endif


int CHAR_INIT()
{
	test_sapp_get_device_opt("em1");
	
	int demo_plugid = 51;

//  函数实现自定义
//  只要求函数返回值为插件ID；
	
	return demo_plugid;
}

void CHAR_DESTROY(void)
{

}

void test_funstat(unsigned long long protflag)
{
	;
}

long long test_flag_change(char* flag_str)
{
	return 0xFFFF;
}

void test_get_plugid(unsigned short plugid)
{
	return;
}


int TEST_APP_INIT()
{
	return 51;
}

void test_destroy(void)
{
	;
}
