#include <stdlib.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif 

#define TEST_PLUG_ID	(1)



char test_get_rawpkt_options(struct streaminfo *stream,void **pme, int thread_seq,const void *raw_pkt)
{
	int ret;
	int gdev_ip;
	int vxlan_id;
	unsigned short vxlan_sport;
	unsigned char service_id;
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_GDEV_IP, &gdev_ip);
	if(ret >= 0){
		char tmp_ip_str[32];
		inet_ntop(AF_INET, &gdev_ip, tmp_ip_str, 32);
		printf("[debug], test_get_rawpkt_options get gdev-ip:%s\n", tmp_ip_str);
	}else{
		printf("[error], test_get_rawpkt_options error\n");
	}

	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_ID, &vxlan_id);
	if(ret >= 0){
		printf("[debug], test_get_rawpkt_options get vlan-id:%d\n", vxlan_id);
	}else{
		printf("[error], test_get_rawpkt_options error\n");
	}

	service_id = vxlan_id_map_to_service_id(ntohl(vxlan_id));
	printf("service id from vxlan_id: %u\n", service_id);
	
	ret = get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_VXLAN_SPORT, &vxlan_sport);
	if(ret >= 0){
		printf("[debug], test_get_rawpkt_options get sport:%u\n", ntohs(vxlan_sport));
	}else{
		printf("[error], test_get_rawpkt_options error\n");
	}

	service_id = vxlan_sport_map_to_service_id(ntohs(vxlan_sport));
	printf("service id from sport: %u\n", service_id);
	
	return APP_STATE_GIVEME;
}


int test_ct_init(void)
{
	printf("test ct plug init SUCC!\n");
	return 1;
}

#ifdef __cplusplus
}
#endif

