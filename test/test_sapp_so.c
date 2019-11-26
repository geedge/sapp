#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if_ether.h>
#include <pcap/pcap.h>
#include <dlfcn.h>
#include "mesa_net.h"
#include "stream_base.h"

static int (*MESA_PLUG_INIT)(void);
static char * (*MESA_IP_PLUG_ENTRY)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const struct mesa_ip4_hdr *ipv4_hdr);

static pcap_t *pcap_handle;
static int pcap_mode = 2;
static const char *device_name = "dumpfile";

#define DUMPFILE_EOF_FLAG	(void*)0xF1E2D3C4B5A6 /* 用一个独特变量表示当前dumpfile模式已结束, 清理内存 */

int pcap_init(void)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	if(1 == pcap_mode){
		pcap_handle = pcap_open_live(device_name,16384,1,1,pcap_errbuf);
		if(NULL == pcap_handle)
		{
			printf("\033[1;31;40m[Error]Can't open device:'%s', %s\033[0m\n", device_name, pcap_errbuf);
			return -1;
		}	
		pcap_setdirection(pcap_handle, PCAP_D_INOUT);
	}else{
		pcap_handle = pcap_open_offline(device_name, pcap_errbuf);
		if(NULL == pcap_handle)
		{
			printf("\033[1;31;40m[Error]Can't open file:'%s', %s\033[0m\n", device_name, pcap_errbuf);
			return -1;
		}
	}

	return 0;
}

static void __pcap_pkt_cb(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	const struct mesa_ethernet_hdr *p_eth_hdr = (const struct mesa_ethernet_hdr *)data;

	if(ETH_P_IP == ntohs(p_eth_hdr->ether_type)){
		MESA_IP_PLUG_ENTRY(NULL, 0, 0, (const struct mesa_ip4_hdr *)(data+14));
	}
}


static void pcap_run(void)
{
	pcap_loop(pcap_handle, -1, __pcap_pkt_cb, NULL);

	/* pcap_loop()函数退出, 表示读包已结束, 调用上层插件, 通知EOF事件 */
	MESA_IP_PLUG_ENTRY((const streaminfo*)DUMPFILE_EOF_FLAG, 0, 0, NULL);
}

static void usage(const char *prog_name)
{
	printf("usage: %s %s %s\n", prog_name,"cap_mode[1:online; 2:dump]", "device_name");
	printf("          %s\n", "for example, %s 1 eth1");
	printf("          %s\n", "for example, %s 2 ./test.pcap");
}


int main(int argc, char *argv[])
{
	void *sapp_so_handle;
	
	if(argc != 3){
		usage(argv[0]);
		exit(0);
	}

	pcap_mode = atoi(argv[1]);
	if((pcap_mode != 1) && (pcap_mode != 2)){
		usage(argv[0]);
		exit(0);
	}

	device_name = argv[2];

	sapp_so_handle = dlopen("./sapp_plug.so", RTLD_NOW|RTLD_GLOBAL);
	if(NULL == sapp_so_handle){
		printf("dlopen %s error!\n", "./sapp_plug.so");
		exit(1);
	}

	MESA_PLUG_INIT = (int (*)(void))dlsym(sapp_so_handle, "MESA_PLUG_INIT");
	if(NULL == MESA_PLUG_INIT){
		printf("dlsym %s error!\n", "MESA_PLUG_INIT");
		exit(1);
	}
	MESA_IP_PLUG_ENTRY = (char * (*)(const struct streaminfo *pstream,unsigned char routedir,int thread_seq, const struct mesa_ip4_hdr *ipv4_hdr))dlsym(sapp_so_handle, "MESA_IP_PLUG_ENTRY");
	if(NULL == MESA_IP_PLUG_ENTRY){
		printf("dlsym %s error!\n", "MESA_IP_PLUG_ENTRY");
		exit(1);
	}

	if(MESA_PLUG_INIT() < 0){
		return -1;
	}

	pcap_init();

	pcap_run();
	
	return 0;
}
		
