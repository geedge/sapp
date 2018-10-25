#include <pcap/pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <sys/time.h>
#include <stdlib.h>
#include "afh_inner.h"
#include "anti_flood_hijack.h"

static pcap_t *pcap_handle;
static const char *dev_name;

SYM_HIDDEN char *ddos_type_n2p(unsigned int ddos_type)
{
	const char *ddos_str = "Unknown";
	
	switch(ddos_type){
		case AFH_ATTACK_DDOS_IPFRAG:
			ddos_str = "ddos_ipfrag";
		break;

		case AFH_ATTACK_DDOS_SYN:
			ddos_str = "ddos_syn";
		break;

		case AFH_ATTACK_DDOS_DNS:
			ddos_str = "ddos_dns";
		break;

		case AFH_ATTACK_DDOS_NTP:
			ddos_str = "ddos_ntp";
		break;
	}

	return "Unknown";
}

SYM_HIDDEN void warn_msg(struct afh_pkt_check_res *ret)
{
	if(ret->attack_type == 1){
		printf("found attack: %s\n", ddos_type_n2p(ret->ddos_type));
	}
}

SYM_HIDDEN void pcap_pkt_handle(u_char *user, const struct pcap_pkthdr *hdr, const u_char *data)
{
	struct afh_pkt_check_res ret;

	ret = anti_flood_hijack_pkt_check(data, hdr->caplen, 0, 0);
	if(ret.action == 0 || ret.attack_type != 0){
		warn_msg(&ret);
	}

	return;
}


SYM_HIDDEN int init(void)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_handle = pcap_open_live(dev_name, 2048, 1, 1, pcap_errbuf);
	if(NULL == pcap_handle)
	{
		printf("\033[1;31;40m[Error]Can't open device:'%s', %s\033[0m\n", dev_name, pcap_errbuf);
		return -1;
	}

	pcap_setdirection(pcap_handle, PCAP_D_IN);

	anti_flood_hijack_module_init(1);

	return 0;
}

SYM_HIDDEN void run(void)
{
	pcap_loop(pcap_handle, -1, pcap_pkt_handle, NULL);
}

SYM_HIDDEN void usage(const char *prog_name)
{
	printf("Usage:\n    %s device_name\n", prog_name);
	exit(1);
}



int main(int argc, char *argv[])
{
	if(argc != 2){
		usage(argv[0]);
	}

	dev_name = argv[1];

	if(init() < 0){
		exit(1);
	}

	run();

	return 0;
}

