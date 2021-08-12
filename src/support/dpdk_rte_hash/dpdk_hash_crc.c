#include "stream.h"
#include <stdio.h>
#include <pthread.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <linux/limits.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <dirent.h>
#include "mrtunnat.h"
#include "dpdk_rte_hash_crc.h"


#ifdef __cplusplus
extern "C" { 
#endif 

/*
	本函数copy自dpdk源码中的rte_hash_crc.h, 用于计算ip二元组hash,
	用来保证pcap模式下收包, 与marsio的分流算法一样, 便于测试.
	详见: marsio源码: ldbc.c -> hash_sym_crc()函数.
*/
unsigned int dpdk_rte_ip_hash(const char *sipaddr, const char *dipaddr, int addrlen)
{
	unsigned int sip_hash, dip_hash;
	
	sip_hash = rte_hash_crc(sipaddr, addrlen, 0);
	dip_hash = rte_hash_crc(dipaddr, addrlen, 0);
	
	return sip_hash ^ dip_hash;
}

#ifdef __cplusplus
}
#endif 


