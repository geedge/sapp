#include <stdio.h>
#include "dpdk_rte_hash_crc.h"
#include "stream.h"

/*
	本插件用于测试dpdk分流算法.
*/

extern int get_thread_count(void);

char test_dpdk_hash(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	unsigned int sip_hash_crc, dip_hash_crc, sapp_stream_hash;
	unsigned int tot_thread_cnt;

	if(pstream->opstate == OP_STATE_PENDING){

		tot_thread_cnt = get_thread_count();
		sip_hash_crc = rte_hash_crc(&pstream->addr.tuple4_v4->saddr, sizeof(int), 0);
		dip_hash_crc = rte_hash_crc(&pstream->addr.tuple4_v4->daddr, sizeof(int), 0);

		sapp_stream_hash = (sip_hash_crc ^ dip_hash_crc) % tot_thread_cnt;

		if(sapp_stream_hash != thread_seq){
			printf("\033[1;31;40m tid:%d, stream:%s, dpdk hash:%u is diff with sapp:%d!\033[0m\n", thread_seq, printaddr(&pstream->addr, thread_seq), sapp_stream_hash, thread_seq);
		}else{
			printf("tid:%d, stream:%s, dpdk hash is same as sapp!\n", thread_seq, printaddr(&pstream->addr, thread_seq));
		}

	}

	return APP_STATE_DROPME;
}


int CHAR_INIT(void)
{
	return 0;
}

#if 0
int main()
{
	unsigned int hash_crc;
	unsigned int sip = 0x12345678;
	unsigned int dip = 0x0ABCDEF0;
	hash_crc = rte_hash_crc(&sip, sizeof(int), 0);
	printf("sip crc=%u\n", hash_crc);
	hash_crc = rte_hash_crc(&dip, sizeof(int), 0);
	printf("dip crc=%u\n", hash_crc);
	return 0;
}
#endif

