#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <assert.h>
#include <time.h>
#include <arpa/inet.h>
#include "stream.h"
#include "md5.h"
#include "cJSON.h"

/* sapp benchmark with gopacket */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct{
	union{
		struct tcp_flow_stat tcp_stat;
		struct udp_flow_stat udp_stat;
	};
	unsigned long long C2S_lost_byte;
	unsigned long long S2C_lost_byte;
	MD5_CTX C2S_md5_context;
	MD5_CTX S2C_md5_context;
	unsigned long long stream_id;
}bhk_plug_pme_t;

static unsigned long long g_plug_stream_id = 0;

static void output_to_cjson(const char *proto_type, bhk_plug_pme_t *plug_stat, 
	const struct streaminfo *pstream, unsigned char *C2S_payload, unsigned char *S2C_payload)
{
	cJSON *json_root;
	char tmp_str_buf[128];
	
	json_root = cJSON_CreateObject();
	
	cJSON_AddStringToObject(json_root, "Proto", proto_type);
	cJSON_AddNumberToObject(json_root, "Stream_id", plug_stat->stream_id);
	
	printaddr_r(&pstream->addr, tmp_str_buf, sizeof(tmp_str_buf)),
	cJSON_AddStringToObject(json_root, "Tuple4", tmp_str_buf);
	cJSON_AddNumberToObject(json_root, "C2S_pkt", plug_stat->tcp_stat.C2S_data_pkt);
	cJSON_AddNumberToObject(json_root, "C2S_byte", plug_stat->tcp_stat.C2S_data_byte);
	cJSON_AddNumberToObject(json_root, "C2S_lost_byte", plug_stat->C2S_lost_byte);
	cJSON_AddStringToObject(json_root, "C2S_payload", (char *)C2S_payload);
	
	cJSON_AddNumberToObject(json_root, "S2C_pkt", plug_stat->tcp_stat.S2C_data_pkt);
	cJSON_AddNumberToObject(json_root, "S2C_byte", plug_stat->tcp_stat.S2C_data_byte);
	cJSON_AddNumberToObject(json_root, "S2C_lost_byte", plug_stat->S2C_lost_byte);
	cJSON_AddStringToObject(json_root, "S2C_payload", (char *)S2C_payload);
	
	cJSON_AddNumberToObject(json_root, "Total_pkt", plug_stat->tcp_stat.C2S_data_pkt+plug_stat->tcp_stat.S2C_data_pkt);
	cJSON_AddNumberToObject(json_root, "Total_byte", plug_stat->tcp_stat.C2S_data_byte+plug_stat->tcp_stat.S2C_data_byte);
	
	//char *cjson_string = cJSON_Print(json_root);
	char *cjson_string = cJSON_PrintUnformatted(json_root);
	printf("%s\n", cjson_string);	
	free(cjson_string);
	cJSON_Delete(json_root);

}

char benchmark_tcp_entry(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	const struct tcpdetail *raw_tcpdetail=(struct tcpdetail *)pstream->pdetail;
	bhk_plug_pme_t *plug_stat;
	unsigned char C2S_bin_digest[16], S2C_bin_digest[16];
	unsigned char C2S_str_digest[64], S2C_str_digest[64];
	unsigned char *C2S_payload = (unsigned char *)"NULL", *S2C_payload = (unsigned char *)"NULL";
	int i;
	
	if(pstream->opstate == OP_STATE_PENDING)
	{
		plug_stat = (bhk_plug_pme_t *)calloc(1, sizeof(bhk_plug_pme_t));
		MD5Init(&plug_stat->C2S_md5_context);
		MD5Init(&plug_stat->S2C_md5_context);
		plug_stat->stream_id = g_plug_stream_id++;
		*pme = plug_stat;
	}
	plug_stat = (bhk_plug_pme_t *)(*pme);
	
	if(raw_tcpdetail->datalen > 0){
		if(DIR_C2S == pstream->curdir){
			plug_stat->tcp_stat.C2S_data_byte += raw_tcpdetail->datalen;
			plug_stat->tcp_stat.C2S_data_pkt++;
			MD5Update (&plug_stat->C2S_md5_context, (unsigned char *)raw_tcpdetail->pdata, raw_tcpdetail->datalen);
		}else{
			plug_stat->tcp_stat.S2C_data_byte += raw_tcpdetail->datalen;
			plug_stat->tcp_stat.S2C_data_pkt++;
			MD5Update (&plug_stat->S2C_md5_context, (unsigned char *)raw_tcpdetail->pdata, raw_tcpdetail->datalen);
		}
	}

	if(raw_tcpdetail->lostlen){
		if(DIR_C2S == pstream->curdir){
			plug_stat->C2S_lost_byte += raw_tcpdetail->lostlen;
		}else{
			plug_stat->S2C_lost_byte += raw_tcpdetail->lostlen;
		}
	}
	
	if(pstream->opstate== OP_STATE_CLOSE)
	{	
		if(plug_stat->tcp_stat.C2S_data_byte > 0){
			memset(C2S_str_digest, 0, sizeof(C2S_str_digest));
			MD5Final(C2S_bin_digest, &plug_stat->C2S_md5_context);
			for (i=0; i<16; i++){
				sprintf((char *)C2S_str_digest+2*i, "%02x", C2S_bin_digest[i]);
			}		
			C2S_payload = C2S_str_digest;
		}
		
		if(plug_stat->tcp_stat.S2C_data_byte > 0){
			memset(S2C_str_digest, 0, sizeof(S2C_str_digest));
			MD5Final(S2C_bin_digest, &plug_stat->S2C_md5_context);
			for (i=0; i<16; i++){
				sprintf((char *)S2C_str_digest+2*i, "%02x", S2C_bin_digest[i]);
			}		
			S2C_payload = S2C_str_digest;
		}

		output_to_cjson("TCP", plug_stat, pstream, C2S_payload, S2C_payload);

		free(plug_stat);
	}

    return APP_STATE_GIVEME;
}

char benchmark_udp_entry(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	const struct tcpdetail *raw_tcpdetail=(struct tcpdetail *)pstream->pdetail;
	bhk_plug_pme_t *plug_stat;
	unsigned char C2S_bin_digest[16], S2C_bin_digest[16];
	unsigned char C2S_str_digest[64], S2C_str_digest[64];
	unsigned char *C2S_payload = (unsigned char *)"NULL", *S2C_payload = (unsigned char *)"NULL";
	int i;
	
	if(pstream->opstate == OP_STATE_PENDING)
	{
		plug_stat = (bhk_plug_pme_t *)calloc(1, sizeof(bhk_plug_pme_t));
		MD5Init(&plug_stat->C2S_md5_context);
		MD5Init(&plug_stat->S2C_md5_context);
		plug_stat->stream_id = g_plug_stream_id++;
		*pme = plug_stat;
	}
	plug_stat = (bhk_plug_pme_t *)(*pme);
	
	if(raw_tcpdetail->datalen > 0){
		if(DIR_C2S == pstream->curdir){
			plug_stat->tcp_stat.C2S_data_byte += raw_tcpdetail->datalen;
			plug_stat->tcp_stat.C2S_data_pkt++;
			MD5Update (&plug_stat->C2S_md5_context, (unsigned char *)raw_tcpdetail->pdata, raw_tcpdetail->datalen);
		}else{
			plug_stat->tcp_stat.S2C_data_byte += raw_tcpdetail->datalen;
			plug_stat->tcp_stat.S2C_data_pkt++;
			MD5Update (&plug_stat->S2C_md5_context, (unsigned char *)raw_tcpdetail->pdata, raw_tcpdetail->datalen);
		}
	}
	
	if(pstream->opstate== OP_STATE_CLOSE)
	{	
		if(plug_stat->tcp_stat.C2S_data_byte > 0){
			memset(C2S_str_digest, 0, sizeof(C2S_str_digest));
			MD5Final(C2S_bin_digest, &plug_stat->C2S_md5_context);
			for (i=0; i<16; i++){
				sprintf((char *)C2S_str_digest+2*i, "%02x", C2S_bin_digest[i]);
			}		
			C2S_payload = C2S_str_digest;
		}
		
		if(plug_stat->tcp_stat.S2C_data_byte > 0){
			memset(S2C_str_digest, 0, sizeof(S2C_str_digest));
			MD5Final(S2C_bin_digest, &plug_stat->S2C_md5_context);
			for (i=0; i<16; i++){
				sprintf((char *)S2C_str_digest+2*i, "%02x", S2C_bin_digest[i]);
			}		
			S2C_payload = S2C_str_digest;
		}

		output_to_cjson("UDP", plug_stat, pstream, C2S_payload, S2C_payload);
		
		free(plug_stat);
	}

    return APP_STATE_GIVEME;
}


int sapp_benchmark_plug_init(void)
{
	return 1;
}


#ifdef __cplusplus
}
#endif



