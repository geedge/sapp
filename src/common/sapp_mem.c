#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

#ifdef __cplusplus
extern "C" {
#endif



int g_sapp_global_mem_used_block = 0;
int g_sapp_global_mem_used_bytes = 0;


typedef struct{
	sapp_mem_type_t mem_type;
	const char *mem_type_string;
}mem_stat_name_tuple_t;

static const  mem_stat_name_tuple_t mem_stat_name_tuple[] = 
{
	{__SAPP_MEM_TYPE_INIT, 		"NULL"},
	{SAPP_MEM_STACK_LOCAL, 		"stack_local" },
	{SAPP_MEM_FIX_GLOBAL_VAL ,  "global_val"},
	{SAPP_MEM_FIX_GLOBAL_STREAM , "global_stream"},
	{SAPP_MEM_FIX_PLUG_CTRL, "global_plugctrl"},
	
	{__SAPP_FIX_DYN_SEPARATOR , "_separator"},
	
	{SAPP_MEM_DYN_MEM_HDR , 	"mem_hdr"},
	{SAPP_MEM_DYN_IP_FRAG_PKT , "ip_frag_pkt"},
	{SAPP_MEM_DYN_TCP_STREAM , "tcp_stream"},
	{SAPP_MEM_DYN_UDP_STREAM , "udp_stream"},
	{SAPP_MEM_DYN_TCP_HALF_STREAM , "tcp_half_stream"},
	{SAPP_MEM_DYN_UDP_HALF_STREAM , "udp_half_stream"},
	{SAPP_MEM_DYN_PLUG_CTRL , 	"stream_plugctrl"},
	{SAPP_MEM_DYN_TCP_UNORDER , "tcp_unorder"},
	{SAPP_MEM_DYN_TCP_SYN_OPT , "tcp_option"},
	{SAPP_MEM_DYN_TCP_POLLING_RAW_PKT , "tcp_polling_pkt"},
	{SAPP_MEM_DYN_UDP_POLLING_RAW_PKT , "udp_polling_pkt"},
	{SAPP_MEM_DYN_TCP_DETAIL , 	"tcp_detail"},
	{SAPP_MEM_DYN_UDP_DETAIL , 	"udp_detail"},
	{SAPP_MEM_DYN_TCP_FLOW_STAT , "tcp_flow_stat"},
	{SAPP_MEM_DYN_UDP_FLOW_STAT , "udp_flow_stat"},
	{SAPP_MEM_DYN_TCP_PROJECT , "tcp_project"},
	{SAPP_MEM_DYN_UDP_PROJECT , "udp_project"},
	{SAPP_MEM_DYN_TCP_BRIDGE , "tcp_bridge"},
	{SAPP_MEM_DYN_UDP_BRIDGE , "udp_bridge"},
	{SAPP_MEM_DYN_PADDR , 		"layer_addr"},
	{SAPP_MEM_DYN_DETAIN_PKT , 		"detain_pkt"},
	{SAPP_MEM_DYN_SID_LIST , 		"segment_id_list"},
	{SAPP_MEM_DYN_BLOOM_FILTER , 	"bloom_filter"},
};

void *sapp_mem_malloc(sapp_mem_type_t type, int thread_seq, unsigned int size)
{
	char *ptr;
	sapp_private_mem_t *mhdr;
	sapp_mem_used_stat_t *mem_used_stat;

	ptr = (char *)malloc(size+sizeof(sapp_private_mem_t));

	mhdr = (sapp_private_mem_t *)ptr;
	
#ifdef DEBUG
	mhdr->magic = 0x4D4D4D4D; 
#endif
	mhdr->user_buf_size = size;

	if(type < __SAPP_FIX_DYN_SEPARATOR){
		mem_used_stat = &sapp_global_val->individual_volatile->mem_used_stat;	
	}else{
		mem_used_stat = &sapp_global_val->mthread_volatile[thread_seq]->mem_used_stat;	
	}

	mem_used_stat->mem_used_block[SAPP_MEM_DYN_MEM_HDR]++;
	mem_used_stat->mem_used_bytes[SAPP_MEM_DYN_MEM_HDR]+=sizeof(sapp_private_mem_t);
	
	mem_used_stat->mem_used_block[type]++;
	mem_used_stat->mem_used_bytes[type] += size;

	return ptr + sizeof(sapp_private_mem_t);
}


void *sapp_mem_calloc(sapp_mem_type_t type, int thread_seq, unsigned int size)
{
	char *ptr;
	sapp_private_mem_t *mhdr;
	sapp_mem_used_stat_t *mem_used_stat;
	ptr = (char *)calloc(1, size+sizeof(sapp_private_mem_t));

	mhdr = (sapp_private_mem_t *)ptr;
	
#ifdef DEBUG
	mhdr->magic = 0x4D4D4D4D; 
#endif
	mhdr->user_buf_size = size;

	if(type < __SAPP_FIX_DYN_SEPARATOR){
		mem_used_stat = &sapp_global_val->individual_volatile->mem_used_stat;	
	}else{
		mem_used_stat = &sapp_global_val->mthread_volatile[thread_seq]->mem_used_stat;	
	}

	mem_used_stat->mem_used_block[SAPP_MEM_DYN_MEM_HDR]++;
	mem_used_stat->mem_used_bytes[SAPP_MEM_DYN_MEM_HDR]+=sizeof(sapp_private_mem_t);

	mem_used_stat->mem_used_block[type]++;
	mem_used_stat->mem_used_bytes[type] += size;
	
	return ptr + sizeof(sapp_private_mem_t);
}


void sapp_mem_free(sapp_mem_type_t type, int thread_seq, void *data)
{	
	char *ptr = (char *)data;
	sapp_private_mem_t *mhdr = (sapp_private_mem_t *)(ptr - sizeof(sapp_private_mem_t));
	sapp_mem_used_stat_t *mem_used_stat;

#ifdef DEBUG
	assert(0x4D4D4D4D == mhdr->magic);
	mhdr->magic = 0xFEFEFEFE;
#endif

	if(type < __SAPP_FIX_DYN_SEPARATOR){
		mem_used_stat = &sapp_global_val->individual_volatile->mem_used_stat;	
	}else{
		mem_used_stat = &sapp_global_val->mthread_volatile[thread_seq]->mem_used_stat;	
	}

	mem_used_stat->mem_used_block[type]--;
	mem_used_stat->mem_used_bytes[type] -= mhdr->user_buf_size;

	mem_used_stat->mem_used_block[SAPP_MEM_DYN_MEM_HDR]--;
	mem_used_stat->mem_used_bytes[SAPP_MEM_DYN_MEM_HDR] -= sizeof(sapp_private_mem_t);
	free((void *)mhdr);
}

void *sapp_mem_realloc(sapp_mem_type_t type, int thread_seq, void *old_ptr, unsigned int size)
{
	void *new_ptr;
	sapp_private_mem_t *mhdr;
	
	if(NULL == old_ptr){ /* first time,  NULL pointer, same to sapp_mem_calloc() */
		return sapp_mem_calloc(type, thread_seq, size);
	}

	mhdr = (sapp_private_mem_t *)((char *)old_ptr - sizeof(sapp_private_mem_t));
	new_ptr = sapp_mem_calloc(type, thread_seq,size);
	memmove(new_ptr, old_ptr, mhdr->user_buf_size); 

	sapp_mem_free(type, thread_seq, old_ptr);

	return new_ptr;
}

/*
	============================
	TYPE		Number		Byte   Human_Byte
	============================
	Fixed
	----------------------------
	
	global					123
	xxx						456
	xxx						789
	=============================
	Dynamic
	-----------------------------
	stream					111
	half_stream				222
	tcp_unorder				333
	xxxx					444
	xxxx					555
	=============================
	total					9999
	=============================
*/

void sapp_mem_stat_output(void)
{
	FILE *fp;
	int tseq, stat_index;
	sapp_mem_used_stat_t dyn_realtime_stat = {};
	sapp_mem_used_stat_t fix_realtime_stat = {};
	const sapp_mem_used_stat_t *mem_used_stat;
	char human_string[1024];
	char time_string[128];

	/* 
	    防止哪天新增了一个类型, 而忘了加到 mem_stat_name_tuple[] 数组里, 或者顺序不对, 此处要校验一下.
	    
        TODO: 其实初始化验证一次就行, 没必要每次输出日志时都检查!!
	*/
	int stat_name_tuple_num = sizeof(mem_stat_name_tuple)/sizeof(mem_stat_name_tuple_t);
	assert(stat_name_tuple_num == __SAPP_MEM_TYPE_MAX);
	if(stat_name_tuple_num != __SAPP_MEM_TYPE_MAX){
		sapp_printf("\033[1;31;40m[Error] sizeof(mem_stat_name_tuple) is not equal with __SAPP_MEM_TYPE_MAX  \033[0m\n");
		exit(1);
	}

	for(stat_index = 0; stat_index < __SAPP_MEM_TYPE_MAX; stat_index++){
		if((int)mem_stat_name_tuple[stat_index].mem_type != stat_index){
			sapp_printf("\033[1;31;40m[Error] mem_stat_name_tuple[] array index:%d is not equal with mem_stat_name_tuple_t\033[0m\n", stat_index);
			exit(1);
		}
	}
	
	fp = fopen(ABBR_MEMORY_STAT_LOG_DATA_FILE,"w+");
	if(fp == NULL){
		sapp_printf("\033[1;31;40mopen %s error, %s\033[0m\n", ABBR_MEMORY_STAT_LOG_DATA_FILE, strerror(errno));
		return;
	}

	memset(&dyn_realtime_stat, 0, sizeof(dyn_realtime_stat));
	memset(&fix_realtime_stat, 0, sizeof(fix_realtime_stat));

	timet_to_str(ABBR_CURRENT_TIME, time_string, sizeof(time_string));

	fprintf(fp,"===================================================================================\n");
	fprintf(fp, "%s\n", time_string);
	fprintf(fp, "%7s %18s %18s %18s %18s\n", "Type", "Module", "Blocks", "Bytes", "Readable_Bytes");
	fprintf(fp,"-----------------------------------------------------------------------------------\n");
	fprintf(fp, "%7s\n", "Fixed");


	for(stat_index = __SAPP_MEM_TYPE_INIT + 1 ; stat_index < __SAPP_FIX_DYN_SEPARATOR; stat_index++){
		mem_used_stat = &sapp_global_val->individual_volatile->mem_used_stat;
		fix_realtime_stat.mem_used_block[stat_index] += mem_used_stat->mem_used_block[stat_index];
		fix_realtime_stat.mem_used_bytes[stat_index] += mem_used_stat->mem_used_bytes[stat_index];
	}
	/* 固定内存使用输出, SAPP_MEM_FIX_GLOBAL_VAL 比较特殊, 直接从全局变量中获取 */
	fix_realtime_stat.mem_used_block[SAPP_MEM_FIX_GLOBAL_VAL] = g_sapp_global_mem_used_block;
	fix_realtime_stat.mem_used_bytes[SAPP_MEM_FIX_GLOBAL_VAL] = g_sapp_global_mem_used_bytes;
	
	for(stat_index = __SAPP_MEM_TYPE_INIT + 1 ; stat_index < __SAPP_FIX_DYN_SEPARATOR; stat_index++){
		mem_used_stat = &sapp_global_val->individual_volatile->mem_used_stat;
		if(mem_used_stat->mem_used_block[stat_index] > 0){
			fprintf(fp, "%7s %18s %18lld %18lld %18s\n", 
					"",
					mem_stat_name_tuple[stat_index].mem_type_string, 
					fix_realtime_stat.mem_used_block[stat_index], 
					fix_realtime_stat.mem_used_bytes[stat_index], 
					byte_convert_human((unsigned long)fix_realtime_stat.mem_used_bytes[stat_index], 1, 1, human_string));
		}
	}

	fprintf(fp, "\n%7s\n", "Dynamic");
	
	/* 先把多个线程的数值求和 */
	for(tseq=0;tseq<g_packet_io_thread_num;tseq++){
		mem_used_stat = &sapp_global_val->mthread_volatile[tseq]->mem_used_stat;
		for(stat_index = __SAPP_MEM_TYPE_INIT+1; stat_index < __SAPP_MEM_TYPE_MAX; stat_index++){
			dyn_realtime_stat.mem_used_block[stat_index] += mem_used_stat->mem_used_block[stat_index];
			dyn_realtime_stat.mem_used_bytes[stat_index] += mem_used_stat->mem_used_bytes[stat_index];
		}
	}

	for(stat_index = __SAPP_FIX_DYN_SEPARATOR + 1 ; stat_index < __SAPP_MEM_TYPE_MAX; stat_index++){
		if(dyn_realtime_stat.mem_used_block[stat_index] != 0){
			fprintf(fp, "%7s %18s %18lld %18lld %18s\n", 
					"",
					mem_stat_name_tuple[stat_index].mem_type_string,  
					dyn_realtime_stat.mem_used_block[stat_index], 
					dyn_realtime_stat.mem_used_bytes[stat_index], 
					byte_convert_human((unsigned long)dyn_realtime_stat.mem_used_bytes[stat_index], 1, 1, human_string));
		}
	}

	long long tot_mem_block = 0, tot_mem_byte = 0;

	for(stat_index = __SAPP_MEM_TYPE_INIT + 1 ; stat_index < __SAPP_FIX_DYN_SEPARATOR; stat_index++){
		tot_mem_block += fix_realtime_stat.mem_used_block[stat_index];
		tot_mem_byte += fix_realtime_stat.mem_used_bytes[stat_index];
	}
	
	for(stat_index = __SAPP_MEM_TYPE_INIT + 1 ; stat_index < __SAPP_MEM_TYPE_MAX; stat_index++){
		tot_mem_block += dyn_realtime_stat.mem_used_block[stat_index];
		tot_mem_byte += dyn_realtime_stat.mem_used_bytes[stat_index];
	}
	
	fprintf(fp, "\n%7s\n", "Total");
	fprintf(fp, "%7s %18s %18lld %18lld %18s\n", "", "ALL", tot_mem_block, tot_mem_byte, 
				byte_convert_human((unsigned long)tot_mem_byte, 1, 1, human_string));
	fprintf(fp,"===================================================================================\n");
	fclose(fp);
}

char bloomfilter_stat_polling_entry(struct streaminfo *nouse1, void **nouse2, int thread_seq, void *nouse3)
{
	static time_t last_get_time[SAPP_MAX_THREADS] = {};

	if(ABBR_CURRENT_TIME <= last_get_time[thread_seq])
	{
		return POLLING_STATE_IDLE;
	} 

	long long blocks = 0, bytes = 0;
	bloomfilter_get_mem_stat(thread_seq, &blocks, &bytes);

	sapp_global_val->mthread_volatile[thread_seq]->mem_used_stat.mem_used_block[SAPP_MEM_DYN_BLOOM_FILTER] = blocks;
	sapp_global_val->mthread_volatile[thread_seq]->mem_used_stat.mem_used_bytes[SAPP_MEM_DYN_BLOOM_FILTER] = bytes;
	
	last_get_time[thread_seq] = ABBR_CURRENT_TIME;
	return POLLING_STATE_WORK;
}

int sapp_mem_init(void)
{
	if(sapp_global_val->config.packet_io.dup_pkt_para.kickout_udp_stream_enabled
	  || sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp
	  || sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_udp
	  || sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject)
	{
		stream_register_fun(FUN_TYPE_POLLING, (char (*)(void))bloomfilter_stat_polling_entry, 0);
	}
	return 0;
}

#ifdef __cplusplus
}
#endif

