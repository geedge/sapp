#include "sapp_api.h"
#include "sapp_private_api.h"
#include "sapp_declaration.h"

#ifdef __cplusplus
extern "C" {
#endif
extern void free_heap_stream_info(int mem_used_type, struct streaminfo *heap_stream, int layer);
extern struct streaminfo_private *copy_stream_info_to_heap(int mem_used_type, const struct streaminfo_private *stack_stream_pr, int reverse);		

struct streaminfo *skip_proxy_phony_stream(struct streaminfo *a_tcp);
static struct buf_unorder *tcp_save_unorder_pkt(struct streaminfo *a_tcp,const void *this_iphdr, 
	const raw_pkt_t *stack_raw_pkt,struct mesa_tcp_hdr *this_tcphdr, 
	unsigned char *tcpdata, int tcpdatalen);
static void tcp_free_unorder_pkt(int threadnum, struct buf_unorder *uo_packet);	
static int get_ip_pkt_tot_len(struct streaminfo *ipinfo, const void *this_iphdr);
static inline void update_stream_list_raw_pkt_pointer(struct streaminfo_private *a_tcp_pr, const raw_pkt_t *raw_pkt);
void addr_reverse_memcpy(const struct streaminfo_private *stack_pr,void *daddr, const void *saddr, int addrtype, int addrlen);
int copy_ipport_union_addr(struct streaminfo *pstream_heap, struct streaminfo *pstream_stack, int reverse);
void iterate_stream_list(const struct streaminfo *stream);
int del_stream_by_time(struct stream_list *plist, const struct streamindex *current_drive_index, int thread_id, enum stream_type_t type);


int G_TCP_FLOW_STAT_PROJECT_ID = -1; /* 2016-07-14 lijia copy from sapp */
int G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = -1;

#if DEBUG
static void packet_io_status_tcp_pkt_update(int tid, unsigned char tcp_flags, int payload_len);
#endif

#define CHECK_ORDER_DATA 1
#define FIN_SENT 120
#define FIN_CONFIRMED 121

#define REUSE_OLD_LINK 	1 
#define CTREAT_LINK		0

#define EXP_SEQ (rcv->first_data_seq + rcv->count_ideal )

static int tcp_deal_unorder(struct streamindex *pindex,struct streaminfo *a_tcp,
		struct  half_tcpstream  *rcv, struct half_tcpstream *snd,int orderflag);
		
inline static int before (u_int seq1, u_int seq2)
{
    return ((int) (seq1 - seq2) < 0);
}

inline static int after (u_int seq1, u_int seq2)
{
    return ((int) (seq2 - seq1) < 0);
}

static int checkcreatlinkseq(struct streaminfo_private*pstream_pr,int this_seq)
{
	int curseq=0;
	int seqdiff=0;
	struct streaminfo *pstream = (struct streaminfo*)(&pstream_pr->stream_public);
	struct tcpdetail_private *pdetail_pr = (struct tcpdetail_private *)pstream->pdetail;
	//struct tcpdetail *pdetail=(struct tcpdetail *)(&pdetail_pr->tcpdetail_public);
	 
	if(pstream->curdir == DIR_C2S)
	{
		curseq=pdetail_pr->iserverseq;
	}
	else
	{
		curseq=pdetail_pr->iclientseq;
	}
	//adjust by lqy 20120923 
	if(curseq==0) return 1;
	if(pdetail_pr->multisynflag==1)
	{
		if(pstream->curdir == DIR_C2S)
			pdetail_pr->iserverseq=this_seq;
		else
			pdetail_pr->iclientseq=this_seq;

		return 1;
	}
	seqdiff = (int)(this_seq - curseq);
	if ((seqdiff >= 0) &&(seqdiff <65536))
	{
		return 1;
	}
	
	return 0;
}

/* 
	return value:
		= 0: no option;
		> 0: opt number;
		< 0: error.
*/	
int MESA_get_tcp_pkt_opts(const struct tcphdr *tcphdr, struct tcp_option *raw_result, int res_num)
{
	int tcphdrlen = tcphdr->doff << 2;
	const unsigned char *opt;
	int opt_num = 0, opt_len;
	struct tcp_option *out_raw_result = raw_result;
	int parsed_opt; 

	if((NULL == raw_result) || (res_num <= 0)){
		return -1;
	}

	opt_len = tcphdrlen - sizeof(struct mesa_tcp_hdr);
	
	if(opt_len <= 0){
		return 0;
	}

	opt = (const unsigned char *)tcphdr + sizeof(struct mesa_tcp_hdr);

	while(opt_len > 0){
		parsed_opt = 0;
		int opsize=0;
		memset(out_raw_result, 0, sizeof(struct tcp_option));

		switch (*opt)
		{
		case TCP_OPT_EOL: 
			return opt_num;

		case TCP_OPT_NOP: 
			opt++;
			opt_len--; /* Ref: RFC 793 section 3.1 */
			continue;
		default:
			if (opt_len < 2)
			{
				return -1;
			}
			opsize = opt[1];
			if (opsize < 2) /* "silly options" */
			{
				return -1;
			}
			if (opsize > opt_len)
			{
				return -1;
			}
			switch (*opt)
			{
			case TCP_OPT_MSS:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_MSS;
				opt++;

				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 4)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->short_value = ntohs(*(unsigned short *)opt);
				opt += 2;
				parsed_opt = 1;

				opt_len -= 4;
				break;

			case TCP_OPT_WIN_SCALE:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_WIN_SCALE;
				opt++;

				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 3)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->char_value = *opt;
				opt++;
				parsed_opt = 1;

				opt_len -= 3;
				break;

			case TCP_OPT_SACK:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_SACK;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 2)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->char_value = 1; 
				opt_len -= 2;
				parsed_opt = 1;
				break;

			case TCP_OPT_TIME_STAMP:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_TIME_STAMP;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 10)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->opt_ts_val.ts_self = ntohl(*(unsigned int *)opt);
				opt += 4;
				out_raw_result->opt_ts_val.ts_echo_reply = ntohl(*(unsigned int *)opt);
				opt += 4;

				opt_len -= 10;
				parsed_opt = 1;
				break;

			case TCP_OPT_SACK_EDGE:
			case TCP_OPT_MD5:
			case TCP_OPT_MULTI_PATH_TCP:
			case TCP_OPT_RIVER_PROBE:
			{
				/*  */
				int this_opt_len;

				if (opt_len <= 1)
				{ 
					goto err;
				}
				this_opt_len = opt[1];
				if ((this_opt_len <= 0) || (this_opt_len > opt_len))
				{
					goto err;
				}
				opt_len -= this_opt_len;
				opt += this_opt_len;
				parsed_opt = 0;
			}
			break;

			default:
			{
				int this_opt_len;

				if (opt_len <= 1)
				{
					goto err;
				}
				this_opt_len = opt[1];
				if ((this_opt_len <= 0) || (this_opt_len > opt_len))
				{
					goto err;
				}
				opt_len -= this_opt_len;
				opt += this_opt_len;
				parsed_opt = 0;
			}
			}
		}

		if (parsed_opt)
		{
			out_raw_result++;
			opt_num++;
		}
	}

	return opt_num;
err:
	return -1;
}


/* 
	return value:
		= 0: no option;
		> 0: opt number;
		< 0: error.
*/	
int MESA_get_tcp_pkt_opts_ext(const struct tcphdr *tcphdr, struct tcp_option_ext *raw_result, int res_num)
{
	int tcphdrlen = tcphdr->doff << 2;
	const unsigned char *opt;
	int opt_num = 0, opt_len;
	struct tcp_option_ext *out_raw_result = raw_result;
	int parsed_opt;

	if((NULL == raw_result) || (res_num <= 0)){
		return -1;
	}

	opt_len = tcphdrlen - sizeof(struct mesa_tcp_hdr);
	
	if(opt_len <= 0){
		return 0;
	}

	opt = (const unsigned char *)tcphdr + sizeof(struct mesa_tcp_hdr);

	while(opt_len > 0){
		parsed_opt = 0;
		int opsize=0;
		memset(out_raw_result, 0, sizeof(struct tcp_option_ext));

		switch (*opt)
		{
		case TCP_OPT_EOL: 
			return opt_num;

		case TCP_OPT_NOP: 
			opt++;
			opt_len--; /* Ref: RFC 793 section 3.1 */
			continue;
		default:
			if (opt_len < 2)
			{
				return -1;
			}
			opsize = opt[1];
			if (opsize < 2) /* "silly options" */
			{
				return -1;
			}
			if (opsize > opt_len)
			{
				return -1;
			}
			switch (*opt)
			{
			case TCP_OPT_MSS:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_MSS;
				opt++;

				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 4)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->short_value = ntohs(*(unsigned short *)opt);
				opt += 2;
				parsed_opt = 1;

				opt_len -= 4;
				break;

			case TCP_OPT_WIN_SCALE:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_WIN_SCALE;
				opt++;

				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 3)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->char_value = *opt;
				opt++;
				parsed_opt = 1;

				opt_len -= 3;
				break;

			case TCP_OPT_SACK:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_SACK;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 2)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->char_value = 1; 
				opt_len -= 2;
				parsed_opt = 1;
				break;

			case TCP_OPT_TIME_STAMP:
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_TIME_STAMP;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if (out_raw_result->len != 10)
				{
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->opt_ts_val.ts_self = ntohl(*(unsigned int *)opt);
				opt += 4;
				out_raw_result->opt_ts_val.ts_echo_reply = ntohl(*(unsigned int *)opt);
				opt += 4;

				opt_len -= 10;
				parsed_opt = 1;
				break;

			case TCP_OPT_MULTI_PATH_TCP:
			{
				if (opt_num >= res_num)
				{
					goto err;
				}
				out_raw_result->type = TCP_OPT_MULTI_PATH_TCP;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				out_raw_result->len -= 2;
				memcpy(out_raw_result->variable_value, opt, out_raw_result->len);

				opt += out_raw_result->len;
				opt_len -= out_raw_result->len + 2;
				parsed_opt = 1;
			}
			break;

			case TCP_OPT_SACK_EDGE:
			case TCP_OPT_MD5:
			case TCP_OPT_RIVER_PROBE:
			{
				/*  */
				int this_opt_len;

				if (opt_len <= 1)
				{ 
					goto err;
				}
				this_opt_len = opt[1];
				if ((this_opt_len <= 0) || (this_opt_len > opt_len))
				{
					goto err;
				}
				opt_len -= this_opt_len;
				opt += this_opt_len;
				parsed_opt = 0;
			}
			break;

			default:
			{
				int this_opt_len;

				if (opt_len <= 1)
				{ 
					goto err;
				}
				this_opt_len = opt[1];
				if ((this_opt_len <= 0) || (this_opt_len > opt_len))
				{
					goto err;
				}
				opt_len -= this_opt_len;
				opt += this_opt_len;
				parsed_opt = 0;
			}
			break;
			}
		}

		if(parsed_opt){
			out_raw_result++;
			opt_num++;
		}
	}

	return opt_num;

err:
	return -1;
}

static void tcp_store_syn_state_opts(struct streaminfo_private *pstream_pr, char dir, 
									struct tcp_option *opts, int optnum)
{
	if(DIR_C2S == dir){
		if(NULL == pstream_pr->syn_opt_array){
			pstream_pr->syn_opt_array = (struct tcp_option *)sapp_mem_calloc(SAPP_MEM_DYN_TCP_SYN_OPT, pstream_pr->stream_public.threadnum, sizeof(struct tcp_option) * optnum);
			memcpy(pstream_pr->syn_opt_array, opts, sizeof(struct tcp_option) * optnum);
			pstream_pr->syn_opt_num = optnum;
		}
	}else{
		if(NULL == pstream_pr->synack_opt_array){
			pstream_pr->synack_opt_array = (struct tcp_option *)sapp_mem_calloc(SAPP_MEM_DYN_TCP_SYN_OPT, pstream_pr->stream_public.threadnum, sizeof(struct tcp_option) * optnum);
			memcpy(pstream_pr->synack_opt_array, opts, sizeof(struct tcp_option) * optnum);
			pstream_pr->synack_opt_num = optnum;
		}
	}
	
}

static inline void tcp_parse_opts(struct streaminfo_private *pstream_pr, char dir, const struct tcphdr *tcphdr)
{
	int ret;
	struct tcp_option local_tmp_opt_array[MAX_TCP_OPT_NUM];
	
	if(g_tcp_syn_option_parse_enabled){
		ret = MESA_get_tcp_pkt_opts((const struct tcphdr *)tcphdr, local_tmp_opt_array, MAX_TCP_OPT_NUM);
		if(ret > 0){
			tcp_store_syn_state_opts(pstream_pr, dir, local_tmp_opt_array, ret);
		}
	}
}

/* add by lqy 20150113 */
static char tcp_processallpkt( struct streaminfo *pstream, const void *this_iphdr, 
					struct mesa_tcp_hdr *this_tcphdr,int tcplen, const raw_pkt_t *raw_pkt)
{
	struct tcpdetail *pdetail=(struct tcpdetail *)(pstream->pdetail);
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)(pstream->pdetail);
	char ret=PASS;
	
	if(tcplen!=0)
	{
		pdetail->pdata=(char*)(this_tcphdr) + 4 * this_tcphdr->th_off;
		pdetail->datalen = tcplen;
	}
	else
	{
		pdetail->pdata=NULL;
		pdetail->datalen = 0;
	}
	ret=stream_process_tcp_allpkt(pstream,this_iphdr,(const void *)this_tcphdr, raw_pkt, &(pdetail_pr->pAllpktpme),&(pstream->pktstate));
	pdetail->pdata=NULL;
	pdetail->datalen = 0;
	
	return ret;
	
}



static struct streamindex *tcp_add_new_stream_bysyn(struct streamindex *pindex,
	const void *this_iphdr, struct mesa_tcp_hdr *this_tcphdr,int datalen,int resetflag, const raw_pkt_t *raw_pkt)
{
	struct streamindex *pindex_tcp=NULL;
	char createdir = DIR_C2S;
	unsigned char threadnum=pindex->stream.stream_public.threadnum;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	struct tcpdetail *pdetail=NULL;
	struct tcpdetail_private *pdetail_pr=NULL;
	int need_reverse = 0; 
	if ((this_tcphdr->th_flags & TH_SYN)
		&& !(this_tcphdr->th_flags & TH_ACK)
				)//&& !(this_tcphdr->th_flags & TH_RST)) 
	{
		createdir=DIR_C2S;
	}
	else if ((this_tcphdr->th_flags & TH_SYN)
			&& (this_tcphdr->th_flags & TH_ACK)
				)//&& !(this_tcphdr->th_flags & TH_RST))
	{
		createdir=DIR_S2C;
	}
	else
	{
		//runtime_log(RLOG_LV_FATAL, "[tcp_add_new_stream_bysyn]:","tcpflags=:%0x\n",this_tcphdr->th_flags);
		//adjust by lqy 20130530 
		if(resetflag==0)
			return NULL;
	}
	if(likely(0 == resetflag)){
		pindex_tcp=malloc_and_copy_streamindex(threadnum, pindex);
		
		//memcpy(pindex_tcp,pindex,sizeof(struct streamindex));
		pstream_pr = &pindex_tcp->stream;
		pstream = &pstream_pr->stream_public;		

		/* 2014-11-13 lijia modify */
		if(DIR_C2S == createdir){ 
			if(1 == pstream_pr->layer_dir){
				pstream_pr->stream_dir = 1; 
			}else{
				pstream_pr->stream_dir = 0;
			}
			need_reverse = 0;
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir;
		}else{
			need_reverse = 1; 
			if(1 == pstream_pr->layer_dir){
				pstream_pr->stream_dir = 0; 
			}else{
				pstream_pr->stream_dir = 1;
			}
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir ^ 1;
		}

#if USE_RBTREE_INSTEAD_LIST
		pstream_pr->layer_dir = pstream_pr->stream_dir;
#endif

		copy_ipport_union_addr(pstream, &pindex->stream.stream_public, need_reverse);

 		hash_add_stream(pindex_tcp);

		pstream_pr->pfather_pr = copy_stream_info_to_heap(SAPP_MEM_DYN_TCP_STREAM, (struct streaminfo_private *)pindex->stream.pfather_pr, need_reverse);	   
		pstream->pfather = (struct streaminfo *)pstream_pr->pfather_pr;
		
#if SAPP_INSECTICIDE
		iterate_stream_list(pstream);
#endif
		get_stream_carry_tunnel_type(pstream, NULL, &pstream_pr->stream_low_layer_tunnel_type);
		
#if 0
		//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream.addr);
		//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);

		if(0 == need_reverse){
			set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
		}else{
			set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
		}
#endif	
		pdetail_pr=(struct tcpdetail_private *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_DETAIL, threadnum,sizeof(struct tcpdetail_private));
		pdetail=&pdetail_pr->tcpdetail_public;
		pindex_tcp->stream.stream_public.pdetail=(void *)pdetail_pr;
		memset(pdetail_pr,0,sizeof(struct tcpdetail_private));   
		pdetail->createtime=g_CurrentTime;
		pstream_pr->stream_create_timestamp_ms=g_CurrentTime_ms;
		if(createdir==DIR_S2C){
			pdetail->clientpktnum++;
			pdetail->clientbytes+= datalen; /* 2014-12-19 lijia add, for SYN pkt append data */
			pdetail_pr->last_s2c_pkt_rcv_time = ABBR_CURRENT_TIME_MS;
			pdetail_pr->S2C_ack_seq = ntohl(this_tcphdr->th_ack);
		}else if(createdir==DIR_C2S){
			pdetail->serverpktnum++;
			pdetail->serverbytes+= datalen;/* 2014-12-19 lijia add, for SYN pkt append data */
			pdetail_pr->last_c2s_pkt_rcv_time = ABBR_CURRENT_TIME_MS;
			pdetail_pr->C2S_ack_seq = ntohl(this_tcphdr->th_ack);
		}	
		pdetail_pr->rtt_csc = 0xFFFF;
		pdetail_pr->rtt_scs = 0xFFFF;
	}
	else
	{
	 pindex_tcp = pindex;
	 pstream_pr = &pindex_tcp->stream;
	 pstream = &pstream_pr->stream_public;
	 pdetail_pr = (struct tcpdetail_private *)pstream->pdetail;
	 pdetail = (struct tcpdetail *)pdetail_pr;
	 // add by lqy 20150107, ???��???
	 if (createdir == DIR_S2C)
	 {
		 pdetail->clientpktnum = 1;
		 pdetail->clientbytes = datalen;
		 pdetail->serverpktnum = 0;
		 pdetail->serverbytes = 0;
		}
		else if(createdir==DIR_C2S)
		{
			pdetail->clientpktnum=0;
			pdetail->clientbytes=0;
			pdetail->serverpktnum=1;
			pdetail->serverbytes=datalen;
		}	   
		pstream_pr->stream_killed_flag = 0;
		pstream_pr->has_duplicate_pkt = 0;
		pdetail_pr->drop_stream_flag = 0;
		
		/* ???????, ??????????????streamid */
		pindex_tcp->stream.global_stream_id = get_global_stream_id(threadnum);
		pindex_tcp->stream.stream_trace_id=0;
		pdetail->createtime=g_CurrentTime;
		pstream_pr->stream_create_timestamp_ms=g_CurrentTime_ms;	

		/* ????????, ?????��????ddos ?? */
		if(pstream_pr->create_dir_by_well_known_port != 1)
		{
			pstream_pr->under_ddos_bypass = packet_io_under_ddos_should_bypass(threadnum);
            if (pstream_pr->under_ddos_bypass == 0 && G_MESA_GLOBAL_STREAM[threadnum]->tcp_opening_ratelimiter != NULL)
            {
				if(token_bucket_consume(G_MESA_GLOBAL_STREAM[threadnum]->tcp_opening_ratelimiter, 1,
                                         g_current_time_ms) == 0)
				{						 
                	pstream_pr->under_ddos_bypass = 1;
					sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;
					local_sys_stat->count[SAPP_STAT_TCP_OPENING_OVERSPEED]++;
				}
            }
        }
    }

	/* 2014-07-31 LiJia add, for set one stream unorder number */
	if(pdetail_pr->pclient){
		pdetail_pr->pclient->maxunorder = tcp_default_unorder;
	}
	if(pdetail_pr->pserver){
		pdetail_pr->pserver->maxunorder = tcp_default_unorder;
	}
	pstream_pr->set_special_timeout=0;
	pstream_pr->timeout=link_default_nopkt_time;
	pdetail_pr->creat_mod=TCP_CTEAT_LINK_BYSYN;	
	
	pstream->dir=createdir;
	pstream->curdir=createdir;
	if(tcp_support_all==TCP_SUPPORT_ENTRYALL_OFF)
	{
		pstream->pktstate=OP_STATE_CLOSE;
	}
	else
	{
		pstream->pktstate=OP_STATE_PENDING;
	}
	pstream->opstate=OP_STATE_PENDING;
	pdetail_pr->tcpstateflag=TCP_SYN_SENT; 

	if(createdir==DIR_S2C)
	{
		pdetail_pr->iclientseq =ntohl (this_tcphdr->th_seq) + 1;
		pdetail_pr->iserverseq=ntohl (this_tcphdr->th_ack);
		pdetail_pr->S2C_first_ack_seq = pdetail_pr->iserverseq;
	}
	else if(createdir==DIR_C2S)
	{
		pdetail_pr->iclientseq = 0; 
		pdetail_pr->iserverseq=ntohl (this_tcphdr->th_seq)+1;
		//pdetail->serverpkt++; //adjust by lqy 20140515 ???????????
		pdetail_pr->C2S_first_ack_seq = ntohl (this_tcphdr->th_ack);
	}
	pdetail->lastmtime=g_CurrentTime;	
	pstream_pr->stream_lastupdate_timestamp_ms=g_CurrentTime_ms;	
	pdetail_pr->link_state=STREAM_LINK_JUST_EST;	
	pstream->stream_state=TCP_SYN_STATE;

	if(pstream_pr->under_ddos_bypass){
		pstream->stream_state=TCP_NOUSE_STATE;
		streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));
		return pindex_tcp;
	}
	streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));

	pstream_pr->pproject = project_requirement_create(SAPP_MEM_DYN_TCP_PROJECT, pstream->threadnum);
	pstream_pr->stream_bridge = stream_bridge_create_per_stream(SAPP_MEM_DYN_TCP_BRIDGE, pstream->threadnum);

	/* 2015-12-28 lijia add */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->flow_stat = (struct tcp_flow_stat *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_FLOW_STAT, pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);

		int frag_cnt = 0;
		int frag_len = 0;
		stream_get_scratch_frag_stat(pstream, &frag_cnt, &frag_len);	

		if(0 == resetflag){
			if(DIR_C2S == pstream->curdir){
				pdetail_pr->flow_stat->C2S_syn_pkt++;
				if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
				{
					pdetail_pr->flow_stat->C2S_ip_fragment_pkt+=MAX(1,frag_cnt);
					pdetail_pr->flow_stat->C2S_all_pkt+= MAX(1,frag_cnt);
					pdetail_pr->flow_stat->C2S_all_byte += MAX(datalen, frag_len);
					pdetail_pr->flow_stat->C2S_all_byte_raw += MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes, frag_len);					
				}
				else
				{
                    pdetail_pr->flow_stat->C2S_all_pkt++;
                    pdetail_pr->flow_stat->C2S_all_byte += datalen;
                    pdetail_pr->flow_stat->C2S_all_byte_raw +=
                        MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes, 0);
                }
			}else{
				pdetail_pr->flow_stat->S2C_syn_pkt++;
				if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
				{
					pdetail_pr->flow_stat->S2C_ip_fragment_pkt+=MAX(1,frag_cnt);
					pdetail_pr->flow_stat->S2C_all_pkt+=MAX(1,frag_cnt);
					pdetail_pr->flow_stat->S2C_all_byte += MAX(datalen, frag_len);
					pdetail_pr->flow_stat->S2C_all_byte_raw += MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,frag_len);
				}
				else
				{
					pdetail_pr->flow_stat->S2C_all_pkt++;
					pdetail_pr->flow_stat->S2C_all_byte += datalen;
					pdetail_pr->flow_stat->S2C_all_byte_raw += MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
				}
			}
		}else{
			if(DIR_C2S == pstream->curdir){
				pdetail_pr->flow_stat->C2S_syn_pkt = 1;
				if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
				{
					pdetail_pr->flow_stat->C2S_all_pkt += MAX(1,frag_cnt);
					pdetail_pr->flow_stat->C2S_all_byte = MAX(datalen, frag_len);
					pdetail_pr->flow_stat->C2S_all_byte_raw = MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes, frag_len);					
					pdetail_pr->flow_stat->C2S_ip_fragment_pkt+= MAX(1,frag_cnt);
				}
				else
				{
					pdetail_pr->flow_stat->C2S_all_pkt = 1;
					pdetail_pr->flow_stat->C2S_all_byte = datalen;
					pdetail_pr->flow_stat->C2S_all_byte_raw = MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
					pdetail_pr->flow_stat->C2S_ip_fragment_pkt=0;
				}
			}else{
				pdetail_pr->flow_stat->S2C_syn_pkt = 1;

				if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
				{
					pdetail_pr->flow_stat->S2C_all_pkt += MAX(1,frag_cnt);
					pdetail_pr->flow_stat->S2C_all_byte = MAX(datalen, frag_len);
					pdetail_pr->flow_stat->S2C_all_byte_raw = MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,frag_len);
					pdetail_pr->flow_stat->S2C_ip_fragment_pkt+= MAX(1,frag_cnt);
				}
				else
				{
					pdetail_pr->flow_stat->S2C_all_pkt = 1;
					pdetail_pr->flow_stat->S2C_all_byte = datalen;
					pdetail_pr->flow_stat->S2C_all_byte_raw = MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
					pdetail_pr->flow_stat->S2C_ip_fragment_pkt=0;
				}
			}
		}
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->deduce_flow_stat = (struct tcp_flow_stat *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_FLOW_STAT, pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->deduce_flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID, pdetail_pr->deduce_flow_stat);

		if(DIR_S2C == createdir){
			pdetail_pr->S2C_first_ack_seq = ntohl(this_tcphdr->th_ack);
		}else{
			; 
		}
	}

	tcp_parse_opts(pstream_pr, createdir, (const struct tcphdr *)this_tcphdr); /* 2016-07-07 lijia add, for janus hijack */


#if SAPP_INSECTICIDE
	iterate_stream_list(pstream);
#endif

	save_polling_inject_context(SAPP_MEM_DYN_TCP_POLLING_RAW_PKT, pstream_pr, raw_pkt);

	pdetail_pr->auto_remedy_flag = sapp_global_val->config.stream.tcp.inject.auto_remedy;

	return pindex_tcp;
}

static struct streamindex *tcp_add_new_stream_bydata(struct streamindex *pindex,
 struct mesa_tcp_hdr *this_tcphdr, int datalen, int resetflag, const raw_pkt_t * raw_pkt)
{
	struct streamindex *pindex_tcp=NULL;
	struct tcpdetail *pdetail=NULL;
	struct tcpdetail_private *pdetail_pr=NULL;
	char createdir;
	unsigned char threadnum=pindex->stream.stream_public.threadnum;
	struct streaminfo_private *pstream_pr;
	struct streaminfo *pstream;
	struct streaminfo *pstream_src=(struct streaminfo *)(&(pindex->stream));

	createdir=pstream_src->curdir;

	if(likely(0 == resetflag)){
		pindex_tcp=malloc_and_copy_streamindex(threadnum, pindex);
		pstream_pr = &pindex_tcp->stream;
		pstream = &pstream_pr->stream_public;	

		if(createdir==DIR_C2S){
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir;
		}else{
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir ^ 1;
		}

 		copy_ipport_union_addr(pstream, &pindex->stream.stream_public, pstream_pr->layer_dir ^1);
 		
 		pstream_pr->pfather_pr = copy_stream_info_to_heap(SAPP_MEM_DYN_TCP_STREAM,(struct streaminfo_private *)(pindex->stream.pfather_pr),  pstream_pr->layer_dir ^1);
 		pstream->pfather = (struct streaminfo *)pstream_pr->pfather_pr;

#if SAPP_INSECTICIDE
		iterate_stream_list(pstream);
#endif

		get_stream_carry_tunnel_type(pstream, NULL, &pstream_pr->stream_low_layer_tunnel_type);
		
		pstream->dir=createdir;
		pstream->curdir=createdir;
		pdetail_pr=(struct tcpdetail_private *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_DETAIL, threadnum,sizeof(struct tcpdetail_private));
		pdetail=&pdetail_pr->tcpdetail_public;
		memset(pdetail_pr,0,sizeof(struct tcpdetail_private));
		pstream->pdetail=(void *)pdetail_pr;

#if USE_RBTREE_INSTEAD_LIST
		if(1 == pstream_pr->layer_dir){
			pstream_pr->stream_dir  = 1; 
			//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
			//set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
		}else{
			pstream_pr->stream_dir  = 1; 
			//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1; 
			//set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
		}

		pstream_pr->layer_dir = 1;
#endif

		hash_add_stream(pindex_tcp); 
	}else{
		pindex_tcp=pindex;
		pstream_pr=&(pindex_tcp->stream);
		pstream=(struct streaminfo *)pstream_pr;
		pstream->dir=createdir;
		pstream->curdir=createdir;		
		pdetail_pr=(struct tcpdetail_private*)pstream->pdetail;
		pdetail=(struct tcpdetail *)pdetail_pr;
		
		//add by lqy 20150107
		if(createdir==DIR_S2C)
		{
			pdetail->clientpktnum=1;
			pdetail->clientbytes=datalen;
			pdetail->serverpktnum=0;
			pdetail->serverbytes=0;
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir ^ 1;
		}
		else if(createdir==DIR_C2S)
		{
			pdetail->clientpktnum=0;
			pdetail->clientbytes=0;
			pdetail->serverpktnum=1;
			pdetail->serverbytes=datalen;
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir;
		}
		pstream_pr->stream_killed_flag = 0;
		pindex_tcp->stream.global_stream_id = get_global_stream_id(threadnum);	
		pindex_tcp->stream.stream_trace_id=0;

		if(pstream_pr->create_dir_by_well_known_port != 1)
		{
			pstream_pr->under_ddos_bypass = packet_io_under_ddos_should_bypass(threadnum);
		}
	}

	pstream->dir=createdir;
	pstream->curdir=createdir;
	//pindex_tcp->stream.stream_dir=pindex_tcp->stream.layer_dir;

	if((datalen>0) && (!(this_tcphdr->th_flags & TH_FIN)) && (!(this_tcphdr->th_flags & TH_RST)))	
	{
		pstream->stream_state=TCP_DATA_STATE;
	}
	else
	{
		pstream->stream_state=TCP_NOUSE_STATE;	
	}
	
	//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream.addr);
	//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);

 #if 0	
	set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);
#else  /* 2014-12-16 lijia modify */
	if(1 == pstream_pr->layer_dir){
		pstream_pr->stream_dir  = 1; 
		//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
		//set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
	}else{
		pstream_pr->stream_dir  = 1; 
		//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1; 
		//set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
	}
#endif
	pstream_pr->set_special_timeout=0;
	pstream_pr->timeout=link_default_nopkt_time;
	pdetail_pr->creat_mod=TCP_CTEAT_LINK_BYDATA;	
	pstream->opstate=OP_STATE_PENDING;
    if (tcp_support_all == TCP_SUPPORT_ENTRYALL_OFF) // by lqy 20141213
    {
        pstream->pktstate = OP_STATE_CLOSE;
    }
    else
    {
        pstream->pktstate = OP_STATE_PENDING;
    }
    pdetail->createtime=g_CurrentTime;	
	pdetail->lastmtime=g_CurrentTime;
	pstream_pr->stream_create_timestamp_ms=g_CurrentTime_ms;
	pstream_pr->stream_lastupdate_timestamp_ms=g_CurrentTime_ms;
	pdetail_pr->link_state=STREAM_LINK_DATA;	

	if(pstream_pr->under_ddos_bypass){
		pstream->stream_state=TCP_NOUSE_STATE;
		streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));
		return pindex_tcp;
	}
	
	streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));
	
	//if(datalen>0)
	if((datalen>0) && (!(this_tcphdr->th_flags & TH_FIN)) && (!(this_tcphdr->th_flags & TH_RST)))	
	{
		if(pstream->dir==DIR_C2S)
		{
			pdetail_pr->pserver=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM, threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
			pdetail_pr->pserver->first_data_seq=(ntohl (this_tcphdr->th_seq) );
			/* 2014-07-31 LiJia add, for set one stream unorder number */
			pdetail_pr->pserver->maxunorder = tcp_default_unorder;
		}
		 if(pstream->dir == DIR_S2C)
		{
			pdetail_pr->pclient=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
			pdetail_pr->pclient->first_data_seq=(ntohl (this_tcphdr->th_seq) );
			/* 2014-07-31 LiJia add, for set one stream unorder number */
			pdetail_pr->pclient->maxunorder = tcp_default_unorder;
		}
	}
	else 
	{
		if(createdir==DIR_S2C)
		{
			
			pdetail_pr->iclientseq =ntohl (this_tcphdr->th_seq) ;
			pdetail_pr->iserverseq=ntohl (this_tcphdr->th_ack);
			
		}
		else if(createdir==DIR_C2S)
		{
			pdetail_pr->iserverseq=ntohl (this_tcphdr->th_seq);
			pdetail_pr->iclientseq=ntohl (this_tcphdr->th_ack);
		}
	}
	pstream->pdetail=(void *)pdetail_pr;

	pstream_pr->pproject = project_requirement_create(SAPP_MEM_DYN_TCP_PROJECT,threadnum);
	pstream_pr->stream_bridge = stream_bridge_create_per_stream(SAPP_MEM_DYN_TCP_BRIDGE,pstream->threadnum);

	/* 2016-07-14 lijia add */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->flow_stat = (struct tcp_flow_stat *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_FLOW_STAT, pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);

		int frag_cnt = 0, frag_len = 0;
		stream_get_scratch_frag_stat(pstream, &frag_cnt, &frag_len);	

		if(resetflag != 0){
			if(pstream->curdir == DIR_C2S){

				if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
				{
					pdetail_pr->flow_stat->C2S_all_pkt =  MAX(1, frag_cnt);
					pdetail_pr->flow_stat->C2S_all_byte = MAX(datalen, frag_len);
					pdetail_pr->flow_stat->C2S_all_byte_raw =MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,frag_len);
					pdetail_pr->flow_stat->C2S_ip_fragment_pkt=MAX(1, frag_cnt);
				}
				else
				{
					pdetail_pr->flow_stat->C2S_all_pkt = 1;
					pdetail_pr->flow_stat->C2S_all_byte = datalen;
					pdetail_pr->flow_stat->C2S_all_byte_raw =MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
					pdetail_pr->flow_stat->C2S_ip_fragment_pkt=0;
				}
			}else{

				if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
				{
					pdetail_pr->flow_stat->S2C_all_pkt = MAX(1, frag_cnt);
					pdetail_pr->flow_stat->S2C_all_byte = MAX(datalen, frag_len);
					pdetail_pr->flow_stat->S2C_all_byte_raw = MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes,frag_len);
					pdetail_pr->flow_stat->S2C_ip_fragment_pkt=MAX(1, frag_cnt);
				}
				else
				{
					pdetail_pr->flow_stat->S2C_all_pkt = 1;
					pdetail_pr->flow_stat->S2C_all_byte = datalen;	
					pdetail_pr->flow_stat->S2C_all_byte_raw = MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes,0);
					pdetail_pr->flow_stat->S2C_ip_fragment_pkt=0;
				}
			}
		}
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->deduce_flow_stat = (struct tcp_flow_stat *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_FLOW_STAT,pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->deduce_flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID, pdetail_pr->deduce_flow_stat);

		if(DIR_C2S == createdir){
			pdetail_pr->C2S_first_ack_seq = ntohl(this_tcphdr->th_ack);
		}else{
			pdetail_pr->S2C_first_ack_seq = ntohl(this_tcphdr->th_ack);
		}
	}
	
#if SAPP_INSECTICIDE
	iterate_stream_list(pstream);
#endif

	save_polling_inject_context(SAPP_MEM_DYN_TCP_POLLING_RAW_PKT, pstream_pr, raw_pkt);

	pdetail_pr->auto_remedy_flag = sapp_global_val->config.stream.tcp.inject.auto_remedy;

	if(pstream_pr->create_dir_by_well_known_port){
		sapp_runtime_log(RLOG_LV_DEBUG, "create new TCP stream without SYN:%s by well known port, the first packet curdir is:%d",
						printaddr(&pstream->addr, threadnum), pstream->curdir);
	}	

	return pindex_tcp;
}


static void tcp_change_stream_todata(struct streamindex *pindex,struct mesa_tcp_hdr *this_tcphdr,int datalen)
{
	struct stream_list *plist;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)pstream->pdetail;
	//struct tcpdetail *pdetail = &pdetail_pr->tcpdetail_public;
	unsigned char threadnum=pstream->threadnum;

	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]);
	streamleavlist(pindex,plist);

	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[TCP_DATA_STATE]);
	pstream->stream_state=TCP_DATA_STATE;
	streamaddlist(pindex,plist);
	
	pdetail_pr->link_state=STREAM_LINK_DATA;
	pdetail_pr->tcpstateflag=TCP_ESTABLISHED;

	// pstream->opstate=OP_STATE_PENDING; //for TFO , can't set to PENDING state
	
	if(pstream->dir & DIR_C2S)
	{
		if(NULL == pdetail_pr->pserver){
			pdetail_pr->pserver=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
			//??????
			pdetail_pr->pserver->first_data_seq=pdetail_pr->iserverseq;
			
			/* 2014-10-20 LiJia add, for set one stream unorder number */
			pdetail_pr->pserver->maxunorder = tcp_default_unorder;
		}
	}
	 if(pstream->dir & DIR_S2C)
	{
		if(NULL == pdetail_pr->pclient){
			pdetail_pr->pclient=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
			pdetail_pr->pclient->first_data_seq=pdetail_pr->iclientseq;
			
			/* 2014-10-20 LiJia add, for set one stream unorder number */
			pdetail_pr->pclient->maxunorder = tcp_default_unorder;
		}
	}

}


static void tcp_free_half(struct half_tcpstream *phalf,int threadnum)
{
  struct buf_unorder *plist,*ptmp;
  plist = phalf->unorderlist;
  while (plist)
  {
		ptmp = plist->next;
		tcp_free_unorder_pkt(threadnum, plist);		
		plist = ptmp;
	}
	sapp_mem_free(SAPP_MEM_DYN_TCP_HALF_STREAM, threadnum,phalf);
	//phalf = NULL;
}

static int inline stream_in_timeout_list(const struct streamindex *pindex, const struct stream_list *plist)
{
	if(timeout_pending((struct timeout *)&(pindex->timeout)))
	{
		return 1;
	}
	return 0;

}

static void tcp_change_stream_tonouse(struct streamindex *pindex)
{
	struct stream_list *plist;
	//struct tcpdetail *pdetail=NULL;
	struct tcpdetail_private *pdetail_pr=NULL;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	int threadnum=pstream->threadnum;

	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]);

	if(stream_in_timeout_list(pindex, plist) == 0){
		return;
	}

	streamleavlist(pindex,plist);

	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[TCP_NOUSE_STATE]);
	pstream->stream_state=TCP_NOUSE_STATE;
	streamaddlist(pindex,plist);

	pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
	if(pdetail_pr->pclient)
	{
		tcp_free_half(pdetail_pr->pclient,threadnum);
		pdetail_pr->pclient = NULL;
	}

	if(pdetail_pr->pserver)
	{
		tcp_free_half(pdetail_pr->pserver,threadnum);
		pdetail_pr->pserver = NULL;
	}

	del_stream_by_time(plist, pindex, threadnum, STREAM_TYPE_TCP);
}


static inline void tcp_update_should_close_reason_stat(int tid)
{
	sapp_gval_mthread_sys_stat_t *local_sys_stat;
	
	local_sys_stat = &sapp_global_val->mthread_volatile[tid]->sys_stat;
	
	local_sys_stat->count[SAPP_STAT_TCP_SHOULD_CLOSE_BUT_TCPALL]++;

	return;
}


static inline void tcp_update_close_reason_stat(int tid, const struct tcpdetail_private *pdetail_pr)
{
	sapp_gval_mthread_sys_stat_t *local_sys_stat;
	
	local_sys_stat = &sapp_global_val->mthread_volatile[tid]->sys_stat;
	
	switch(pdetail_pr->link_state){
		case STREAM_LINK_CLOSE:
			local_sys_stat->count[SAPP_STAT_TCP_CLOSE_BY_FIN]++;
		break;

		case STREAM_LINK_RESET:
			local_sys_stat->count[SAPP_STAT_TCP_CLOSE_BY_RST]++;
		break;

		case STREAM_LINK_TIMEOUT:
			local_sys_stat->count[SAPP_STAT_TCP_CLOSE_BY_TIMEOUT]++;
		break;

		case STREAM_LINK_LRU_OUT:
			local_sys_stat->count[SAPP_STAT_TCP_CLOSE_BY_KICKOUT]++;
		break;

		case STREAM_CLOSE_BY_DUMPFILE_END:
			local_sys_stat->count[SAPP_STAT_TCP_CLOSE_BY_DUMPFILE_END]++;
		break;

		default:
		break;
	}

	return;
}


//void tcp_free_stream(struct streamindex *pindex)
//add raw_pkt by lqy 2015-01-07
/* 2017-07-14 lijia add return value, for WY master and slave mode, last packet also need assign forward action */
int tcp_free_stream(struct streamindex *pindex, const void *this_ip_hdr, const void *transport_hdr,  const raw_pkt_t *raw_pkt)
{
	struct stream_list *plist=NULL;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)pstream->pdetail;
	struct half_tcpstream *pclient = pdetail_pr->pclient;
	struct half_tcpstream *pserver = pdetail_pr->pserver;
	UCHAR  saved_curdir;
	pstream->addr.pkttype = PKT_TYPE_NORMAL;
	UCHAR threadnum = pstream->threadnum;
	int pkt_ret = PASS;

	tcp_update_close_reason_stat(threadnum, pdetail_pr);
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]);

	saved_curdir = pstream->curdir;
	if(pclient && (pclient->unorderlist != NULL)){
		pstream->curdir = DIR_S2C; 
		tcp_deal_unorder(pindex, pstream, pclient, pserver, !CHECK_ORDER_DATA);		
	}
	if(pserver && (pserver->unorderlist != NULL)){
		pstream->curdir = DIR_C2S; 
		tcp_deal_unorder(pindex, pstream, pserver, pclient, !CHECK_ORDER_DATA);		
	}
	pstream->curdir = saved_curdir;

	pstream_pr->raw_pkt = raw_pkt; 

    if (pdetail_pr->apme != NULL)
    {
        pstream->opstate = OP_STATE_CLOSE;
        pkt_ret =
            stream_process_tcp(pstream, this_ip_hdr, transport_hdr, raw_pkt, &(pdetail_pr->apme), &(pstream->opstate));
        pdetail_pr->apme = NULL;
    }

    if(pdetail_pr->pAllpktpme!=NULL)
	{
			pstream->pktstate=OP_STATE_CLOSE;
			pkt_ret = stream_process_tcp_allpkt(pstream, this_ip_hdr, transport_hdr, raw_pkt, &(pdetail_pr->pAllpktpme),&(pstream->pktstate)); 
			pdetail_pr->pAllpktpme=NULL;
	}

	stream_bridge_destroy_per_stream(SAPP_MEM_DYN_TCP_BRIDGE, pstream, pstream_pr->stream_bridge);
	pstream_pr->stream_bridge = NULL;
	project_requirement_destroy(SAPP_MEM_DYN_TCP_PROJECT, threadnum, pstream_pr->pproject);
	pstream_pr->pproject = NULL;
    if (pclient)
    {
            tcp_free_half(pclient, threadnum);
            pclient = NULL;
    }
    if (pserver)
    {
            tcp_free_half(pserver, threadnum);
            pserver = NULL;
    }
	streamleavlist(pindex, plist);
	hash_del_stream(pindex);
	
	if(pstream->pdetail != NULL)
	{
		sapp_mem_free(SAPP_MEM_DYN_TCP_DETAIL, threadnum,pstream->pdetail);
		pstream->pdetail=NULL;
	}



	if(pstream_pr->set_special_timeout != 0){ 
		sapp_global_mthread[threadnum].tcp_stream_special_timeout_num--;
	}
	
	free_heap_stream_info(SAPP_MEM_DYN_TCP_STREAM, pstream, 0);

	if(pstream_pr->syn_opt_array){
		sapp_mem_free(SAPP_MEM_DYN_TCP_SYN_OPT, threadnum, pstream_pr->syn_opt_array);
		pstream_pr->syn_opt_array = NULL;
	}

	if(pstream_pr->synack_opt_array){
		sapp_mem_free(SAPP_MEM_DYN_TCP_SYN_OPT, threadnum, pstream_pr->synack_opt_array);
		pstream_pr->synack_opt_array = NULL;
	}

	free_polling_inject_context(SAPP_MEM_DYN_TCP_POLLING_RAW_PKT, pstream_pr);

	if(pstream_pr->sid_append_list){
		sapp_mem_free(SAPP_MEM_DYN_SID_LIST, threadnum, pstream_pr->sid_append_list);
		pstream_pr->sid_append_list = NULL;
	}

	if(pstream_pr->sid_prepend_list){
		sapp_mem_free(SAPP_MEM_DYN_SID_LIST, threadnum, pstream_pr->sid_prepend_list);
		pstream_pr->sid_prepend_list = NULL;
	}	

	if(raw_pkt)
	{
		((raw_pkt_t *)raw_pkt)->append_list=NULL;
		((raw_pkt_t *)raw_pkt)->prepend_list=NULL;
	}


	free_streamindex(threadnum,pindex);
	
	return pkt_ret;
}

/*
	return value:
		1: reset and create new stream;
		0: reset but free current stream;
*/
static int tcp_reset_stream(struct streamindex *pindex,const void *this_iphdr,
				struct mesa_tcp_hdr *this_tcphdr,int datalen,const raw_pkt_t *raw_pkt)
{
	struct stream_list *plist=NULL;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)pstream->pdetail;
	struct tcpdetail *pdetail = &pdetail_pr->tcpdetail_public;
	UCHAR threadnum = pstream->threadnum;
	UCHAR saved_curdir;
	int ret = 0;
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[threadnum]->sys_stat;
	
        if(pstream->curdir==DIR_S2C)
        {
                pdetail->clientpktnum--;
                pdetail->clientbytes-=datalen;
        }
        else
        {
                pdetail->serverpktnum--;
                pdetail->serverbytes-=datalen;
        }

	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->flow_stat->C2S_all_pkt--;
			pdetail_pr->flow_stat->C2S_all_byte -= datalen;
			pdetail_pr->flow_stat->C2S_all_byte_raw -= raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
		}else{
			pdetail_pr->flow_stat->S2C_all_pkt--;
			pdetail_pr->flow_stat->S2C_all_byte -= datalen;
			pdetail_pr->flow_stat->S2C_all_byte_raw -= raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
		}
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->deduce_flow_stat->C2S_all_pkt--;
			pdetail_pr->deduce_flow_stat->C2S_all_byte -= datalen - raw_pkt->overlay_layer_bytes;
		}else{
			pdetail_pr->deduce_flow_stat->S2C_all_pkt--;
			pdetail_pr->deduce_flow_stat->S2C_all_byte -= datalen - raw_pkt->overlay_layer_bytes;
		}
	}
	
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]);

	saved_curdir = pstream->curdir; 
	if(pdetail_pr->pclient && pdetail_pr->pclient->unorderlist != NULL){
		pstream->curdir = DIR_S2C; 
		tcp_deal_unorder(pindex, pstream, pdetail_pr->pclient, pdetail_pr->pserver, !CHECK_ORDER_DATA);		
	}
	if(pdetail_pr->pserver && pdetail_pr->pserver->unorderlist != NULL){
		pstream->curdir = DIR_C2S;
		tcp_deal_unorder(pindex, pstream, pdetail_pr->pserver, pdetail_pr->pclient, !CHECK_ORDER_DATA);		
	}
	pstream_pr->raw_pkt = raw_pkt;
	pstream->curdir = saved_curdir;

	const raw_pkt_t *saved_raw_pkt = pstream_pr->raw_pkt;
	pstream_pr->raw_pkt = NULL; 
	pstream_pr->stream_killed_flag = 0;

    if (pdetail_pr->apme != NULL)
    {
        pstream->opstate = OP_STATE_CLOSE;
        stream_process_tcp(pstream, NULL, NULL, NULL, &(pdetail_pr->apme), &(pstream->opstate));
        pdetail_pr->apme = NULL;
    }
    if (pdetail_pr->pclient != NULL)
    {
        tcp_free_half(pdetail_pr->pclient, threadnum);
        pdetail_pr->pclient = NULL;
    }
    if (pdetail_pr->pserver != NULL)
    {
        tcp_free_half(pdetail_pr->pserver, threadnum);
        pdetail_pr->pserver = NULL;
    }

    if(pdetail_pr->pAllpktpme!=NULL)
	{
			pstream->pktstate=OP_STATE_CLOSE;
			stream_process_tcp_allpkt(pstream,NULL,NULL,NULL,&(pdetail_pr->pAllpktpme),&(pstream->pktstate));  
			pdetail_pr->pAllpktpme=NULL;
	}
	stream_bridge_destroy_per_stream(SAPP_MEM_DYN_TCP_BRIDGE, pstream, pstream_pr->stream_bridge);
	pstream_pr->stream_bridge = NULL;
	
	project_requirement_destroy(SAPP_MEM_DYN_TCP_PROJECT, threadnum, pstream_pr->pproject);
	pstream_pr->pproject = NULL;


	
	streamleavlist(pindex, plist);
	


	pstream_pr->raw_pkt = saved_raw_pkt;

	pstream_pr->syn_opt_num = 0;     
	pstream_pr->synack_opt_num = 0; 
	if(pstream_pr->syn_opt_array){
		sapp_mem_free(SAPP_MEM_DYN_TCP_SYN_OPT, threadnum, pstream_pr->syn_opt_array);
		pstream_pr->syn_opt_array = NULL;
	}

	if(pstream_pr->synack_opt_array){
		sapp_mem_free(SAPP_MEM_DYN_TCP_SYN_OPT, threadnum, pstream_pr->synack_opt_array);
		pstream_pr->synack_opt_array = NULL;
	}

	free_polling_inject_context(SAPP_MEM_DYN_TCP_POLLING_RAW_PKT, pstream_pr); //2020-06-08 lijia add, for memory leak

	if(pstream_pr->sid_append_list){
		sapp_mem_free(SAPP_MEM_DYN_SID_LIST, threadnum, pstream_pr->sid_append_list);
		pstream_pr->sid_append_list = NULL;
	}
	
	if(pstream_pr->sid_prepend_list){
		sapp_mem_free(SAPP_MEM_DYN_SID_LIST, threadnum, pstream_pr->sid_prepend_list);
		pstream_pr->sid_prepend_list = NULL;
	}	

	if(raw_pkt)
	{
		((raw_pkt_t *)raw_pkt)->append_list=NULL;
		((raw_pkt_t *)raw_pkt)->prepend_list=NULL;
	}

	if (pstream_pr->set_special_timeout != 0)
	{ 
		sapp_global_mthread[threadnum].tcp_stream_special_timeout_num--;
	}
	if(this_tcphdr->th_flags & TH_SYN){
		tcp_add_new_stream_bysyn(pindex,this_iphdr,this_tcphdr,datalen,REUSE_OLD_LINK,raw_pkt);
		ret = 1;
	}else{
		if(TCP_CTEAT_LINK_BYDATA & tcp_creatlink_model){
			tcp_add_new_stream_bydata(pindex,this_tcphdr,datalen,REUSE_OLD_LINK, raw_pkt);
			ret = 1;
		}else{
			hash_del_stream(pindex);
			if(pstream->pdetail != NULL)
			{
				sapp_mem_free(SAPP_MEM_DYN_TCP_DETAIL, threadnum,pstream->pdetail);
				pstream->pdetail=NULL;
			}			
			free_heap_stream_info(SAPP_MEM_DYN_TCP_STREAM, pstream, 0);
			free_streamindex(threadnum,pindex);
			ret = 0;
		}
	}	

	local_sys_stat->count[SAPP_STAT_TCP_STREAM_RESET]++;
	return ret;
}

static void inline calculate_tcp_rtt(const struct streaminfo *pstream, struct tcpdetail_private *pdetail_pr, const struct mesa_tcp_hdr *this_tcphdr)
{
	if(pdetail_pr->tcpdetail_public.clientpktnum < 1 || pdetail_pr->tcpdetail_public.serverpktnum < 1)
	{
		return;
	}
	if(pdetail_pr->rtt_csc != 0xFFFF && pdetail_pr->rtt_scs != 0xFFFF)
	{
		return;
	}	
	unsigned int cur_tcp_ack = ntohl(this_tcphdr->th_ack);

	if(pstream->curdir == DIR_C2S)
	{
		unsigned int cur_tcp_seq = ntohl(this_tcphdr->th_seq);
		if(pdetail_pr->iclientseq == cur_tcp_ack && pdetail_pr->S2C_ack_seq == cur_tcp_seq)
		{
			pdetail_pr->rtt_scs = ABBR_CURRENT_TIME_MS - pdetail_pr->last_s2c_pkt_rcv_time;
		}
	}
	else
	{
		if(pdetail_pr->iserverseq == cur_tcp_ack)
		{
			pdetail_pr->rtt_csc = ABBR_CURRENT_TIME_MS - pdetail_pr->last_c2s_pkt_rcv_time;
		}
	}
	return;
}

//static int tcp_deal_syn_stream(struct streamindex *pindex,struct mesa_tcp_hdr *this_tcphdr,int datalen)
static int tcp_deal_syn_stream(struct streamindex *pindex,const raw_pkt_t *raw_pkt, 
		const void *this_iphdr, struct mesa_tcp_hdr *this_tcphdr,int datalen)
{
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream=&(pstream_pr->stream_public);
	struct tcpdetail_private* pdetail_pr=(struct tcpdetail_private*)pstream->pdetail;
	
	char curdir=pstream->curdir;
	int curseq;
	int thisseq=ntohl (this_tcphdr->th_seq);
	int thisack=ntohl (this_tcphdr->th_ack);

	calculate_tcp_rtt(pstream, pdetail_pr, this_tcphdr);

    if (pstream->dir == DIR_C2S)
    {
        curseq = pdetail_pr->iserverseq;
        if (curdir == DIR_S2C)
        {
			pdetail_pr->S2C_ack_seq = thisack;
			pdetail_pr->last_s2c_pkt_rcv_time = ABBR_CURRENT_TIME_MS;
            if ((this_tcphdr->th_flags & TH_RST) && (datalen == 0))
            {
                if (thisack == curseq)
                {
                    pstream->dir = DIR_DOUBLE; 
                    pdetail_pr->link_state = STREAM_LINK_RESET;
                    tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
                    return PASS;
                }
            }
            else
                if (thisack == curseq)
                {
                    pstream->dir = DIR_DOUBLE;
                    if (this_tcphdr->th_flags & TH_SYN)
                        pdetail_pr->iclientseq = thisseq + 1;
                    else
                        pdetail_pr->iclientseq = thisseq;
                    if (this_tcphdr->th_flags == (TH_SYN | TH_ACK))
                    {
                        pdetail_pr->tcpstateflag = TCP_SYN_RECV;
                        tcp_parse_opts(pstream_pr, DIR_S2C,
                                       (const struct tcphdr *)this_tcphdr); /* 2016-07-07 lijia add, for janus hijack */
                    }
                    return PASS;
                }
        }
        else 
        {
			pdetail_pr->C2S_ack_seq = thisack;
			pdetail_pr->last_c2s_pkt_rcv_time = ABBR_CURRENT_TIME_MS;
            if (thisseq == curseq)
            {
                if ((this_tcphdr->th_flags & TH_RST) && (datalen == 0))
                {
                    pdetail_pr->link_state = STREAM_LINK_RESET;
                    tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
                    return PASS;
                }
                else if ((this_tcphdr->th_flags == TH_ACK) && (datalen == 0))
                {
                    pdetail_pr->tcpstateflag = TCP_SYN_RECV;
                    return PASS;
                }
                else
                {
                    return PASS; // 2014-12-05 lijia modify, for xj serial
                }
                // end add by lqy 20130802
            }
        }
    }
    else if (pstream->dir == DIR_S2C)
    {
        curseq = pdetail_pr->iclientseq;

        if (curdir == DIR_C2S)
        {
			pdetail_pr->last_c2s_pkt_rcv_time = ABBR_CURRENT_TIME_MS;
            if ((this_tcphdr->th_flags & TH_RST) && (datalen == 0))
            {
                pstream->dir = DIR_DOUBLE;
                pdetail_pr->link_state = STREAM_LINK_RESET;
                tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
                return PASS;
            }
            else
            {
                pstream->dir = DIR_DOUBLE;
                if (this_tcphdr->th_flags & TH_SYN)
                    pdetail_pr->iserverseq = thisseq + 1;
                else
                    pdetail_pr->iserverseq = thisseq;
                return PASS;
            }
        }
        else 
        {
			pdetail_pr->last_s2c_pkt_rcv_time = ABBR_CURRENT_TIME_MS;
            if ((thisseq == curseq) && (this_tcphdr->th_flags & TH_RST) && (datalen == 0))

            {
                pdetail_pr->link_state = STREAM_LINK_RESET;
                tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
                return PASS;
            }
        }
    }
    else if (pstream->dir == DIR_DOUBLE)
    {
        if ((pdetail_pr->tcpstateflag == TCP_SYN_RECV) && (curdir == DIR_C2S))
        {
            if ((this_tcphdr->th_flags == TH_ACK) && (datalen == 0))
            {
                pdetail_pr->tcpstateflag = TCP_ESTABLISHED;
                tcp_change_stream_todata(pindex, this_tcphdr, 0);
            }
        }
    }

	if(this_tcphdr->th_flags == TH_SYN)
	{
		pdetail_pr->iserverseq=thisseq + 1;
		pdetail_pr->multisynflag=1;
		pdetail_pr->tcpstateflag=TCP_SYN_SENT;
	}
	
	if(this_tcphdr->th_flags == (TH_SYN|TH_ACK))
	{
		pdetail_pr->iclientseq=thisseq+1;
		pdetail_pr->multisynflag=1;
		pdetail_pr->tcpstateflag=TCP_SYN_SENT;
	}
	
	return PASS;
	
}

static void tcp_half_handle_ack_and_seq(struct half_tcpstream *phalf, struct mesa_tcp_hdr * this_tcphdr, UINT32 *cur_half_stream_ack)
{
	struct half_tcpstream  *rcv=NULL;
	int ackdiff =0;
	int seqdiff=0;

	rcv = phalf;

	if (0 == *cur_half_stream_ack)
		*cur_half_stream_ack = ntohl(this_tcphdr->th_ack);
	else
	{
		ackdiff = (int)(ntohl (this_tcphdr->th_ack) - *cur_half_stream_ack);

		if (ackdiff > 0 || ackdiff < (int)0x80000000) 
		{
			*cur_half_stream_ack = ntohl (this_tcphdr->th_ack);
		}
	}

	if (0 == rcv->seq)
		rcv->seq = ntohl(this_tcphdr->th_seq);
	else
	{
		seqdiff = (int)(ntohl(this_tcphdr->th_seq) - rcv->seq);
		if (seqdiff > 0 || seqdiff < (int)0x80000000) 
		{
			rcv->seq = ntohl(this_tcphdr->th_seq);
		}
	}

}
static int tcp_deal_ack(struct streaminfo *a_tcp,struct mesa_tcp_hdr *this_tcphdr)
{
	struct tcpdetail_private *pdetail_pr=NULL;
	struct half_tcpstream *phalf=NULL;
	struct half_tcpstream *phother=NULL;
	unsigned char threadnum=a_tcp->threadnum;
	pdetail_pr=(struct tcpdetail_private*)a_tcp->pdetail;
	UINT32 *cur_half_stream_ack;
	struct tcpdetail *pdetail;
	
	if((a_tcp->dir==DIR_C2S)&&(a_tcp->curdir==DIR_S2C))
	{
		pdetail_pr->pclient=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
		memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
		phalf=pdetail_pr->pclient;
		phalf->maxunorder = tcp_default_unorder;//add by lqy, 20150210
		phalf->seq = ntohl (this_tcphdr->th_seq) ;
		phalf->first_data_seq =  ntohl (this_tcphdr->th_seq);
		//add by lqy 20150210
		if((this_tcphdr->th_flags & TH_SYN)
			&& (this_tcphdr->th_flags & TH_ACK))
		{
			phalf->first_data_seq+=1;
		}
		
		pdetail_pr->S2C_ack_seq = ntohl (this_tcphdr->th_ack);
		phalf->window = ntohs (this_tcphdr->th_win);
		a_tcp->dir=DIR_DOUBLE;
	}
	if((a_tcp->dir==DIR_S2C)&&(a_tcp->curdir==DIR_C2S))
	{
		pdetail_pr->pserver=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
		memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
		phalf=pdetail_pr->pserver;
		phalf->maxunorder = tcp_default_unorder; //add by lqy, 20150210
		phalf->seq = ntohl (this_tcphdr->th_seq) ;
		phalf->first_data_seq =  ntohl (this_tcphdr->th_seq);
 		pdetail_pr->C2S_ack_seq = ntohl (this_tcphdr->th_ack);
		phalf->window = ntohs (this_tcphdr->th_win);
		a_tcp->dir=DIR_DOUBLE;
	}
	if ((this_tcphdr->th_flags & TH_ACK))
	{
		if(a_tcp->curdir==DIR_S2C)
		{
			phalf=pdetail_pr->pclient;
			phother=pdetail_pr->pserver;		
			if(0 == pdetail_pr->S2C_first_ack_seq){
				pdetail_pr->S2C_first_ack_seq = ntohl (this_tcphdr->th_ack);
			}
			pdetail_pr->S2C_ack_seq = ntohl (this_tcphdr->th_ack);
			cur_half_stream_ack = &pdetail_pr->S2C_ack_seq;
		}
		else
		{
			phalf=pdetail_pr->pserver;
			phother=pdetail_pr->pclient;
			if((0 == pdetail_pr->iclientseq)
			 &&(ntohl(this_tcphdr->th_seq) == pdetail_pr->iserverseq)){ 
				pdetail_pr->iclientseq = ntohl (this_tcphdr->th_ack);
			}
			if(0 == pdetail_pr->C2S_first_ack_seq){
				pdetail_pr->C2S_first_ack_seq = ntohl (this_tcphdr->th_ack);
			}
			pdetail_pr->C2S_ack_seq = ntohl (this_tcphdr->th_ack);
			cur_half_stream_ack = &pdetail_pr->C2S_ack_seq;
		}
		
		if(DIR_C2S == a_tcp->dir){
			pdetail = a_tcp->ptcpdetail;
			//pdetail->clientbytes = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq;
			if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
				pdetail_pr->deduce_flow_stat->C2S_data_byte = pdetail->serverbytes; 
				pdetail_pr->deduce_flow_stat->C2S_data_pkt = pdetail->serverpktnum;
				
				pdetail_pr->deduce_flow_stat->S2C_all_byte = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq;
				pdetail_pr->deduce_flow_stat->S2C_data_byte = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq; 
			}
		}else if(DIR_S2C == a_tcp->dir){
			pdetail = a_tcp->ptcpdetail;
			//pdetail->serverbytes = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq;
			if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
				pdetail_pr->deduce_flow_stat->S2C_data_byte = pdetail->clientbytes; 
				pdetail_pr->deduce_flow_stat->S2C_data_pkt = pdetail->clientpktnum;
				
				pdetail_pr->deduce_flow_stat->C2S_all_byte = pdetail_pr->S2C_ack_seq - pdetail_pr->S2C_first_ack_seq;
				pdetail_pr->deduce_flow_stat->C2S_data_byte = pdetail_pr->S2C_ack_seq - pdetail_pr->S2C_first_ack_seq;
			}
		}
			
		tcp_half_handle_ack_and_seq(phalf,this_tcphdr,cur_half_stream_ack);

		if(phother!=NULL)
		if (phother->finstate == FIN_SENT)
		{
			phother->finstate = FIN_CONFIRMED;
		}
	}
	return PASS;
}

static inline void tcp_clear_newdata(struct streaminfo *a_tcp,struct  half_tcpstream  *rcv)
{
	//struct tcpdetail_private*pdetail_pr=(struct tcpdetail_private*)a_tcp->pdetail;
	struct tcpdetail *pdetail=(struct tcpdetail *)a_tcp->ptcpdetail;

	//pdetail_pr->tcpoverlen=0; //del by lqy 20150325
	
   	pdetail->datalen=0;
   	pdetail->lostlen=0;
	pdetail->pdata=NULL;
	
	rcv->count_new=0;
	rcv->data=NULL;
	rcv->offset=rcv->count; 
}

static void  tcp_set_new_data(struct streaminfo *a_tcp,struct  half_tcpstream  *rcv, struct half_tcpstream *snd,
	u_char* data, int datalen, u_int this_seq,char fin, unsigned char is_ctrl_pkt)
{
  	int havelen;
	int len_new=0;
	unsigned char *pdata_new=NULL;
	struct tcpdetail_private*pdetail_pr=(struct tcpdetail_private*)a_tcp->pdetail;
	struct tcpdetail *pdetail=(struct tcpdetail *)&pdetail_pr->tcpdetail_public;

	if(is_ctrl_pkt==0)
	{
		if(this_seq< EXP_SEQ)
		{
			havelen = EXP_SEQ - this_seq;
			if (datalen - havelen > 0)
			{
				pdetail_pr->tcpoverlen=havelen;		
				len_new= datalen - havelen; 
				pdata_new=data+havelen;
			}
		}
		else 
		{
			len_new=datalen;
			pdata_new=data;
		}

		if(len_new>0)
		{
			rcv->count_ideal += len_new;
			rcv->data=pdata_new;
			rcv->count_new = len_new;
			rcv->count += len_new;
		}
	}
	else
	{
		len_new=datalen;
		pdata_new=data;
	}
	{
		pdetail->lostlen=rcv->count_ideal - rcv->count- rcv->totallost;
	}

	rcv->totallost+=pdetail->lostlen;

	sapp_global_val->mthread_volatile[a_tcp->threadnum]->sys_stat.length[SAPP_STAT_TCP_LOST_PKT] += pdetail->lostlen;		
	
	pdetail->datalen=len_new;
	pdetail->pdata=pdata_new;

	if(pdetail_pr->pclient)
	{
		pdetail_pr->flow_stat->S2C_seq_gap_loss_cnt=pdetail_pr->pclient->totallost;
	}
	if(pdetail_pr->pserver)
	{
		pdetail_pr->flow_stat->C2S_seq_gap_loss_cnt=pdetail_pr->pserver->totallost;
	}

	if (fin)
		rcv->finstate = FIN_SENT;
 
}



static int tcp_save_unorder(struct streaminfo *a_tcp,struct  half_tcpstream  *rcv,
	const void *this_iphdr, const raw_pkt_t *stack_raw_pkt,struct mesa_tcp_hdr *this_tcphdr, 
	unsigned char *tcpdata, int tcpdatalen)
{
	int threadnum = a_tcp->threadnum;
	struct buf_unorder *p = rcv->unorderlisttail;
	struct buf_unorder *packet=NULL;
	unsigned int this_seq = ntohl (this_tcphdr->th_seq);

	packet = tcp_save_unorder_pkt(a_tcp, this_iphdr, stack_raw_pkt, this_tcphdr, tcpdata, tcpdatalen);

	for (;;)
	{
		if (!p || !after (p->seq, this_seq))
			break;
		p = p->prev;
	}
	if (!p)
	{
		packet->prev = 0;
		if(rcv->unorderlist)
		  rcv->unorderlist->prev=packet;
		packet->next = rcv->unorderlist;
		rcv->unorderlist = packet;
		if (!rcv->unorderlisttail)
			rcv->unorderlisttail = packet;
	}
	else
	{
           //from being repeatly added to the list
            //if (p->seq == this_seq)
		//add by yw 20150311
		if (p->seq == this_seq 
		  || (p->seq+p->tcpdatalen) == (this_seq+packet->tcpdatalen)
		  ||after(p->seq+p->tcpdatalen,this_seq+packet->tcpdatalen))
             {

			tcp_free_unorder_pkt(threadnum, packet);
			return PASS;
               }

		packet->next = p->next;
		p->next = packet;
		packet->prev = p;
		if (packet->next)
			packet->next->prev = packet;
		else
			rcv->unorderlisttail = packet;
	}
	rcv->unorder_cnt++;

	//add by yw 20150311, remove overlab saved pkt
	p=packet->next;
	while(p != NULL){
		if(before(p->seq+p->tcpdatalen,this_seq+packet->tcpdatalen)
		  ||(p->seq+p->tcpdatalen)==(this_seq+packet->tcpdatalen)){
			packet->next = p->next;
			if(p->next != NULL)	
				p->next->prev = packet;
			else
				rcv->unorderlisttail = packet;
				
			tcp_free_unorder_pkt(threadnum, p);
			
			rcv->unorder_cnt--;
		}else{
			break;
		}
		p=packet->next;
	}

	return 1;
}

static int tcp_deal_unorder(struct streamindex *pindex,struct streaminfo *a_tcp,
		struct  half_tcpstream  *rcv, struct half_tcpstream *snd,int orderflag)
{
	struct buf_unorder *unorder_packet, *tmp;
	int ret;
	unsigned char tmpktype;
   	struct tcpdetail_private *pdetail_pr;
   	struct streaminfo_private *a_tcp_pr;
   	const raw_pkt_t *cur_raw_pkt;
   	UCHAR last_link_state;

	unorder_packet = (struct buf_unorder *) rcv->unorderlist;
	if(likely(NULL == unorder_packet)){
		return PASS;
	}

	ret=PASS;
	pdetail_pr=(struct tcpdetail_private*)(a_tcp->pdetail);
	a_tcp_pr = (struct streaminfo_private *)a_tcp;
	cur_raw_pkt = a_tcp_pr->raw_pkt;
	
	//add by yw 20150316 save tcpoverlen before deal_unorder
	UINT16 t_tcpoverlen = pdetail_pr->tcpoverlen;
	pdetail_pr->tcpoverlen = 0;
	
	while (unorder_packet)
	{
		if(a_tcp->opstate== OP_STATE_CLOSE)
		{
			ret = PASS;
			goto done;
		}	
		
		if ((after (unorder_packet->seq, EXP_SEQ)) && (orderflag==CHECK_ORDER_DATA)){
			ret = PASS;
			goto done;
		}

		if (after (unorder_packet->seq + unorder_packet->tcpdatalen+unorder_packet->fin+unorder_packet->rst, EXP_SEQ))
		{                    
			update_stream_list_raw_pkt_pointer(a_tcp_pr, &unorder_packet->raw_pkt);
			
			if(unorder_packet->rst )//add by lqy 20100805)
			{
				last_link_state = pdetail_pr->link_state;
				pdetail_pr->link_state=STREAM_LINK_RESET;
				a_tcp->opstate = OP_STATE_CLOSE;
				tmpktype=a_tcp->addr.pkttype;
				a_tcp->addr.pkttype=PKT_TYPE_TCPREORDER;
				if(a_tcp->curdir==DIR_C2S)
				{
					pdetail_pr->flow_stat->C2S_ooorder_pkt++;
				}
				else
				{
					pdetail_pr->flow_stat->S2C_ooorder_pkt++;
				}
				if(orderflag==CHECK_ORDER_DATA || sapp_global_val->config.stream.tcp.reorder_on_closing == 1)
				{
					stream_process_tcp(a_tcp,unorder_packet->this_ip_hdr, unorder_packet->this_tcp_hdr, &(unorder_packet->raw_pkt),&(pdetail_pr->apme),&(a_tcp->opstate));
				}
				a_tcp->addr.pkttype=tmpktype;
				if(STREAM_LINK_DATA == last_link_state){
				    tcp_update_should_close_reason_stat(a_tcp->threadnum);
					tcp_change_stream_tonouse(pindex);
					ret = DROP;
					goto done;
				}
				ret = PASS;
				goto done;
			}
			else
			{
				if(rcv->unorder_cnt > rcv->maxunorder || orderflag!=CHECK_ORDER_DATA)//add by lqy 20150325
				{
					//20150401 lqy
					if(after(unorder_packet->seq,EXP_SEQ) && rcv->first_data_seq!=0)
					{
						rcv->count_ideal = unorder_packet->seq   - rcv->first_data_seq;
					}
					//add by lqy 20150331 for payload overlap in deal reorder 
					if(rcv->unorder_cnt > rcv->maxunorder)
						orderflag = CHECK_ORDER_DATA;
				}

				tcp_set_new_data(a_tcp,rcv,snd,(u_char *)(unorder_packet->tcpdata),
				unorder_packet->tcpdatalen,unorder_packet->seq,unorder_packet->fin, 0);
				if(unorder_packet->tcpdatalen >0)
				{
					if((0 == a_tcp_pr->stream_killed_flag) && (0 == pdetail_pr->drop_stream_flag)){
						tmpktype=a_tcp->addr.pkttype;
						a_tcp->addr.pkttype = PKT_TYPE_TCPREORDER;
						if (a_tcp->curdir == DIR_C2S)
						{
							pdetail_pr->flow_stat->C2S_ooorder_pkt++;
						}
						else
						{
							pdetail_pr->flow_stat->S2C_ooorder_pkt++;
						}
						if(orderflag==CHECK_ORDER_DATA || sapp_global_val->config.stream.tcp.reorder_on_closing == 1)
						{
							ret=stream_process_tcp(a_tcp,unorder_packet->this_ip_hdr,unorder_packet->this_tcp_hdr,&(unorder_packet->raw_pkt),&(pdetail_pr->apme),&(a_tcp->opstate));
						}
						a_tcp->addr.pkttype=tmpktype;	
						tcp_clear_newdata(a_tcp,rcv);
					}
					
					if((a_tcp_pr->stream_killed_flag != 0) || (pdetail_pr->drop_stream_flag != 0))  
					{
						goto done;
					}
				}
			}
			if (unorder_packet->prev)
					unorder_packet->prev->next = unorder_packet->next;
			else
					rcv->unorderlist= unorder_packet->next;
			if (unorder_packet->next)
					unorder_packet->next->prev = unorder_packet->prev;
			else
					rcv->unorderlisttail= unorder_packet->prev;
			tmp = unorder_packet->next;
			tcp_free_unorder_pkt(a_tcp->threadnum, unorder_packet);
			unorder_packet = tmp;
			rcv->unorder_cnt--;                    
		}
		else
		 {
			unorder_packet = unorder_packet->next;
		 }			
	}

done:	
	update_stream_list_raw_pkt_pointer(a_tcp_pr, cur_raw_pkt); /* 2015-01-13 lijia add, recover pointer */

	pdetail_pr->tcpoverlen = t_tcpoverlen;//add by yw 20150316 set tcpoverlen back
	return ret;
}

static int tcp_deal_data(struct streamindex *pindex,const void *this_iphdr,const raw_pkt_t *raw_pkt,
	struct mesa_tcp_hdr *this_tcphdr,unsigned char *tcpdata,int datalen)
{
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
	struct half_tcpstream *snd=NULL,*rcv=NULL;
	u_int this_seq = ntohl (this_tcphdr->th_seq);
	int ret=PASS;
	int ret_unorder = PASS;
	
	if(pstream->curdir==DIR_S2C)
	{
		rcv=pdetail_pr->pclient;
		snd=pdetail_pr->pserver;
	}
	else
	{
		rcv=pdetail_pr->pserver;
		snd=pdetail_pr->pclient;
	}

	if (!after (this_seq, EXP_SEQ))
	{
		if (after(this_seq + datalen + 
			(this_tcphdr->th_flags & TH_FIN), EXP_SEQ))
		{
			tcp_set_new_data(pstream,rcv,snd,tcpdata,datalen,this_seq,this_tcphdr->th_flags & TH_FIN, raw_pkt->is_ctrl_pkt);
			if(datalen >0)
			{
				ret=stream_process_tcp(pstream,this_iphdr,(const void *)this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
				//tcp_clear_newdata(pstream,rcv); /*  2016-09-12 lijia move to outside if(datalen > 0) */
			}
			tcp_clear_newdata(pstream,rcv); 


			ret_unorder = tcp_deal_unorder(pindex,pstream,rcv,snd,CHECK_ORDER_DATA);
		
			if((DROP == ret_unorder) || (DROP == ret)){
				ret = DROP;
			}
			return ret;			
		}
	}
	else
	{
		tcp_save_unorder(pstream,rcv,this_iphdr,raw_pkt,this_tcphdr,tcpdata, datalen);		
		if(rcv->unorder_cnt > rcv->maxunorder)
		{
			ret=tcp_deal_unorder(pindex,pstream,rcv,snd, !CHECK_ORDER_DATA);
		}
		pdetail_pr->has_lost_pkt_flag = 1;
	}     
	return ret;
} 

static inline int tcp_tuple4_reuse(const struct streaminfo *pstream, const struct tcpdetail_private *pdetail_pr, const struct mesa_tcp_hdr *this_tcphdr)
{
	int is_reuse = 0;
	unsigned int cur_seq = ntohl(this_tcphdr->th_seq);

	if(DIR_C2S == pstream->curdir){
		if((pdetail_pr->iserverseq != 0) && (cur_seq != pdetail_pr->iserverseq-1)){
			is_reuse = 1;
		 }else{
			is_reuse = 0;
		 }
	}else{
		if((pdetail_pr->iclientseq != 0) && (cur_seq != pdetail_pr->iclientseq-1)){
			is_reuse = 1;
		 }else{
			is_reuse = 0;
		 }
	}

	/* lijia 2017-12-06 add */  
	if((1 == is_reuse) && (sapp_global_val->config.stream.tcp.tuple4_reuse_time_interval > 0)){
		if(pdetail_pr->tcpdetail_public.createtime + sapp_global_val->config.stream.tcp.tuple4_reuse_time_interval >= (UINT64)g_CurrentTime){
			is_reuse = 0;
		}
	}

	return is_reuse;
}

static int tcp_deal_data_stream(struct streamindex *pindex,const void *this_iphdr, 
				const raw_pkt_t *raw_pkt,struct mesa_tcp_hdr *this_tcphdr,int datalen)
{
	int ret=PASS;
	int finclose=0;
	struct streaminfo_private *pstream_pr=&(pindex->stream);
	struct streaminfo *pstream = &pstream_pr->stream_public;
	struct tcpdetail_private *pdetail_pr =(struct tcpdetail_private*)(pstream->pdetail);
	struct tcpdetail *pdetail = &pdetail_pr->tcpdetail_public;
	int curseq=0,thisseq=0;
	struct half_tcpstream *pcurhalf=NULL;
	struct half_tcpstream *snd=NULL,*rcv=NULL;
	unsigned char *tcpdata=NULL;
	unsigned char th_flags = this_tcphdr->th_flags;



	pdetail->lastmtime=(long)g_CurrentTime;
	pstream_pr->stream_lastupdate_timestamp_ms=g_CurrentTime_ms;

	
	tcp_deal_ack(pstream,this_tcphdr);

	if(pstream->curdir==DIR_C2S)
	{
		pcurhalf=pdetail_pr->pserver;
		snd=pdetail_pr->pclient;
		rcv=pdetail_pr->pserver;
	}	
	else
	{
		pcurhalf=pdetail_pr->pclient;
		snd=pdetail_pr->pserver;
		rcv=pdetail_pr->pclient;
	}


	pcurhalf->pktcout++;
	curseq=pcurhalf->first_data_seq + pcurhalf->count_ideal ;
	thisseq=ntohl (this_tcphdr->th_seq);
	//if((thisseq<curseq)&&(thisseq+datalen<=curseq)&&(!(this_tcphdr->th_flags & TH_SYN))){ // modify by lqy 20150325
	if(before(thisseq,curseq)&&before(thisseq+datalen,curseq+1)&&(!(th_flags & TH_SYN))){
		pstream->addr.pkttype = PKT_TYPE_TCPRETRANS;
		if(pstream->curdir==DIR_C2S)
		{
			pdetail_pr->flow_stat->C2S_retransmission_pkt++;
			pdetail_pr->flow_stat->C2S_retransmission_byte+=MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
		}
		else
		{
			pdetail_pr->flow_stat->S2C_retransmission_pkt++;
			pdetail_pr->flow_stat->S2C_retransmission_byte+=MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
		}
		return PASS;
	}
	//rst
	if( (th_flags & TH_RST)&&(curseq!=0)&&(pdetail_pr->ignore_rst_fin==0))
	{
		/* 2014-07-31 LiJia modify, for one stream unorder number  */
		//if(thisseq>curseq+(pcurhalf->maxunorder+1)*1460)
		if(after(thisseq, curseq+(pcurhalf->maxunorder+1)*1460))//modify by lqy 20150325
			 return PASS;
		 //syn+rst drop packet
		 if(th_flags & TH_SYN)
			return PASS; 
		 //if((thisseq-curseq<=1)&&(datalen==0))
		if(before(thisseq, curseq+2)&&(datalen==0))//modify by lqy 20150325
		 {
		 	pdetail_pr->link_state=STREAM_LINK_RESET;
			
			if(pstream->pktstate!=OP_STATE_CLOSE)
			{
				//add by lqy 20140515
				pstream->opstate = OP_STATE_CLOSE;
				//ret=stream_process_tcp(pstream,rawdata, ); //modify by lijia 20140516
				ret=stream_process_tcp(pstream,this_iphdr, this_tcphdr, raw_pkt, &(pdetail_pr->apme),&(pstream->opstate));
				//pstream->apme=NULL;//modify by lijia 20140516
				pdetail_pr->apme=NULL;
				tcp_update_should_close_reason_stat(pstream->threadnum);
				tcp_change_stream_tonouse(pindex);
			}										
			else
			{
				tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
			}
		
			return PASS;
		 }
	}

	if (th_flags & TH_SYN)
	{
	   if((datalen>0) || ((UINT32)thisseq+1 == rcv->first_data_seq) || ((UINT32)thisseq==rcv->first_data_seq)) 
	   {
		pstream->addr.pkttype = PKT_TYPE_TCPRETRANS;
		if(pstream->curdir==DIR_C2S)
		{
			pdetail_pr->flow_stat->C2S_retransmission_pkt++;
			pdetail_pr->flow_stat->C2S_retransmission_byte+=MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
		}
		else
		{
			pdetail_pr->flow_stat->S2C_retransmission_pkt++;
			pdetail_pr->flow_stat->S2C_retransmission_byte+=MAX(raw_pkt->raw_pkt_len-raw_pkt->overlay_layer_bytes,0);
		}
		return PASS;
	   }else{
			if(tcp_tuple4_reuse(pstream, pdetail_pr, this_tcphdr) == 0){
				return PASS;
			}
	   }
	   //adjust by lqy 20150107
	   //if(thisseq==rcv->first_data_seq) return PASS;
	   //if(datalen>0) return PASS;
	   //return PASS;	
	   if(th_flags & TH_RST)
	   {
	   		//MESA_runtime_log(RLOG_LV_FATAL, "[tcp_deal_data_stream]:","syn_rst,curseq:%d\n",curseq);
			return PASS;
	   }
	    pdetail_pr->link_state=STREAM_LINK_REUSE_BYSYN;
		pstream->opstate= OP_STATE_CLOSE;
		
		tcp_reset_stream(pindex,this_iphdr,this_tcphdr,datalen,raw_pkt);
		return PASS;		
	}
	if(datalen + (th_flags & TH_FIN) +(th_flags & TH_RST)> 0)//????TCP????
	{
		tcpdata=(unsigned char*)(this_tcphdr) + 4 * this_tcphdr->th_off;
		ret=tcp_deal_data(pindex,this_iphdr,raw_pkt,this_tcphdr,tcpdata,datalen);	
		if((pstream->opstate==OP_STATE_CLOSE)&&(pdetail_pr->link_state!=STREAM_LINK_RESET))
		{	
			tcp_change_stream_tonouse(pindex);
			return ret;
        }

		if(ret==DROP)
			return DROP;
	}
	else if(pdetail_pr->needackflag!=0)
	{
		ret=stream_process_tcp(pstream,this_iphdr,this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
		if((pstream->opstate==OP_STATE_CLOSE)
		&& (OP_STATE_CLOSE == pstream->pktstate)
		&&(pdetail_pr->link_state!=STREAM_LINK_RESET))
		{	
			tcp_change_stream_tonouse(pindex);
			return ret;
		}
	}

	if(pstream->dir==DIR_DOUBLE)
	{
		//if((snd->finstate ==FIN_CONFIRMED)&&(rcv->finstate ==FIN_CONFIRMED))
		if(rcv == NULL || snd == NULL)
		{
			pdetail_pr->link_state=STREAM_LINK_CLOSE;
			finclose=1;
		}
		else if((snd->finstate >=FIN_SENT)&&(rcv->finstate >=FIN_SENT))
		{
			pdetail_pr->link_state=STREAM_LINK_CLOSE;
			finclose=1;
		}
		else
			;
	}
	else if(rcv->finstate==FIN_SENT)
	{
		pdetail_pr->link_state=STREAM_LINK_CLOSE;
		finclose=1;
	}
	if ((th_flags & TH_RST)&&(thisseq==curseq) &&(datalen!=0))
	{
		pdetail_pr->link_state=STREAM_LINK_RESET;
		finclose=1;
	}
	if(pdetail_pr->ignore_rst_fin != 0){
		finclose = 0;
	}
	if(finclose)
	{
		pstream->opstate = OP_STATE_CLOSE;
	
		ret=stream_process_tcp(pstream,this_iphdr,this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
		if(pstream->pktstate!=OP_STATE_CLOSE)
		{
			tcp_update_should_close_reason_stat(pstream->threadnum);
			tcp_change_stream_tonouse(pindex);
		}
		else
		{
			tcp_free_stream(pindex, this_iphdr,this_tcphdr,raw_pkt);
		}
		return PASS;	
	}
	
	return ret;
}


static int tcp_deal_nouse_stream(struct streamindex *pindex,const void *this_iphdr,const raw_pkt_t *raw_pkt,struct mesa_tcp_hdr *this_tcphdr,int datalen)
{
	struct streaminfo *pstream=(struct streaminfo *)(&(pindex->stream));
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;

	if((pstream->opstate == OP_STATE_PENDING) 
	  && (datalen>0) 
	  && (!(this_tcphdr->th_flags & TH_FIN)) 
	  && (!(this_tcphdr->th_flags & TH_RST))
	  && (TCP_CTEAT_LINK_BYDATA & tcp_creatlink_model))
	{
		tcp_change_stream_todata(pindex,this_tcphdr,datalen);
		return tcp_deal_data_stream(pindex,this_iphdr,raw_pkt,this_tcphdr,datalen);
	}

	if (this_tcphdr->th_flags & TH_SYN)
	{
		if(1 == tcp_tuple4_reuse(pstream, pdetail_pr, this_tcphdr)){
			pdetail_pr->link_state=STREAM_LINK_REUSE_BYSYN;
			tcp_reset_stream(pindex,this_iphdr,this_tcphdr,datalen,raw_pkt);
		}
		else
		{
			if (pdetail_pr->flow_stat)
			{
				if (pstream->curdir == DIR_C2S)
				{
					pdetail_pr->flow_stat->C2S_syn_pkt++;
				}
				else
				{
					pdetail_pr->flow_stat->S2C_syn_pkt++;
				}
			}
		}
		return PASS;
	}

	if(this_tcphdr->th_flags & TH_FIN || this_tcphdr->th_flags & TH_RST || pdetail_pr->link_state==STREAM_LINK_CLOSE)
	{
		struct stream_list *lru_list_root=&(G_MESA_GLOBAL_STREAM[pstream->threadnum]->tcpList[pstream->stream_state]);
		timeouts_add(lru_list_root->streamindex_timer, &pindex->timeout, tcp_closing_timeout*1000+g_CurrentTime_ms);
	}

	return PASS;	
}


/* add by lqy 20150113 */
static char tcp_process_newstreambydata(struct streamindex *pindex_tcp,const void *this_iphdr, 
					struct mesa_tcp_hdr *this_tcphdr,int tcplen, const raw_pkt_t * raw_pkt)
{
	char ret=PASS;
	struct streaminfo * pstream=(struct streaminfo *)(&(pindex_tcp->stream));			
	struct tcpdetail *pdetail=NULL;
	struct tcpdetail_private *pdetail_pr=NULL;
	
	pdetail_pr=(struct tcpdetail_private *)(pstream->pdetail);
	pdetail=(struct tcpdetail *)(pstream->pdetail);

	pdetail->lastmtime=g_CurrentTime;
	if(pstream->curdir==DIR_S2C)
	{
		pdetail->clientbytes+=tcplen;
		pdetail->clientpktnum++;
	}
	else
	{
		pdetail->serverbytes+=tcplen;
		pdetail->serverpktnum++;
	}
	int frag_cnt = 0, frag_len = 0;
	stream_get_scratch_frag_stat(pstream, &frag_cnt, &frag_len);

	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_S2C == pstream->curdir){
			if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
			{
				pdetail_pr->flow_stat->S2C_all_pkt+=MAX(1, frag_cnt);
				pdetail_pr->flow_stat->S2C_all_byte += MAX(tcplen, frag_len);
				pdetail_pr->flow_stat->S2C_all_byte_raw += MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes, frag_len);
				pdetail_pr->flow_stat->S2C_ip_fragment_pkt+=MAX(1, frag_cnt);
			}
			else
			{
				pdetail_pr->flow_stat->S2C_all_pkt++;
				pdetail_pr->flow_stat->S2C_all_byte += tcplen;
				pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
			}
		}else{

			if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
			{
				pdetail_pr->flow_stat->C2S_all_pkt+=MAX(1, frag_cnt);
				pdetail_pr->flow_stat->C2S_all_byte += MAX(tcplen, frag_len);
				pdetail_pr->flow_stat->C2S_all_byte_raw += MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes, frag_len);
				pdetail_pr->flow_stat->C2S_ip_fragment_pkt+=MAX(1, frag_cnt);
			}
			else
			{
				pdetail_pr->flow_stat->C2S_all_pkt++;
				pdetail_pr->flow_stat->C2S_all_byte += tcplen;
				pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
			}
		}
	}
	
	ret=tcp_processallpkt(pstream,this_iphdr,this_tcphdr,tcplen,raw_pkt);	

	if(DROP == ret){ 
		return DROP;
	}

	if(likely(raw_pkt->is_ctrl_pkt == 0))
	{
		if (pstream->stream_state == TCP_DATA_STATE)
		{
			ret = tcp_deal_data_stream(pindex_tcp, this_iphdr, raw_pkt, this_tcphdr, tcplen);
		}
		else if (pstream->stream_state == TCP_NOUSE_STATE)
		{
			ret = tcp_deal_nouse_stream(pindex_tcp, this_iphdr, raw_pkt, this_tcphdr, tcplen);
		}
	}
	return ret;
}


static int deal_tcp_stream_dup_pkt_check(int tid, struct streaminfo_private *pstream_pr, struct tcpdetail_private *ptcpdetail_pr,
										   const struct mesa_ip4_hdr * this_iphdr, struct mesa_tcp_hdr *this_tcphdr)
{
	int is_dup_pkt = 0;
	int dup_check_enabled = 0;
	const sapp_dup_pkt_t *dup_pkt_para = &sapp_global_val->config.packet_io.dup_pkt_para;

	if ((ADDR_TYPE_IPV4 == pstream_pr->stream_public.addr.addrtype) 
	&& (dup_pkt_para->dup_pkt_distinguish_ipv4_tcp || dup_pkt_para->dup_pkt_distinguish_all_inject))
	{
		if((0 == pstream_pr->has_duplicate_pkt) 
		  && (ptcpdetail_pr->tcpdetail_public.clientpktnum+ptcpdetail_pr->tcpdetail_public.serverpktnum >= (unsigned int)dup_pkt_para->first_packets)){ 
			dup_check_enabled = 0;
		}else{	
			dup_check_enabled = 1;
		}
	}

	if ((ADDR_TYPE_IPV6 == pstream_pr->stream_public.addr.addrtype) 
	  && (dup_pkt_para->dup_pkt_distinguish_all_inject != 0))
	{
		dup_check_enabled = 1;
	}
	
	if(dup_check_enabled != 0){
		is_dup_pkt = sapp_dup_pkt_identify(tid, pstream_pr, this_iphdr, this_tcphdr, dup_pkt_para->dup_pkt_distinguish_ipv4_tcp!=0?1:0);
	}

	return is_dup_pkt;
}

static int deal_tcp_tfo(struct streaminfo *pstream, const void *this_iphdr, struct mesa_tcp_hdr *this_tcphdr, int tcplen,const raw_pkt_t *raw_pkt)
{
	struct half_tcpstream *snd=NULL,*rcv=NULL;
	int ret=PASS;
	struct tcpdetail_private*pdetail_pr=(struct tcpdetail_private*)pstream->pdetail;
	struct tcpdetail *pdetail=(struct tcpdetail *)&pdetail_pr->tcpdetail_public;
	unsigned int this_tfo_first_seq = ntohl (this_tcphdr->th_seq) + 1; //for TFO: first_payload.seq == SYN.seq, plus 1 otherwise will be treat as overlap
	if(pstream->curdir == DIR_C2S)
	{
		if(NULL == pdetail_pr->pserver){
			pdetail_pr->pserver=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,pstream->threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
			pdetail_pr->pserver->first_data_seq=pdetail_pr->iserverseq;
			
			/* 2014-10-20 LiJia add, for set one stream unorder number */
			pdetail_pr->pserver->maxunorder = tcp_default_unorder;
		}
		rcv=pdetail_pr->pserver;
		snd=pdetail_pr->pclient;
	}
	else
	{
		if(NULL == pdetail_pr->pclient){
			pdetail_pr->pclient=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,pstream->threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
			pdetail_pr->pclient->first_data_seq=pdetail_pr->iclientseq;
			/* 2014-10-20 LiJia add, for set one stream unorder number */
			pdetail_pr->pclient->maxunorder = tcp_default_unorder;
		}
		rcv=pdetail_pr->pclient;
		snd=pdetail_pr->pserver;		
	}

	tcp_set_new_data(pstream,rcv,snd,(uchar *)this_tcphdr + this_tcphdr->th_off*4,tcplen,this_tfo_first_seq,this_tcphdr->th_flags & TH_FIN, raw_pkt->is_ctrl_pkt);
	ret = stream_process_tcp(pstream, this_iphdr, this_tcphdr, raw_pkt, &(pdetail_pr->apme),&(pstream->opstate));	
	return ret;
}

//int deal_tcp_stream(struct streamindex *pstream,struct mesa_tcp_hdr *this_tcphdr,int tcplen,const void *rawippkt,int iplen)
static int deal_tcp_stream(struct streamindex *pindex, const void *this_iphdr, struct mesa_tcp_hdr *this_tcphdr,
	int tcplen,const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	struct streamindex *pindex_tcp;
	struct tcpdetail *pdetail=NULL;
	struct tcpdetail_private *pdetail_pr=NULL;
	int ret=PASS;
	int retAll=PASS;
	struct streaminfo_private *pstream_pr = &pindex->stream;
	struct streaminfo *pstream = &pstream_pr->stream_public;
	int try_to_update_addr_info = 0;
	int call_tcpall_after_reset = 0; 
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[pstream->threadnum]->sys_stat;

	pindex_tcp = findstreamindex (pindex, raw_pkt);
	if(unlikely(!pindex_tcp)){
		if((ADDR_TYPE_IPV4 == pstream->addr.addrtype) 
		&& sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp){
			sapp_dup_pkt_mark_l4(pstream, this_iphdr, (const void *)this_tcphdr);
		}

		if(this_tcphdr->th_flags & TH_SYN)
		{
			if(0==(TCP_CTEAT_LINK_BYSYN & tcp_creatlink_model ))
				return PASS;
			if(raw_pkt->is_ctrl_pkt==1)
				return PASS;	
			pindex_tcp=tcp_add_new_stream_bysyn(pindex,this_iphdr, this_tcphdr,tcplen,CTREAT_LINK,raw_pkt);
			if(likely(pindex_tcp != NULL))
			{
				pstream_pr = &pindex_tcp->stream;
				pstream = &pstream_pr->stream_public;
				//add by lqy 20130822
				pdetail_pr = (struct tcpdetail_private *)(pindex_tcp->stream.stream_public.pdetail);
				pdetail = (struct tcpdetail *)(&pdetail_pr->tcpdetail_public);
				pstream_pr->raw_pkt = raw_pkt; //add by lijia 20171206
				//add by lqy 20140114
				if(pstream_pr->under_ddos_bypass){
					local_sys_stat->count[SAPP_STAT_TCP_BYPASS_STREAM]++;
					local_sys_stat->count[SAPP_STAT_TCP_BYPASS_PKTS]++;
					local_sys_stat->length[SAPP_STAT_TCP_BYPASS_BYTES]+= tcplen;
					cycle_pkt_dump_by_classify(pstream->threadnum, raw_pkt, PKT_CLASSIFY_BYPASS);
					sapp_runtime_log(RLOG_LV_INFO, "TCP stream:%s under ddos bypass!", printaddr(&pstream->addr, pstream->threadnum));
					ret = PASS;
				}else{
					if(tcplen > 0){ // for TFO
						ret = deal_tcp_tfo(pstream, this_iphdr, this_tcphdr, tcplen, raw_pkt);
					}
					if(ret == PASS){ //TFO, call TCP->TCPALL
					ret=tcp_processallpkt(pstream,this_iphdr,this_tcphdr,tcplen,raw_pkt);
					}
				}
			}
			return ret; 
		}
		else
		{
			if((this_tcphdr->th_flags & TH_RST) && (0 == this_tcphdr->th_seq)){
				return PASS;
			}
			if((tcplen==0)&&(tcp_support_all==TCP_SUPPORT_ENTRYALL_OFF))
				return PASS;		
			if(TCP_CTEAT_LINK_BYDATA  & tcp_creatlink_model )
			{
				pindex_tcp=tcp_add_new_stream_bydata(pindex,this_tcphdr,tcplen,CTREAT_LINK, raw_pkt);
				
				if(likely(pindex_tcp != NULL))
				{
					pstream_pr = &pindex_tcp->stream;
					pstream = &pstream_pr->stream_public;
					pstream_pr->raw_pkt = raw_pkt;  //add by lijia 20171206
					if(pstream_pr->under_ddos_bypass)
					{
						local_sys_stat->count[SAPP_STAT_TCP_BYPASS_STREAM]++;
						local_sys_stat->count[SAPP_STAT_TCP_BYPASS_PKTS]++;
						local_sys_stat->length[SAPP_STAT_TCP_BYPASS_BYTES]+= tcplen;	
						cycle_pkt_dump_by_classify(pstream->threadnum, raw_pkt, PKT_CLASSIFY_BYPASS);
						sapp_runtime_log(RLOG_LV_INFO, "TCP stream:%s under ddos bypass!", printaddr(&pstream->addr, pstream->threadnum));			
						ret = PASS;
					}else
					{
						ret = tcp_process_newstreambydata(pindex_tcp,this_iphdr, this_tcphdr,tcplen,raw_pkt);
					}

					pdetail_pr =(struct tcpdetail_private*)(pstream->pdetail);
					if(pdetail_pr->offload_stream_flag==(SMART_OFFLOAD_FLAG_TCP|SMART_OFFLOAD_FLAG_TCPALL) && (g_CurrentTime > pdetail_pr->offload_stream_timestamp_s))
					{
						local_sys_stat->count[SAPP_STAT_TCP_OFFLOAD_STREAM]++;
						MESA_send_smart_offload(pstream, (const void *)raw_pkt, pstream->threadnum);
						pdetail_pr->offload_stream_timestamp_s = g_CurrentTime;
					}
				}
			}
			return ret;
		}		
		
		if(!pindex_tcp)
		{
			//return DROP;
			return PASS; //2014-12-05 lijia modify, for xj serial
		}
	}else{
		pstream_pr = &pindex_tcp->stream;
		pstream = &pstream_pr->stream_public;	
		//pindex_tcp->stream.p_layer_header = (void *)this_tcphdr;
//		pindex_tcp->stream.offset_to_raw_pkt_hdr = (char *)this_tcphdr - (char *)raw_pkt->raw_pkt_data;
		//pstream_pr->offset_to_raw_pkt_hdr = offset_to_raw_pkt_hdr;	
		pstream_pr->raw_pkt = raw_pkt; /* 2014-12-30 lijia add */
		pstream->addr.pktipfragtype = pindex->stream.stream_public.addr.pktipfragtype; 
	}

	pdetail_pr =(struct tcpdetail_private*)(pstream->pdetail);
	pdetail =(struct tcpdetail *)(&pdetail_pr->tcpdetail_public);


	if(pstream_pr->under_ddos_bypass){
		local_sys_stat->count[SAPP_STAT_TCP_BYPASS_PKTS]++;
		local_sys_stat->length[SAPP_STAT_TCP_BYPASS_BYTES]+= tcplen;
		cycle_pkt_dump_by_classify(pstream->threadnum, raw_pkt, PKT_CLASSIFY_BYPASS);
		return PASS;
	}




	if(unlikely(pstream_pr->stream_killed_flag != 0) && raw_pkt->is_ctrl_pkt==0){
		if((pdetail_pr->auto_remedy_flag != 0) && (tcplen > 0)){ 
			sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream: %s, kill_tcp remedy, curdir:%d, send RST pkt.", 
				printaddr(&pstream->addr, pstream->threadnum), pstream->curdir);
			pstream_pr->plugin_process_context=1;
			MESA_kill_tcp_remedy(pstream, raw_pkt);
			pstream_pr->plugin_process_context=0;
		}
	}
	if(raw_pkt->is_ctrl_pkt==0 &&
		deal_tcp_stream_dup_pkt_check(pstream->threadnum, pstream_pr, pdetail_pr, (const struct mesa_ip4_hdr *)this_iphdr, this_tcphdr) != 0){
			local_sys_stat->count[SAPP_STAT_RCV_DUP_TCP]++;
			local_sys_stat->length[SAPP_STAT_RCV_DUP_TCP] += tcplen;	
			cycle_pkt_dump_by_classify(pstream->threadnum, raw_pkt, PKT_CLASSIFY_REPEAT);
			return PASS;
	}

	if(unlikely(pdetail_pr->drop_stream_flag != 0) && raw_pkt->is_ctrl_pkt==0){
		sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream: %s, has been set drop flag, curdir:%d, return DROP.", 
						printaddr(&pstream->addr, pstream->threadnum), pstream->curdir);
		pdetail->lastmtime = g_CurrentTime;
		pstream_pr->stream_lastupdate_timestamp_ms = g_CurrentTime_ms;
		if(1 == lrustream(pindex_tcp))
		{
			tcp_reset_stream(pindex_tcp, this_iphdr,this_tcphdr, tcplen,raw_pkt);	
		}
		if((this_tcphdr->th_flags & TH_RST) && tcplen == 0)
		{
			return PASS;
		}
		else
		{
			return DROP;
		}
	}

	if(pstream_pr->sid_append_list != NULL)((raw_pkt_t *)raw_pkt)->append_list=pstream_pr->sid_append_list;
	if(pstream_pr->sid_prepend_list != NULL)((raw_pkt_t *)raw_pkt)->prepend_list=pstream_pr->sid_prepend_list;
	if(pstream_pr->stream_trace_id != 0)((raw_pkt_t *)raw_pkt)->stream_trace_id=pstream_pr->stream_trace_id;

	if(pstream->curdir==DIR_S2C)
	{
		if(pdetail->clientpktnum == 0) 
		{
			try_to_update_addr_info = 1;
		}
		pdetail->clientbytes+=tcplen;
		pdetail->clientpktnum++;
	}
	else
	{
		if(pdetail->serverpktnum == 0) 
		{
			try_to_update_addr_info = 1;
		}
		pdetail->serverbytes+=tcplen;
		pdetail->serverpktnum++;
	}

	if(try_to_update_addr_info == 1)
	{
		update_opposite_addr_info(pstream_pr, (struct streaminfo_private *)(pstream_pr->pfather_pr),
				(struct streaminfo_private *)(pindex->stream.pfather_pr), pstream->curdir);
	}

    int frag_cnt = 0, frag_len = 0;
    stream_get_scratch_frag_stat(pstream, &frag_cnt, &frag_len);

	if(G_TCP_FLOW_STAT_PROJECT_ID != -1 && raw_pkt->is_ctrl_pkt == 0){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->flow_stat->C2S_syn_pkt+=((this_tcphdr->th_flags & TH_SYN) ? 1 : 0);
			if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
			{
				pdetail_pr->flow_stat->C2S_all_pkt+=MAX(1, frag_cnt);
				pdetail_pr->flow_stat->C2S_all_byte +=MAX(1, frag_cnt);
				pdetail_pr->flow_stat->C2S_all_byte_raw += MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes, frag_len);
				pdetail_pr->flow_stat->C2S_ip_fragment_pkt+=MAX(1, frag_cnt);
			}
			else
			{
				pdetail_pr->flow_stat->C2S_all_pkt++;
				pdetail_pr->flow_stat->C2S_all_byte += tcplen;
				pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
			}
		}else{
			pdetail_pr->flow_stat->S2C_syn_pkt+=((this_tcphdr->th_flags & TH_SYN) ? 1 : 0);
			if(pstream->addr.pktipfragtype & PKT_TYPE_IPREBUILD)
			{
				pdetail_pr->flow_stat->S2C_all_pkt+=MAX(1, frag_cnt);
				pdetail_pr->flow_stat->S2C_all_byte +=MAX(1, frag_cnt);
				pdetail_pr->flow_stat->S2C_all_byte_raw +=MAX(raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes, frag_len);
				pdetail_pr->flow_stat->S2C_ip_fragment_pkt+=MAX(1, frag_cnt);
			}
			else
			{
				pdetail_pr->flow_stat->S2C_all_pkt++;
				pdetail_pr->flow_stat->S2C_all_byte += tcplen;
				pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
			}
		}
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->deduce_flow_stat->C2S_all_pkt++;
			pdetail_pr->deduce_flow_stat->C2S_all_byte += tcplen;
		}else{
			pdetail_pr->deduce_flow_stat->S2C_all_pkt++;
			pdetail_pr->deduce_flow_stat->S2C_all_byte += tcplen;
		}
	}

	update_polling_inject_context(SAPP_MEM_DYN_TCP_POLLING_RAW_PKT, pstream_pr, raw_pkt);

	/* update ip ttl */
	if(unlikely(0 == pstream_pr->ip_ttl_c2s) && (DIR_C2S == pstream->curdir)) {
		pstream_pr->ip_ttl_c2s = pindex->stream.ip_ttl_c2s;
	}
	if(unlikely(0 == pstream_pr->ip_ttl_s2c) && (DIR_S2C == pstream->curdir)) {
		pstream_pr->ip_ttl_s2c = pindex->stream.ip_ttl_c2s; /* Not a mistake, that's it! */
	}
	
	if(1 == lrustream(pindex_tcp)){
		ret = tcp_reset_stream(pindex_tcp, this_iphdr,this_tcphdr, tcplen,raw_pkt);		
		if(0 == ret){
			return PASS;
		}
		if(pstream_pr->under_ddos_bypass){
			return PASS;
		}
		ret = tcp_processallpkt(pstream, this_iphdr, this_tcphdr, tcplen, raw_pkt);
		if(DROP == ret){
			return DROP;
		}

		call_tcpall_after_reset = 1;		
	}

	pdetail->lastmtime=g_CurrentTime;
	pstream_pr->stream_lastupdate_timestamp_ms=g_CurrentTime_ms;
	pstream->addr.pkttype = PKT_TYPE_NORMAL;//add by lqy 20151222, init pkttype
	pdetail_pr->tcpoverlen=0;//add by lqy 20150325
	
	if(pdetail_pr->takeoverflag==TCP_TAKEOVER_STATE_FLAG_ON)
	{
		//ret=stream_process_tcp_takeover(pstream,raw_pkt);
		ret=stream_process_tcp_takeover(pstream,this_iphdr); /* 20160928 lijia modify, iphdr */		
	}
	else
	{
		if(pdetail_pr->offload_stream_flag==(SMART_OFFLOAD_FLAG_TCP|SMART_OFFLOAD_FLAG_TCPALL) && (g_CurrentTime > pdetail_pr->offload_stream_timestamp_s))
		{
			local_sys_stat->count[SAPP_STAT_TCP_OFFLOAD_PKTS]++;
			local_sys_stat->length[SAPP_STAT_TCP_OFFLOAD_BYTES]+= tcplen;

			MESA_send_smart_offload(pstream, (const void *)raw_pkt, pstream->threadnum);		
			pdetail_pr->offload_stream_timestamp_s = g_CurrentTime;
			return PASS;
		}
		if (likely(raw_pkt->is_ctrl_pkt == 0))
		{
			if (pstream->stream_state == TCP_DATA_STATE)
			{
				// ret=tcp_deal_data_stream(pindex_tcp,rawippkt,iplen,this_tcphdr,tcplen);
				ret = tcp_deal_data_stream(pindex_tcp, this_iphdr, raw_pkt, this_tcphdr, tcplen);
			}
			else if (pstream->stream_state == TCP_SYN_STATE)
			{
				ret = tcp_deal_syn_stream(pindex_tcp, raw_pkt, this_iphdr, this_tcphdr, tcplen);
				if (DROP == ret)
				{
					ret = PASS;
					goto fun_exit;
				}
				if ((tcplen > 0) && (checkcreatlinkseq(&(pindex_tcp->stream), htonl(this_tcphdr->th_seq)) == 1))
				{
					tcp_change_stream_todata(pindex_tcp, this_tcphdr, tcplen);
					// ret=tcp_deal_data_stream(pindex_tcp,rawippkt,iplen,this_tcphdr,tcplen);
					ret = tcp_deal_data_stream(pindex_tcp, this_iphdr, raw_pkt, this_tcphdr, tcplen);
				}
				else
				{
					pindex_tcp->stream.stream_public.addr.pkttype = PKT_TYPE_TCPUNORDER;
				}
			}
			else if (pstream->stream_state == TCP_NOUSE_STATE)
			{
				ret = tcp_deal_nouse_stream(pindex_tcp, this_iphdr, raw_pkt, this_tcphdr, tcplen);
			}
		}
	}

	if(pstream_pr->under_ddos_bypass){
		return ret;
	}	
	
	pdetail_pr =(struct tcpdetail_private*)(pstream->pdetail);
	if((pdetail_pr != NULL) && (0 == call_tcpall_after_reset) && pindex_tcp && (pstream->pktstate!=OP_STATE_CLOSE))
	{
		if(tcplen == 0)
		{
			pdetail->pdata = NULL;
			pdetail->datalen = 0;
		}
		else
		{
			pdetail->pdata=(char*)(this_tcphdr) + 4 * this_tcphdr->th_off;
                            pdetail->datalen = tcplen;
		}
		retAll=stream_process_tcp_allpkt(pstream,this_iphdr, (const void *)this_tcphdr, raw_pkt,&(pdetail_pr->pAllpktpme),&(pstream->pktstate));
		pdetail->pdata=NULL;
                    pdetail->datalen = 0;
		if(DROP==retAll)
		{
			//return retAll;
			ret = retAll;
			goto fun_exit;
		}
	}
	if(pdetail_pr != NULL 
		&& pdetail_pr->offload_stream_flag==(SMART_OFFLOAD_FLAG_TCP|SMART_OFFLOAD_FLAG_TCPALL) 
		&& DROP!=ret 
		&& (g_CurrentTime > pdetail_pr->offload_stream_timestamp_s))
	{
		local_sys_stat->count[SAPP_STAT_TCP_OFFLOAD_STREAM]++;
		MESA_send_smart_offload(pstream, (const void *)raw_pkt, pstream->threadnum);	
		pdetail_pr->offload_stream_timestamp_s = g_CurrentTime;
	}

fun_exit:    

	if(DROP == ret){
		sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream: %s, tcphdr->checksum:0x%x, curdir:%d, return DROP.", 
						printaddr(&pstream->addr, pstream->threadnum), ntohs(this_tcphdr->th_sum), pstream->curdir);
	}

	return ret;
}


static int dealtcppkt(struct streamindex *pfindex, const void *this_iphdr, struct mesa_tcp_hdr *this_tcphdr, 
	int thread_num,unsigned char routedir, int tcpdatalen, const raw_pkt_t *raw_packet, int offset_to_raw_pkt_hdr)
{


	//struct streamindex tmp_tcp_stream;
	//struct streamindex *ptmp=&tmp_tcp_stream;
	struct streaminfo_private *pstream_pr = (struct streaminfo_private *)(&pfindex->stream);
	struct streaminfo *pstream = (struct streaminfo *)(&pstream_pr->stream_public);
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	
	local_sys_stat->count[SAPP_STAT_RCV_TCP]++;
	local_sys_stat->length[SAPP_STAT_RCV_TCP]+=tcpdatalen;
	if (routedir == sapp_global_val->config.packet_io.inbound_route_dir)
	{
		local_sys_stat->count[SAPP_STAT_TCP_INBOUND]++;
		local_sys_stat->length[SAPP_STAT_TCP_INBOUND] += tcpdatalen;
	}
	else
	{
		local_sys_stat->count[SAPP_STAT_TCP_OUTBOUND]++;
		local_sys_stat->length[SAPP_STAT_TCP_OUTBOUND] += tcpdatalen;
	}

	pstream->type=STREAM_TYPE_TCP;
	//set_transport_addr(pstream, !(this_tcphdr->th_flags & TH_SYN), this_tcphdr->th_sport, this_tcphdr->th_dport);
	set_transport_addr(pstream, 1, this_tcphdr->th_sport, this_tcphdr->th_dport);

	pstream->addr.pkttype = PKT_TYPE_NORMAL;//add by lqy 20151222, init pkttype
	
	pstream_pr->addr_use_as_hash = 1;
//	ptmp->stream.p_layer_header = this_tcphdr;
	//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_tcphdr - (char *)raw_packet->raw_pkt_data;
	pstream_pr->offset_to_ip_hdr = (char *)this_tcphdr - (char *)this_iphdr;
	pstream_pr->raw_pkt = raw_packet; /* 2014-12-30 lijia add */
	
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	local_sys_stat->count_per_layer[ADDR_TYPE_TCP][pstream_pr->layer_index]++;
	local_sys_stat->length_per_layer[ADDR_TYPE_TCP][pstream_pr->layer_index] += tcpdatalen + this_tcphdr->th_off*4; 
	
	//return deal_tcp_stream(ptmp,this_tcphdr,tcpdatalen,raw_packet,raw_len);
	return deal_tcp_stream(pfindex,this_iphdr, this_tcphdr,tcpdatalen, raw_packet, offset_to_raw_pkt_hdr);
}

int dealipv4tcppkt(struct streamindex *pfindex, const struct mesa_ip4_hdr *this_iphdr,int thread_num,
					unsigned char routedir, const raw_pkt_t *raw_pkt,  int offset_to_raw_pkt_hdr)
{
	int iphdr_len, datalen, iplen;

	iphdr_len = this_iphdr->ip_hl << 2;
	struct mesa_tcp_hdr *this_tcphdr = (struct mesa_tcp_hdr *)((char *)this_iphdr + iphdr_len);

	if(raw_pkt->is_ctrl_pkt==0)
	{
		iplen = ntohs (this_iphdr->ip_len);
		if(unlikely(iplen - iphdr_len < (int)sizeof (struct mesa_tcp_hdr))){
			return PASS;
		}
		
		datalen = iplen - iphdr_len - (this_tcphdr->th_off<<2);
	}
	else
	{
		datalen = raw_pkt->raw_pkt_len-offset_to_raw_pkt_hdr-(this_tcphdr->th_off<<2);
	}

	if(unlikely(datalen < 0)){
		return PASS;
	}
	
			
#if HIGH_PERF
	if((0 == datalen) && (TH_ACK == this_tcphdr->th_flags)){
		return PASS;
	}
#else
	if((0 == datalen) && (TH_ACK == this_tcphdr->th_flags) && (1 == g_discard_ack_sw)){
		return PASS;
	}
#endif

#if HIGH_PERF	
	if(unlikely((this_iphdr->ip_src.s_addr | this_iphdr->ip_dst.s_addr) == 0)){
		return PASS;
	}
#endif	

	/* temporarily stored in the stack memory, use fix val c2s */
	pfindex->stream.ip_ttl_c2s = this_iphdr->ip_ttl;

	//return dealtcppkt(pfstream, this_tcphdr, thread_num, routedir, datalen, iplen, raw_pkt);
	return dealtcppkt(pfindex, (const void *)this_iphdr, this_tcphdr, thread_num, routedir, datalen, raw_pkt, offset_to_raw_pkt_hdr);
}

/* 2012-06-09 LiJia add */
int dealipv6tcppkt(struct streamindex *pfindex, const struct mesa_ip6_hdr *this_iphdr,
	char *data, int datalen, int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	struct mesa_tcp_hdr *this_tcphdr = (struct mesa_tcp_hdr *)data;

	if(raw_pkt->is_ctrl_pkt==0)
	{
		datalen -= (this_tcphdr->th_off << 2);
	}
	else
	{
		datalen = raw_pkt->raw_pkt_len-offset_to_raw_pkt_hdr-(this_tcphdr->th_off<<2);
	}
	
	if(unlikely(datalen < 0)){
		return PASS;
	}

	/* temporarily stored in the stack memory, use fix val c2s */
	pfindex->stream.ip_ttl_c2s = this_iphdr->ip6_hop;

	return dealtcppkt(pfindex,(const void *)this_iphdr, this_tcphdr,thread_num, routedir, datalen, raw_pkt, offset_to_raw_pkt_hdr);
}

int  tcp_set_single_stream_needack(const struct streaminfo *pstream)
{
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	pdetail_pr->needackflag=1;
	return 0;
}

int  tcp_set_single_stream_takeoverflag(const struct streaminfo *pstream,int flag)
{
	
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	pdetail_pr->takeoverflag=flag;
	return 0;
}


/* 2014-07-31 LiJia add, for set one stream unorder number */
int tcp_set_single_stream_max_unorder(const struct streaminfo *pstream, UCHAR dir, UINT16 unorder_num)
{
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;
	int ret=-1;
	if((dir & DIR_C2S) && (pdetail_pr->pserver != NULL)){
		if(pdetail_pr->pserver->maxunorder < unorder_num)
		{
			pdetail_pr->pserver->maxunorder = unorder_num;
			ret = 0;
		}	
		else
		{
			ret=-1;
		}
	}

	if((dir & DIR_S2C) && (pdetail_pr->pclient != NULL)){
		if(pdetail_pr->pclient->maxunorder < unorder_num)
		{
			pdetail_pr->pclient->maxunorder = unorder_num;
			ret = 0;
		}
		else
		{
			ret=-1;
		}	
	}

	return ret;
}

void setneedack(struct streaminfo *pstream)
{
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
	pdetail_pr->needackflag=1;
	return;
}

void set_tcp_takeoverflag(struct streaminfo *pstream,int flag)
{
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private*)(pstream->pdetail);
	pdetail_pr->takeoverflag=flag;
	return;
}


static int is_well_known_port(int stream_type, unsigned short port_host_order)
{
	int i;
	const unsigned short *wellknown_port_array;
	int wellknown_port_array_num;

	if(STREAM_TYPE_TCP == stream_type){
		if(NULL == sapp_global_val->config.stream.tcp.well_known_ports_array){
			return 0;
		}
		wellknown_port_array = sapp_global_val->config.stream.tcp.well_known_ports_array;
		wellknown_port_array_num = sapp_global_val->config.stream.tcp.well_known_ports_array_num;
	}else{
		if(NULL == sapp_global_val->config.stream.udp.well_known_ports_array){
			return 0;
		}
		wellknown_port_array = sapp_global_val->config.stream.udp.well_known_ports_array;
		wellknown_port_array_num = sapp_global_val->config.stream.udp.well_known_ports_array_num;		
	}

	for(i = 0 ; i < wellknown_port_array_num; i++){
		if(port_host_order == wellknown_port_array[i]){
			return 1;
		}
	}

	return 0;
}

static int adjust_stream_dir_by_well_known_ports(unsigned char stream_type,UINT16 sport_host, UINT16 dport_host)
{
	int ret;

	ret = is_well_known_port(stream_type,dport_host);
	if(ret != 0){
		return DIR_C2S; 
	}

	ret = is_well_known_port(stream_type,sport_host);
	if(ret != 0){
		return DIR_S2C; 
	}	
	return 0;
}



int set_transport_addr(struct streaminfo *this_stream, int enable_well_known_port, UINT16 sport, UINT16 dport)
{
	struct streaminfo_private *this_stream_pr = (struct streaminfo_private *)this_stream;
	struct layer_addr *this_addr = &this_stream->addr;
	unsigned char dir_by_well_known_port = 0;
	
	if(__ADDR_TYPE_IP_PAIR_V4 == this_addr->addrtype){
		struct stream_tuple4_v4 *ip4_addr = this_addr->tuple4_v4;
		if(enable_well_known_port){
			dir_by_well_known_port = adjust_stream_dir_by_well_known_ports(this_stream->type, ntohs(sport), ntohs(dport));
		}
		if(dir_by_well_known_port != 0){
			if(DIR_C2S == dir_by_well_known_port){
				this_stream_pr->layer_dir = 1; 
				this_stream->curdir = DIR_C2S;
			}else{
				this_stream_pr->layer_dir = 0;
				this_stream->curdir = DIR_S2C;
			}
			this_stream_pr->create_dir_by_well_known_port = 1;
		}else{
			if(ntohs(sport) > ntohs(dport)){
				this_stream_pr->layer_dir = 1; 
				this_stream->curdir = DIR_C2S;
			}else{
				if(unlikely(sport == dport)){
					if(ntohl(ip4_addr->saddr) > ntohl(ip4_addr->daddr)){
						this_stream_pr->layer_dir = 1;
						this_stream->curdir = DIR_C2S;
					}else{
						this_stream_pr->layer_dir = 0;
						this_stream->curdir = DIR_S2C;
					}
				}else{
					this_stream_pr->layer_dir = 0;
					this_stream->curdir = DIR_S2C;
				}
			}
		}
		ip4_addr->source = sport;
		ip4_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV4; 
		this_addr->addrlen = sizeof(struct stream_tuple4_v4);
	}else if(__ADDR_TYPE_IP_PAIR_V6 == this_addr->addrtype){
		struct stream_tuple4_v6 *ip6_addr = this_addr->tuple4_v6;
		if(enable_well_known_port){
			dir_by_well_known_port = adjust_stream_dir_by_well_known_ports(this_stream->type,ntohs(sport), ntohs(dport));
		}
		if(dir_by_well_known_port != 0){
			if(DIR_C2S == dir_by_well_known_port){
				this_stream_pr->layer_dir = 1; 
				this_stream->curdir = DIR_C2S;
			}else{
				this_stream_pr->layer_dir = 0;
				this_stream->curdir = DIR_S2C;
			}
			this_stream_pr->create_dir_by_well_known_port = 1;
		}else{		
			if(ntohs(sport) > ntohs(dport)){
				this_stream_pr->layer_dir = 1;
				this_stream->curdir = DIR_C2S;
			}else{
				if(unlikely(sport == dport)){
					if(memcmp(ip6_addr->saddr, ip6_addr->daddr, IPV6_ADDR_LEN) >= 0){
						this_stream_pr->layer_dir = 1;
						this_stream->curdir = DIR_C2S;
					}else{
						this_stream_pr->layer_dir = 0;
						this_stream->curdir = DIR_S2C;
					}
				}else{
					this_stream_pr->layer_dir = 0;
					this_stream->curdir = DIR_S2C;
				}
			}
		}
		
		ip6_addr->source = sport;
		ip6_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV6; 
		this_addr->addrlen = sizeof(struct stream_tuple4_v6);
	}else{
		assert(0);
	}
	
	return 0;
}




struct streaminfo *skip_proxy_phony_stream(struct streaminfo *a_tcp)
{
int proxy_layer_num = 0;

	while(a_tcp){
		if(is_proxy_stream(a_tcp)){
			a_tcp = a_tcp->pfather;
			if(++proxy_layer_num > 5){
				return NULL;
			}
		}else{
			break;
		}
	}

	return a_tcp;
}


/* 2015-01-12 lijia add  */
static struct buf_unorder *tcp_save_unorder_pkt(struct streaminfo *a_tcp,const void *this_iphdr, 
	const raw_pkt_t *stack_raw_pkt,struct mesa_tcp_hdr *this_tcphdr, 
	unsigned char *tcpdata, int tcpdatalen)
{
	struct buf_unorder *uo_packet;
	struct streaminfo *carry_ip_stream;
	int ip_to_raw_offset = (char *)this_iphdr - (char *)stack_raw_pkt->raw_pkt_data;
	int tcp_to_ip_offset = (char *)this_tcphdr - (char *)this_iphdr;
	int tcpdata_to_tcp_offset = (char *)tcpdata - (char *)this_tcphdr;
	int this_ip_tot_len;
	
	uo_packet = (struct buf_unorder *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_UNORDER,a_tcp->threadnum, sizeof(struct buf_unorder));
	memset(uo_packet, 0, sizeof(struct buf_unorder));

	//carry_ip_stream = skip_proxy_phony_stream(a_tcp->pfather);
	carry_ip_stream = skip_proxy_phony_stream(a_tcp);

	/* ?��???? */
	memcpy(&(uo_packet->raw_pkt),  stack_raw_pkt, sizeof(raw_pkt_t));	
	uo_packet->raw_pkt.raw_pkt_data = sapp_mem_malloc(SAPP_MEM_DYN_TCP_UNORDER,a_tcp->threadnum, stack_raw_pkt->raw_pkt_len);
	memcpy((void *)uo_packet->raw_pkt.raw_pkt_data, stack_raw_pkt->raw_pkt_data, stack_raw_pkt->raw_pkt_len);


	if(labs((char *)this_iphdr - (char *)stack_raw_pkt->raw_pkt_data) > MTU_MAX){
		uo_packet->ip_reassemble_pkt = 1;
		this_ip_tot_len = get_ip_pkt_tot_len(carry_ip_stream, this_iphdr);
		uo_packet->this_ip_hdr = sapp_mem_malloc(SAPP_MEM_DYN_TCP_UNORDER,a_tcp->threadnum, this_ip_tot_len);
		memcpy(uo_packet->this_ip_hdr, this_iphdr, this_ip_tot_len);
		uo_packet->this_tcp_hdr = (struct mesa_tcp_hdr *)((char *)uo_packet->this_ip_hdr + tcp_to_ip_offset);
		if(tcpdatalen > 0){
			uo_packet->tcpdata = (char *)(uo_packet->this_tcp_hdr) + tcpdata_to_tcp_offset;
		}else{
			uo_packet->tcpdata = NULL;
		}
	}else{
		uo_packet->ip_reassemble_pkt = 0;
		uo_packet->this_ip_hdr = (char *)uo_packet->raw_pkt.raw_pkt_data + ip_to_raw_offset;
		uo_packet->this_tcp_hdr = (struct mesa_tcp_hdr *)((char *)uo_packet->this_ip_hdr + tcp_to_ip_offset);
		if(tcpdatalen > 0){
			uo_packet->tcpdata = (char *)(uo_packet->this_tcp_hdr) + tcpdata_to_tcp_offset;
		}else{
			uo_packet->tcpdata = NULL;
		}
	}
	uo_packet->tcpdatalen = tcpdatalen;

	uo_packet->fin = (this_tcphdr->th_flags & TH_FIN);
	uo_packet->rst = (this_tcphdr->th_flags & TH_RST);
	uo_packet->seq = ntohl (this_tcphdr->th_seq);
	uo_packet->urg = (this_tcphdr->th_flags & TH_URG);
	uo_packet->urg_ptr = ntohs (this_tcphdr->th_urp);	

	uo_packet->ipfrag_list = raw_ip_frag_list_global_move_pkt(a_tcp);

	a_tcp->addr.pkttype = PKT_TYPE_TCPUNORDER;//add by lqy 20151222, mark unorder
	
	return uo_packet;
}

static void tcp_free_unorder_pkt(int threadnum, struct buf_unorder *uo_packet)
{
	if(uo_packet->ip_reassemble_pkt != 0){
		sapp_mem_free(SAPP_MEM_DYN_TCP_UNORDER, threadnum, uo_packet->this_ip_hdr);
	}

#if (0 == HIGH_PERF)	
	if(uo_packet->ipfrag_list){
		raw_frags_list_free_one(threadnum, uo_packet->ipfrag_list);
		uo_packet->ipfrag_list = NULL;
	}
#endif

	sapp_mem_free(SAPP_MEM_DYN_TCP_UNORDER,threadnum, (void *)uo_packet->raw_pkt.raw_pkt_data);
	sapp_mem_free(SAPP_MEM_DYN_TCP_UNORDER,threadnum, uo_packet);

	return;
}

static int get_ip_pkt_tot_len(struct streaminfo *ipinfo, const void *this_iphdr)
{
	int ip_tot_len = 0;
	
	if(ADDR_TYPE_IPV4 == ipinfo->addr.addrtype){
		const struct mesa_ip4_hdr *ipv4_hdr = (const struct mesa_ip4_hdr *)this_iphdr;
		ip_tot_len = ntohs(ipv4_hdr->ip_len);
	}else{
		const struct mesa_ip6_hdr *ipv6_hdr = (const struct mesa_ip6_hdr *)this_iphdr;
		ip_tot_len = ntohs(ipv6_hdr->ip6_payload_len) + sizeof(struct mesa_ip6_hdr);
	}

	return ip_tot_len;
}

static inline void update_stream_list_raw_pkt_pointer(struct streaminfo_private *a_tcp_pr, const raw_pkt_t *raw_pkt)
{
	a_tcp_pr->raw_pkt = raw_pkt;
	return;
}

static void tcp_flow_stat_free(int thread_seq, void *project_req_value)
{
	sapp_mem_free(SAPP_MEM_DYN_TCP_FLOW_STAT,thread_seq, project_req_value);
	return;
}


int tcp_flow_stat_init(void)
{
	int project_req_id;
	
	project_req_id = project_producer_register(PROJECT_REQ_TCP_FLOW, "struct", tcp_flow_stat_free);
	if(project_req_id >= 0){
		G_TCP_FLOW_STAT_PROJECT_ID = project_req_id;
	}else{
		G_TCP_FLOW_STAT_PROJECT_ID = -1;
	}

	project_req_id = project_producer_register(PROJECT_REQ_TCP_DEDUCE_FLOW, "struct", tcp_flow_stat_free);
	if(project_req_id >= 0){
		G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = project_req_id;
	}else{
		G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = -1;
	}
	
	return 0;
}

#ifdef __cplusplus
}
#endif

