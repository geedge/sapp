/*
20120603 : 1)修改建立链接的策略 ，datalen>0的包直接建立链接
		   2)应用层不需要的链接，转入nouse状态，而不是直接释放

20140322 : 1)原来设计只有当进入data状态后，才分配pdetail的空间；现在修改为
			流一建立就分配pdetail的空间，当进入data后才分配half的空间
		    2)原来和流相关的一些变量，全部移入pdetail
		    3) 流表的管理，用最里层的地址做hash，用多层地址进行比较
		    
20140329 1)恢复在tcpdetail记录本次丢包字节数pdetail->lostlen
		 2)考虑在tcpallpkt模式中由于不进行乱序重组，不能确保fin，rst等的到达shunx
			顺序，因此不能置流表close状态，只能等淘汰；
	        3)在流表中记录每册的包数字节数的位置调整，为实际到达的顺序
			记录，记录中包含了不带负载的包数目，传统系统中记录了带负载的包数

20141210 1)全面更新streaminfo的相关结构体，使用分离结构体的不同定义
20141213 1)对于tcp_add_new_stream_bydata里面按tcplen=0的包建链接，进入nouse链表
			nouse链表有两种情况，一种是data分析完了opstate=close进入的
			第二种是从一建立就进入了nouse，这时opsate=pending,
		 2) 对上述第二种情况nouse链表有数据包时，恢复到data链表，

20141217 1)对于c2s单向流的第二包，纯ack包是否必须存在，一直存在争议，
	   目前版本中不做严格检查


20150114 对于函数的调用顺序，是先调用tcpall接口，还是先调用tcp接口进行了反复调整
	 原来先调用tcpall，后调用tcp，发现对syn重传无法判断是否有效，是否重置
	 后改为先调用tcp，再调用tcpall，发现 类似某水浒工程，tcp接口，依赖tcpall的标签
	 现在调整为，新建链接尤其data建链接，必须先调用all，在调用tcp，	   
20150126 刘庆云
	对于tcp_free_stream,tcp_reset_stream的操作都改为先调用tcp，再调用tcpall
20150210 lqy
	对于syn+ack慢于syn侧数据的情况，更新本侧数据seq时要判断是否带syn
	 nouse链表的第三种情况
	链接复用 ,syn状态需要重置tcp的状态
*/
#include "sapp_api.h"
#include "sapp_private_api.h"

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
int del_stream_by_time(struct stream_list *plist, const struct streamindex *current_drive_index);

//int g_kill_tcp_remedy_sw = 0; /* 2016-06-21 lijia add, 是否进行FD补救 */

int G_TCP_FLOW_STAT_PROJECT_ID = -1; /* 2016-07-14 lijia copy from sapp */
int G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = -1; /* 单向流, 根据ACK序号推断出的对端理论接收的数据长度 */

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
	//第一次出现数据，认为是正序
	if(curseq==0) return 1;
	//多次出现syn，第一个数据包序号为准
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
	int parsed_opt; /* 正确解析的OPT标准位 */

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
		memset(out_raw_result, 0, sizeof(struct tcp_option));
		
		switch(*opt){
			case TCP_OPT_EOL: /* 无实际意义, 不记录在选项总数里 */
				goto done;
			break;

			case TCP_OPT_NOP: /* 无实际意义, 不记录在选项总数里 */
				opt++;
				opt_len--;
			break;

			case TCP_OPT_MSS:
				if(opt_num >= res_num){
					goto err;
				}
				out_raw_result->type = TCP_OPT_MSS;
				opt++;
				
				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len != 4){
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->short_value = ntohs(*(unsigned short *)opt);
				opt += 2;
				parsed_opt = 1;

				opt_len -= 4;
			break;

			case TCP_OPT_WIN_SCALE:
				if(opt_num >= res_num){
					goto err;
				}
				out_raw_result->type = TCP_OPT_WIN_SCALE;
				opt++;

				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len != 3){
					goto err;
				}	
				out_raw_result->len -= 2;
				out_raw_result->char_value = *opt;
				opt++;
				parsed_opt = 1;	

				opt_len -= 3;
			break;

			case TCP_OPT_SACK:
				if(opt_num >= res_num){
					goto err;
				}
				out_raw_result->type = TCP_OPT_SACK;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len != 2){
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->char_value = 1; /* SACK实际没有值, 此处赋值仅为了便于外部插件使用 */
				opt_len -= 2;
				parsed_opt = 1;
			break;

			case TCP_OPT_TIME_STAMP:
				if(opt_num >= res_num){
					goto err;
				}	
				out_raw_result->type = TCP_OPT_TIME_STAMP;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len != 10){
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

			/* 可以识别但暂不处理的选项, 跳过 */
			case TCP_OPT_SACK_EDGE:
			case TCP_OPT_MD5:
			case TCP_OPT_MULTI_PATH_TCP:
			case TCP_OPT_RIVER_PROBE:
			{
				/*  */
				int this_opt_len;
				
				if(opt_len <= 1){ /* 当前选项长度为0, 或剩余选项长度只有一个字节, 但选项类型非0非1, 错误包! */
					goto err;
				}
				this_opt_len = opt[1];
				if((this_opt_len <= 0) || (this_opt_len > opt_len)){
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
				
				if(opt_len <= 1){ /* 当前选项长度为0, 或剩余选项长度只有一个字节, 但选项类型非0非1, 错误包! */
					goto err;
				}
				this_opt_len = opt[1];
				if((this_opt_len <= 0) || (this_opt_len > opt_len)){
					goto err;
				}
				opt_len -= this_opt_len;
				opt += this_opt_len; 
				parsed_opt = 0;
			}
			break;
		}

		if(parsed_opt){
			out_raw_result++;
			opt_num++;
		}
	}

done:
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
	int parsed_opt; /* 正确解析的OPT标准位 */

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
		memset(out_raw_result, 0, sizeof(struct tcp_option_ext));
		
		switch(*opt){
			case TCP_OPT_EOL: /* 无实际意义, 不记录在选项总数里 */
				goto done;
			break;

			case TCP_OPT_NOP: /* 无实际意义, 不记录在选项总数里 */
				opt++;
				opt_len--;
			break;

			case TCP_OPT_MSS:
				if(opt_num >= res_num){
					goto err;
				}
				out_raw_result->type = TCP_OPT_MSS;
				opt++;
				
				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len !=4){
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->short_value = ntohs(*(unsigned short *)opt);
				opt += 2;
				parsed_opt = 1;

				opt_len -= 4;
			break;

			case TCP_OPT_WIN_SCALE:
				if(opt_num >= res_num){
					goto err;
				}
				out_raw_result->type = TCP_OPT_WIN_SCALE;
				opt++;

				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len != 3){
					goto err;
				}	
				out_raw_result->len -= 2;
				out_raw_result->char_value = *opt;
				opt++;
				parsed_opt = 1;	

				opt_len -= 3;
			break;

			case TCP_OPT_SACK:
				if(opt_num >= res_num){
					goto err;
				}
				out_raw_result->type = TCP_OPT_SACK;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len != 2){
					goto err;
				}
				out_raw_result->len -= 2;
				out_raw_result->char_value = 1; /* SACK实际没有值, 此处赋值仅为了便于外部插件使用 */
				opt_len -= 2;
				parsed_opt = 1;
			break;

			case TCP_OPT_TIME_STAMP:
				if(opt_num >= res_num){
					goto err;
				}	
				out_raw_result->type = TCP_OPT_TIME_STAMP;
				opt++;
				out_raw_result->len = *opt;
				opt++;
				if(out_raw_result->len != 10){
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
				if(opt_num >= res_num){
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

			/* 可以识别但暂不处理的选项, 跳过 */
			case TCP_OPT_SACK_EDGE:
			case TCP_OPT_MD5:
			case TCP_OPT_RIVER_PROBE:
			{
				/*  */
				int this_opt_len;
				
				if(opt_len <= 1){ /* 当前选项长度为0, 或剩余选项长度只有一个字节, 但选项类型非0非1, 错误包! */
					goto err;
				}
				this_opt_len = opt[1];
				if((this_opt_len <= 0) || (this_opt_len > opt_len)){
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
				
				if(opt_len <= 1){ /* 当前选项长度为0, 或剩余选项长度只有一个字节, 但选项类型非0非1, 错误包! */
					goto err;
				}
				this_opt_len = opt[1];
				if((this_opt_len <= 0) || (this_opt_len > opt_len)){
					goto err;
				}
				opt_len -= this_opt_len;
				opt += this_opt_len; 
				parsed_opt = 0;
			}
			break;
		}

		if(parsed_opt){
			out_raw_result++;
			opt_num++;
		}
	}

done:
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


/* LiJia comment: 如果是新建连接, 即resetflag=0, 参数pindex指向栈里的内存;
				如果是四元组重用, 参数pindex指向堆里的内存;
*/
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
	int need_reverse = 0; /* copy地址时, 是否需要将src, dst颠倒 */

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
		//只有当初次建立时直接返回
		if(resetflag==0)
			return NULL;
	}
	if(likely(0 == resetflag)){
		/* 此函数copy了整个pindex结构, 但addr地址内容是另一块内存, 所以并没有copy, 实际还存于pindex指向的内存块里 */
		pindex_tcp=malloc_and_copy_streamindex(threadnum, pindex);
		
		//memcpy(pindex_tcp,pindex,sizeof(struct streamindex));
		pstream_pr = &pindex_tcp->stream;
		pstream = &pstream_pr->stream_public;		

		/* 2014-11-13 lijia modify */
		if(DIR_C2S == createdir){ /* 当前地址在TCP逻辑层面上符合C->S传输方向 */
			if(1 == pstream_pr->layer_dir){
				pstream_pr->stream_dir = 1; /* 在地址传输层面, 和"大地址是客户端"规则相反 */
			}else{
				pstream_pr->stream_dir = 0;
			}
			need_reverse = 0;
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir;
		}else{
			need_reverse = 1; /* 必须将地址方向颠倒, 插件读取地址结构时, src固定指向逻辑上的源地址 */
			if(1 == pstream_pr->layer_dir){
				/* 因为在copy_stream_info_to_heap()中会做地址颠倒, 所以此处就和"大地址是客户端"规则相同了 */
				pstream_pr->stream_dir = 0; 
			}else{
				pstream_pr->stream_dir = 1;
			}
			pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir ^ 1;
		}

#if USE_RBTREE_INSTEAD_LIST
		/* note:
			因为插入rbtree时需要和现有其他流做比较, 用以确定插入left还是right分支,
			对于本流来说, layer_dir自身没有意义了, 但要用于和其他流比较地址大小, 
			所以将layer_dir = stream_dir;
		*/
		pstream_pr->layer_dir = pstream_pr->stream_dir;
#endif

		copy_ipport_union_addr(pstream, &pindex->stream.stream_public, need_reverse);

		hash_add_stream(pindex_tcp);

		pstream_pr->pfather_pr = copy_stream_info_to_heap(SAPP_MEM_DYN_TCP_STREAM, (struct streaminfo_private *)pindex->stream.pfather_pr, need_reverse);	   
		pstream->pfather = (struct streaminfo *)pstream_pr->pfather_pr;
		
#if SAPP_INSECTICIDE
		iterate_stream_list(pstream);
#endif
		/* 2016-07-25 lijia add, 记录当前流最底层隧道类型, 每个流只在创建时做一次即可 */
		get_stream_carry_tunnel_type(pstream, NULL, &pstream_pr->stream_low_layer_tunnel_type);
		
#if 0
		/* TCP层存储的是指针, 真实地址数据存储在IP层, 需更新 */
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
		pstream_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;
		//adjust by lqy 20140515 只有新建时计数
		if(createdir==DIR_S2C){
			pdetail->clientpktnum++;
			pdetail->clientbytes+= datalen; /* 2014-12-19 lijia add, for SYN pkt append data */
		}else if(createdir==DIR_C2S){
			pdetail->serverpktnum++;
			pdetail->serverbytes+= datalen;/* 2014-12-19 lijia add, for SYN pkt append data */
		}	
	}
	else
	{
	 /* TODO 1:
		如果连接重置, 最好不使用原来的streamindex结构, free后再申请一个新的,
		故意使streamindex地址与原来不一样, 主要便于DEBUG.
	 */
	   pindex_tcp=pindex;
		pstream_pr = &pindex_tcp->stream;
		pstream = &pstream_pr->stream_public;	   
	   pdetail_pr = (struct tcpdetail_private *)pstream->pdetail;
	   pdetail=(struct tcpdetail *)pdetail_pr;
		//add by lqy 20150107, 重置计数
		if(createdir==DIR_S2C)
		{
			pdetail->clientpktnum=1;
			pdetail->clientbytes=datalen;
			pdetail->serverpktnum=0;
			pdetail->serverbytes=0;
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
		
		/* 链接复用, 重新生成一个新的streamid */
		pindex_tcp->stream.global_stream_id = get_global_stream_id(threadnum);				
		pdetail->createtime=g_CurrentTime;
		pstream_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;	

		/* 连接重置, 重新判断一下ddos 状态 */
		pstream_pr->under_ddos_bypass = packet_io_under_ddos_should_bypass(threadnum);
	}

	/* 2014-07-31 LiJia add, for set one stream unorder number */
	if(pdetail_pr->pclient){
		pdetail_pr->pclient->maxunorder = tcp_default_unorder;
	}
	if(pdetail_pr->pserver){
		pdetail_pr->pserver->maxunorder = tcp_default_unorder;
	}
	
	pstream_pr->timeout=link_default_nopkt_time;
	pdetail_pr->creat_mod=TCP_CTEAT_LINK_BYSYN;	
	
	pstream->dir=createdir;
	pstream->curdir=createdir;
	//未开启全包接口模式下，直接关闭, add by lqy 20141213
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
		//暂时缓存起始的seq
		pdetail_pr->iclientseq =ntohl (this_tcphdr->th_seq) + 1;
		pdetail_pr->iserverseq=ntohl (this_tcphdr->th_ack);
		//pdetail->clientpkt++; //adjust by lqy 20140515 只有新建时计数
		pdetail_pr->S2C_first_ack_seq = pdetail_pr->iserverseq;
	}
	else if(createdir==DIR_C2S)
	{
		pdetail_pr->iclientseq = 0; /* 2017-12-06 lijia add, 此时S2C方向的ISN还未获取到 */
		pdetail_pr->iserverseq=ntohl (this_tcphdr->th_seq)+1;
		//pdetail->serverpkt++; //adjust by lqy 20140515 只有新建时计数
		pdetail_pr->C2S_first_ack_seq = ntohl (this_tcphdr->th_ack);
	}
	pdetail->lastmtime=g_CurrentTime;	
	pstream_pr->stream_lastupdate_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;	
	pdetail_pr->link_state=STREAM_LINK_JUST_EST;	
	pstream->stream_state=TCP_SYN_STATE;

	if(pstream_pr->under_ddos_bypass){
		/* bypass状态不调用任何插件, 后续的project,  parse_tcp_option等操作都可以忽略了,以节约cpu资源 */
		pstream->stream_state=TCP_NOUSE_STATE;
		streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));
		return pindex_tcp;
	}
	streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));

	/* LiJia add, 某些项目特殊应用初始化, 如标签、原始IP分片列表等 */
	pstream_pr->pproject = project_requirement_create(SAPP_MEM_DYN_TCP_PROJECT, pstream->threadnum);
	pstream_pr->stream_bridge = stream_bridge_create_per_stream(SAPP_MEM_DYN_TCP_BRIDGE, pstream->threadnum);

	/* 2015-12-28 lijia add */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->flow_stat = (struct tcp_flow_stat *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_FLOW_STAT, pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);

		if(0 == resetflag){
			if(DIR_C2S == pstream->curdir){
				pdetail_pr->flow_stat->C2S_all_pkt++;
				pdetail_pr->flow_stat->C2S_all_byte += datalen;
				pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
			}else{
				pdetail_pr->flow_stat->S2C_all_pkt++;
				pdetail_pr->flow_stat->S2C_all_byte += datalen;
				pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len- raw_pkt->overlay_layer_bytes;
			}
		}else{
			if(DIR_C2S == pstream->curdir){
				pdetail_pr->flow_stat->C2S_all_pkt = 1;
				pdetail_pr->flow_stat->C2S_all_byte = datalen;
				pdetail_pr->flow_stat->C2S_all_byte_raw = raw_pkt->raw_pkt_len- raw_pkt->overlay_layer_bytes;
			}else{
				pdetail_pr->flow_stat->S2C_all_pkt = 1;
				pdetail_pr->flow_stat->S2C_all_byte = datalen;
				pdetail_pr->flow_stat->S2C_all_byte_raw = raw_pkt->raw_pkt_len- raw_pkt->overlay_layer_bytes;
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
			; /* SYN包木有ACK, 忽略 */
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

/*
	1)原有设计为没有syn的情况下，直接靠第一个数据包建立链接
	2) 为了兼容全包接口，对于没有数据的包也来建立链接进入NOUSE 状态

	2015-06-10 lijia add "resetflag", 用于流超时淘汰新建连接.
*/
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

 		/* 2016-07-25 lijia add, 记录当前流最底层隧道类型, 每个流只在创建时做一次即可 */
		get_stream_carry_tunnel_type(pstream, NULL, &pstream_pr->stream_low_layer_tunnel_type);
		
		pstream->dir=createdir;
		pstream->curdir=createdir;
		pdetail_pr=(struct tcpdetail_private *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_DETAIL, threadnum,sizeof(struct tcpdetail_private));
		pdetail=&pdetail_pr->tcpdetail_public;
		memset(pdetail_pr,0,sizeof(struct tcpdetail_private));
		pstream->pdetail=(void *)pdetail_pr;

#if USE_RBTREE_INSTEAD_LIST
		if(1 == pstream_pr->layer_dir){
			pstream_pr->stream_dir  = 1; /* 因为是按DATA建连接, 所以stream_dir肯定和默认规则相同 */
			//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
			//set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
		}else{
			pstream_pr->stream_dir  = 1; /* 因为是按DATA建连接, 所以stream_dir肯定和默认规则相同 */
			//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1; /* IP层创建流的方向与当前包传输方向相反 */
			//set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
		}

		/* note:
			因为插入rbtree时需要和现有其他流做比较, 用以确定插入left还是right分支,
			对于本流来说, layer_dir自身没有意义了, 但要用于和其他流比较地址大小, 
			按data建连接中, layer_dir = 1;
		*/
		pstream_pr->layer_dir = 1;
#endif

		hash_add_stream(pindex_tcp); /* 如果resetflag=1, 说明是连接复用, tcp_reset_stream()没有从hash表里删除, 也就不用重复添加了 */
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
		/* 链接复用, 重新生成一个新的streamid */
		pindex_tcp->stream.global_stream_id = get_global_stream_id(threadnum);	

		/* 链接复用, 重新判断一下ddos 状态 */
		pstream_pr->under_ddos_bypass = packet_io_under_ddos_should_bypass(threadnum);		
	}

	pstream->dir=createdir;
	pstream->curdir=createdir;
	//pindex_tcp->stream.stream_dir=pindex_tcp->stream.layer_dir;

	//有数据报文直接进入data状态, by lqy 20141213
	//if(datalen>0)
	//有数的但是不带结束标志的报文adjust by lqy 20150215
	if((datalen>0) && (!(this_tcphdr->th_flags & TH_FIN)) && (!(this_tcphdr->th_flags & TH_RST)))	
	{
		pstream->stream_state=TCP_DATA_STATE;
	}
	else
	{
		pstream->stream_state=TCP_NOUSE_STATE;	
	}
	
	/* TCP层存储的是指针, 真实地址数据存储在IP层, 需更新 */
	//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream.addr);
	//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);

 #if 0	
	set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);
#else  /* 2014-12-16 lijia modify */
	if(1 == pstream_pr->layer_dir){
		pstream_pr->stream_dir  = 1; /* 因为是按DATA建连接, 所以stream_dir肯定和默认规则相同 */
		//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
		//set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
	}else{
		pstream_pr->stream_dir  = 1; /* 因为是按DATA建连接, 所以stream_dir肯定和默认规则相同 */
		//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1; /* IP层创建流的方向与当前包传输方向相反 */
		//set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
	}
#endif

	pstream_pr->timeout=link_default_nopkt_time;
	pdetail_pr->creat_mod=TCP_CTEAT_LINK_BYDATA;	
	pstream->opstate=OP_STATE_PENDING;
	if(tcp_support_all==TCP_SUPPORT_ENTRYALL_OFF) //by lqy 20141213
        {
                pstream->pktstate=OP_STATE_CLOSE;
        }
        else
        {
                pstream->pktstate=OP_STATE_PENDING;
        }	
	pdetail->createtime=g_CurrentTime;	
	pdetail->lastmtime=g_CurrentTime;
	pstream_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;
	pstream_pr->stream_lastupdate_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;
	pdetail_pr->link_state=STREAM_LINK_DATA;	

	if(pstream_pr->under_ddos_bypass){
		/* bypass状态不调用任何插件, 后续的project,  bridge,parse_opt,初始化half_stream等操作都可以忽略了 */
		pstream->stream_state=TCP_NOUSE_STATE;
		streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));
		return pindex_tcp;
	}
	
	streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));
	
	//if(datalen>0)
	//有数的但是不带结束标志的报文adjust by lqy 20150325
	if((datalen>0) && (!(this_tcphdr->th_flags & TH_FIN)) && (!(this_tcphdr->th_flags & TH_RST)))	
	{
		if(pstream->dir==DIR_C2S)
		{
			pdetail_pr->pserver=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM, threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
			//待完善
			pdetail_pr->pserver->first_data_seq=(ntohl (this_tcphdr->th_seq) );
			/* 2014-07-31 LiJia add, for set one stream unorder number */
			pdetail_pr->pserver->maxunorder = tcp_default_unorder;
		}
		 if(pstream->dir == DIR_S2C)
		{
			pdetail_pr->pclient=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
			//待完善
			pdetail_pr->pclient->first_data_seq=(ntohl (this_tcphdr->th_seq) );
			/* 2014-07-31 LiJia add, for set one stream unorder number */
			pdetail_pr->pclient->maxunorder = tcp_default_unorder;
		}
	}
	else //无数据的情况记录临时seq值
	{
		if(createdir==DIR_S2C)
		{
			//暂时缓存起始的seq
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

	/* 2014-03-26 LiJia add, 某些项目特殊应用初始化, 如标签、原始IP分片列表等 */
	pstream_pr->pproject = project_requirement_create(SAPP_MEM_DYN_TCP_PROJECT,threadnum);
	pstream_pr->stream_bridge = stream_bridge_create_per_stream(SAPP_MEM_DYN_TCP_BRIDGE,pstream->threadnum);

	/* 2016-07-14 lijia add */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->flow_stat = (struct tcp_flow_stat *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_FLOW_STAT, pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);

		if(resetflag != 0){
			if(pstream->curdir == DIR_C2S){
				pdetail_pr->flow_stat->C2S_all_pkt = 1;
				pdetail_pr->flow_stat->C2S_all_byte = datalen;
				pdetail_pr->flow_stat->C2S_all_byte_raw = raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
			}else{
				pdetail_pr->flow_stat->S2C_all_pkt = 1;
				pdetail_pr->flow_stat->S2C_all_byte = datalen;	
				pdetail_pr->flow_stat->S2C_all_byte_raw = raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;;
			}
		}
		/* NOTE, tcp_data计数在stream_process_tcp()中累计 */
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

	pstream->opstate=OP_STATE_PENDING;
	
	if(pstream->dir & DIR_C2S)
	{
		if(NULL == pdetail_pr->pserver){
			pdetail_pr->pserver=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
			//待完善
			pdetail_pr->pserver->first_data_seq=pdetail_pr->iserverseq;
			/* pdetail_pr->iserverseq=0; */  /* 2016-04-27 lijia modify, 用于获取当前流的ISN */
			
			/* 2014-10-20 LiJia add, for set one stream unorder number */
			pdetail_pr->pserver->maxunorder = tcp_default_unorder;
		}
	}
	 if(pstream->dir & DIR_S2C)
	{
		if(NULL == pdetail_pr->pclient){
			pdetail_pr->pclient=(struct half_tcpstream *)sapp_mem_malloc(SAPP_MEM_DYN_TCP_HALF_STREAM,threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
			//待完善
			pdetail_pr->pclient->first_data_seq=pdetail_pr->iclientseq;
			/* pdetail_pr->iclientseq=0; */ /* 2016-04-27 lijia modify, 用于获取当前流的ISN */
			
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
 #if 0 
        raw_frags_list_free_one(threadnum, plist->ipfrag_list);
        plist->ipfrag_list = NULL;

		if(plist->data != NULL)
		{
			dictator_free(threadnum,plist->data);
			plist->data = NULL;
		}

		/* 2014-12-01 lijia add, for memory leak */
		if(plist->raw_pkt.raw_pkt_data != NULL){
			dictator_free(threadnum, (void *)plist->raw_pkt.raw_pkt_data);
			plist->raw_pkt.raw_pkt_data = NULL;
		}
		
		ptmp = plist->next;
		dictator_free(threadnum,plist);
#else
		ptmp = plist->next;
		tcp_free_unorder_pkt(threadnum, plist);		
#endif
		plist = ptmp;
	}
	sapp_mem_free(SAPP_MEM_DYN_TCP_HALF_STREAM, threadnum,phalf);
	//phalf = NULL;
}

/* 快速验证pindex是否在plist中 */
static int inline stream_in_timeout_list(const struct streamindex *pindex, const struct stream_list *plist)
{
	if(plist->cnt <= 1){
		/* 只有一个元素时, head==tail==pindex */
		if(plist->head == pindex){
			return 1;
		}else{
			return 0;
		}
	}else{
		/* 多个元素时, next和prev必定有一个不为NULL */
		if((NULL == pindex->next) &&(NULL == pindex->prev)){
			return 0;
		}
	}

	return 1;
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
	/* 2017-01-03 lijia add, 
	   如果在tcp_reset_stream()函数栈内, 调用了tcp_change_stream_tonouse, 
	   pindex已经被移除当前所在list, 不能再继续执行streamleavlist和streamaddlist了.
	*/
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
	/* 2017-12-20 lijia add, 
	   因FIN结束的流进入NOUSE状态,
	   deal_tcp_stream()每次都是TCP_SYN_STATE或TCP_DATA_STATE状态,
	   无法将TCP_NOUSE_STATE状态下的流淘汰出去,
	   所以此处再扫描一次TCP_NOUSE_STATE的超时流.
	 */
	del_stream_by_time(plist, pindex);
}


/* 正常情况下tcp层面已经结束了, 但因为有TCP_ALL插件, 所以实际还不能free, 这种流最终会以TIMEOUT或KICKOUT结束 */
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

	/* TODO 1,
		free分平台靠time, list_lru原因, 此时属于真正的free,
		如果是插件返回CLOSEME, 则只释放相关pdetail内存, 但仍将tcp流结构保留, 为了FD补救功能.

		拆分为两个函数:
		tcp_lite_free(); //只free data, 保留基础结构

		tcp_struct_free(); //free 应用层数据
		
		tcp_thorough_free(); // del_stream_by_time(), streamaddlist()时超过最大数量等函数要调用, 真正的free
							// 包含tcp_light_free(); tcp_struct_free();两个函数

		TODO 1:
			如果在调用tcp_deal_unorder()后, 因乱序包引发的kill_tcp, 应该判断stream_killed_flag标记, 
			如果stream_killed_flag=1, 则后续的包不再处理, 直接tcp_free_half()释放.
	*/

	/* 2014-07-24 lijia add, 流结束前处理乱序包 */
	saved_curdir = pstream->curdir; /* 2015-11-16 LiJia add, 保存当前流方向, 处理乱序包后要恢复当前值 */
	if(pclient && (pclient->unorderlist != NULL)){
		pstream->curdir = DIR_S2C; /* 临时修改 */
		tcp_deal_unorder(pindex, pstream, pclient, pserver, !CHECK_ORDER_DATA);		
	}
	if(pserver && (pserver->unorderlist != NULL)){
		pstream->curdir = DIR_C2S; /* 临时修改 */
		tcp_deal_unorder(pindex, pstream, pserver, pclient, !CHECK_ORDER_DATA);		
	}
	pstream->curdir = saved_curdir;

	pstream_pr->raw_pkt = raw_pkt; /* 如果是因超时淘汰, 此值为NULL; 如果因RST导致淘汰, 为真实原始包 */
	
	if(pstream->stream_state==TCP_DATA_STATE)
	{
		if(pdetail_pr->apme!=NULL)
		{
			pstream->opstate=OP_STATE_CLOSE;
			//tcp stream 回调
			pkt_ret = stream_process_tcp(pstream, this_ip_hdr, transport_hdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));  
			pdetail_pr->apme=NULL;
		}
		if(pclient){
				tcp_free_half(pclient,threadnum);
				pclient = NULL;
		}
		if(pserver){
				tcp_free_half(pserver,threadnum);
				pserver = NULL;
		}
	}

	//不论任何状态回调全包处理函数链表
	if(pdetail_pr->pAllpktpme!=NULL)
	{
			pstream->pktstate=OP_STATE_CLOSE;
			//tcp stream 回调
#if 0			
			pkt_ret = stream_process_tcp_allpkt(pstream, this_ip_hdr, transport_hdr, raw_pkt,&(pdetail_pr->pAllpktpme),&(pstream->pktstate));  
#else
			/* 2017-12-13 lijia modify, TCPALL改为先调用, 所以在tcp_free_stream中, 最后只向TCPALL插件传递流CLOSE状态, 不再给原始包, 指针固定为NULL, 否则就重复了 */
			pkt_ret = stream_process_tcp_allpkt(pstream, NULL, NULL, NULL, &(pdetail_pr->pAllpktpme),&(pstream->pktstate)); 
#endif
			pdetail_pr->pAllpktpme=NULL;
	}

	/* 调用完插件后再从结构中移除, 因为调用插件时, 可能会调用stream_set_single_stream_timeout(), 会操作当前流在LRU链表中的位置 */
	streamleavlist(pindex, plist);
	hash_del_stream(pindex);
	
	if(pstream->pdetail != NULL)
	{
		sapp_mem_free(SAPP_MEM_DYN_TCP_DETAIL, threadnum,pstream->pdetail);
		pstream->pdetail=NULL;
	}

	project_requirement_destroy(SAPP_MEM_DYN_TCP_PROJECT, threadnum, pstream_pr->pproject);
	pstream_pr->pproject = NULL;
	stream_bridge_destroy_per_stream(SAPP_MEM_DYN_TCP_BRIDGE, pstream, pstream_pr->stream_bridge);
	pstream_pr->stream_bridge = NULL;

	if(pstream_pr->timeout > link_default_nopkt_time){ /* 链接独有超时时间, 减少计数 */
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
	
	 //add by lqy 20150107 回退计数
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
			pdetail_pr->flow_stat->C2S_all_byte_raw -= raw_pkt->raw_pkt_len;
		}else{
			pdetail_pr->flow_stat->S2C_all_pkt--;
			pdetail_pr->flow_stat->S2C_all_byte -= datalen;
			pdetail_pr->flow_stat->S2C_all_byte_raw -= raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
		}
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->deduce_flow_stat->C2S_all_pkt--;
			pdetail_pr->deduce_flow_stat->C2S_all_byte -= datalen;
		}else{
			pdetail_pr->deduce_flow_stat->S2C_all_pkt--;
			pdetail_pr->deduce_flow_stat->S2C_all_byte -= datalen - raw_pkt->overlay_layer_bytes;
		}
	}
	
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]);

	/* 2014-07-24 lijia add, 流结束前处理乱序包 */
	saved_curdir = pstream->curdir; /* 2015-11-16 LiJia add, 保存当前流方向, 处理乱序包后要恢复当前值 */
	if(pdetail_pr->pclient && pdetail_pr->pclient->unorderlist != NULL){
		pstream->curdir = DIR_S2C; 
		tcp_deal_unorder(pindex, pstream, pdetail_pr->pclient, pdetail_pr->pserver, !CHECK_ORDER_DATA);		
	}
	if(pdetail_pr->pserver && pdetail_pr->pserver->unorderlist != NULL){
		pstream->curdir = DIR_C2S;
		tcp_deal_unorder(pindex, pstream, pdetail_pr->pserver, pdetail_pr->pclient, !CHECK_ORDER_DATA);		
	}
	/* tcp_deal_unorder()函数可能会修改pstream_pr->raw_pkt, 此处恢复raw_pkt */
	pstream_pr->raw_pkt = raw_pkt;
	pstream->curdir = saved_curdir;

	/* 2015-02-04 lijia add, 
	   先将旧流因超时或因四元组重用淘汰, 当前包不能做为旧流的原始包, 
	   不能因此调用插件后而触发MESA_kill_xxx, 所以设pstream_pr->raw_pkt = NULL.
	 */
	const raw_pkt_t *saved_raw_pkt = pstream_pr->raw_pkt;
	pstream_pr->raw_pkt = NULL; 
	pstream_pr->stream_killed_flag = 0;
	
	if(pstream->stream_state==TCP_DATA_STATE)
	{
		if(pdetail_pr->apme!=NULL)
		{
			pstream->opstate=OP_STATE_CLOSE;
			stream_process_tcp(pstream,NULL, NULL,NULL,&(pdetail_pr->apme),&(pstream->opstate));  
			pdetail_pr->apme=NULL;
		}
		if(pdetail_pr->pclient!=NULL)
		{
			tcp_free_half(pdetail_pr->pclient,threadnum);
			pdetail_pr->pclient=NULL;
		}
		if(pdetail_pr->pserver!=NULL)
		{
			tcp_free_half(pdetail_pr->pserver,threadnum);
			pdetail_pr->pserver=NULL;
		}	
	}

	if(pdetail_pr->pAllpktpme!=NULL)
	{
			pstream->pktstate=OP_STATE_CLOSE;
			//tcp stream 回调
			stream_process_tcp_allpkt(pstream,NULL,NULL,NULL,&(pdetail_pr->pAllpktpme),&(pstream->pktstate));  
			pdetail_pr->pAllpktpme=NULL;
	}

	/* 调用完插件后再从结构中移除, 因为调用插件时, 可能会调用stream_set_single_stream_timeout(), 会操作当前流在LRU链表中的位置 */
	streamleavlist(pindex, plist);
	
	project_requirement_destroy(SAPP_MEM_DYN_TCP_PROJECT, threadnum, pstream_pr->pproject);
	pstream_pr->pproject = NULL;

	stream_bridge_destroy_per_stream(SAPP_MEM_DYN_TCP_BRIDGE, pstream, pstream_pr->stream_bridge);
	pstream_pr->stream_bridge = NULL;

	/* 恢复之前存储的raw_pkt */
	pstream_pr->raw_pkt = saved_raw_pkt;

	pstream_pr->syn_opt_num = 0;     /* 清空选项计数 */
	pstream_pr->synack_opt_num = 0; /* 清空选项计数 */
	if(pstream_pr->syn_opt_array){
		sapp_mem_free(SAPP_MEM_DYN_TCP_SYN_OPT, threadnum, pstream_pr->syn_opt_array);
		pstream_pr->syn_opt_array = NULL;
	}

	if(pstream_pr->synack_opt_array){
		sapp_mem_free(SAPP_MEM_DYN_TCP_SYN_OPT, threadnum, pstream_pr->synack_opt_array);
		pstream_pr->synack_opt_array = NULL;
	}

	free_polling_inject_context(SAPP_MEM_DYN_TCP_POLLING_RAW_PKT, pstream_pr); //2020-06-08 lijia add, for memory leak
	
	if(this_tcphdr->th_flags & TH_SYN){
		tcp_add_new_stream_bysyn(pindex,this_iphdr,this_tcphdr,datalen,REUSE_OLD_LINK,raw_pkt);
		ret = 1;
	}else{
		if(TCP_CTEAT_LINK_BYDATA & tcp_creatlink_model){
			tcp_add_new_stream_bydata(pindex,this_tcphdr,datalen,REUSE_OLD_LINK, raw_pkt);
			ret = 1;
		}else{
			/* 20190506 lijia add, reset之后如果不建新流, 直接free掉 */
			hash_del_stream(pindex);
			if(pstream->pdetail != NULL)
			{
				sapp_mem_free(SAPP_MEM_DYN_TCP_DETAIL, threadnum,pstream->pdetail);
				pstream->pdetail=NULL;
			}			
			if(pstream_pr->timeout > link_default_nopkt_time){ /* 链接独有超时时间, 减少计数 */
				sapp_global_mthread[threadnum].tcp_stream_special_timeout_num--;
			}			
			free_heap_stream_info(SAPP_MEM_DYN_TCP_STREAM, pstream, 0);
			free_streamindex(threadnum,pindex);
			ret = 0;
		}
	}	

	local_sys_stat->count[SAPP_STAT_TCP_STREAM_RESET]++;
	return ret;
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

	if(pstream->dir==DIR_C2S)
	{
		curseq=pdetail_pr->iserverseq;
		if(curdir==DIR_S2C)
		{
			if((this_tcphdr->th_flags & TH_RST)&&(datalen==0))
			{
				if(thisack==curseq)
				{
					pstream->dir=DIR_DOUBLE; /* 更新dir */
			 		pdetail_pr->link_state=STREAM_LINK_RESET;
					tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
					return PASS;
				}			
			}
			else
			//反向来包，建立链接
			if(thisack==curseq)
			{
					pstream->dir=DIR_DOUBLE;
					if(this_tcphdr->th_flags & TH_SYN)
						pdetail_pr->iclientseq=thisseq+1;
					else
						pdetail_pr->iclientseq=thisseq;
					if(this_tcphdr->th_flags == (TH_SYN|TH_ACK)){
 					     pdetail_pr->tcpstateflag=TCP_SYN_RECV;	
 					     tcp_parse_opts(pstream_pr, DIR_S2C, (const struct tcphdr *)this_tcphdr); /* 2016-07-07 lijia add, for janus hijack */
 					}
					return PASS;
			}
			
		}
		else //同侧来包
		{
			//正序报文
			 if(thisseq==curseq)
			 {
			 	if((this_tcphdr->th_flags & TH_RST)&&(datalen==0))
			       {
			 		pdetail_pr->link_state=STREAM_LINK_RESET;
					tcp_free_stream(pindex,  this_iphdr, this_tcphdr, raw_pkt);
					return PASS;
			        }	
				//add by lqy 20130802 单向流防攻击必须有第三个包
			        //单向流第二个ack
			       else  if((this_tcphdr->th_flags == TH_ACK)&&(datalen==0))
			       {
			       	pdetail_pr->tcpstateflag=TCP_SYN_RECV;
					return PASS;
			       }
				else
				{
					//if(TCP_SYN_SENT==pdetail_pr->tcpstateflag ){
				 	   //return DROP;
				 	  return PASS; //2014-12-05 lijia modify, for xj serial
				 	 //}  
				}
				//end add by lqy 20130802
			 } 
		}
	}
	else if (pstream->dir == DIR_S2C)
	{	
		curseq=pdetail_pr->iclientseq;

		if(curdir==DIR_C2S)			
	    	{
		    	if((this_tcphdr->th_flags & TH_RST)&&(datalen==0))
			   {	
			   		pstream->dir=DIR_DOUBLE; /* 更新dir */
			   		pdetail_pr->link_state=STREAM_LINK_RESET;
					tcp_free_stream(pindex,  this_iphdr, this_tcphdr, raw_pkt);
					return PASS;
		    	}
			else
			{
				pstream->dir=DIR_DOUBLE;
				if(this_tcphdr->th_flags & TH_SYN)
					pdetail_pr->iserverseq=thisseq+1;
	            		else
					pdetail_pr->iserverseq=thisseq;
				return PASS;
			}
		}	
		else //同侧来包
		{
			//正序rst
			if((thisseq==curseq)
			 	&&(this_tcphdr->th_flags & TH_RST)
				&&(datalen==0))

			 {
			 	pdetail_pr->link_state=STREAM_LINK_RESET;
					tcp_free_stream(pindex,  this_iphdr, this_tcphdr, raw_pkt);
					return PASS;
			 }
		}

	}
	//add by lqy 20130805 双向流，三次握手完整后存入data表
	else if( pstream->dir == DIR_DOUBLE)
	{
		if((pdetail_pr->tcpstateflag==TCP_SYN_RECV)&&(curdir==DIR_C2S))
		{
			 if((this_tcphdr->th_flags == TH_ACK)&&(datalen==0))
			{
			       	pdetail_pr->tcpstateflag=TCP_ESTABLISHED;
				tcp_change_stream_todata(pindex,this_tcphdr,0); 
		 	}
		}
	}
	//syn重传
	/*
		TODO, 
		四元组相同的两个SYN包, 还要进一步判断SEQ是否一致才能算重传, 可能是四元组重用,
		需要reset.
	*/
	if((this_tcphdr->th_flags == TH_SYN))
	{
		pdetail_pr->iserverseq=thisseq + 1;
		pdetail_pr->multisynflag=1;
		pdetail_pr->tcpstateflag=TCP_SYN_SENT;
	}
	
	if((this_tcphdr->th_flags == (TH_SYN|TH_ACK)))
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

	//流刚开始，ack_seq必为0，此时直接将包头的ack_seq赋值给rcv->ack_seq
	if (0 == *cur_half_stream_ack)
		*cur_half_stream_ack = ntohl(this_tcphdr->th_ack);
	else
	{
		ackdiff = (int)(ntohl (this_tcphdr->th_ack) - *cur_half_stream_ack);
#if 0 /* 20160930 lijia modify, 消除编译警告 */
		if (ackdiff > 0 || ackdiff < -(2 << 30)) //防止重传及翻越序号上限
#else
		if (ackdiff > 0 || ackdiff < (int)0x80000000) //防止重传及翻越序号上限
#endif
		{
			*cur_half_stream_ack = ntohl (this_tcphdr->th_ack);
		}
	}

	//同理
	if (0 == rcv->seq)
		rcv->seq = ntohl(this_tcphdr->th_seq);
	else
	{
		seqdiff = (int)(ntohl(this_tcphdr->th_seq) - rcv->seq);
#if 0	/* 20160930 lijia modify, 消除编译警告, 使用立即数0x80000000 */	
		if (seqdiff > 0 || seqdiff < -(2 << 30))
#else
		if (seqdiff > 0 || seqdiff < (int)0x80000000) //防止重传及翻越序号上限
#endif
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
		phalf->first_data_seq+=1;
		
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
			/* 2017-08-02 lijia modify, 记录本侧第一个ACK号, 和ack_seq一起可以计算出单向流对侧的数据总量 */
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
			/* 2017-08-02 lijia add, C2S单向流获取对端ISN */
			if((0 == pdetail_pr->iclientseq)
			 &&(ntohl(this_tcphdr->th_seq) == pdetail_pr->iserverseq)){ /* C2S方向SYN包后的第一个ACK包 */
				pdetail_pr->iclientseq = ntohl (this_tcphdr->th_ack);
			}
			/* 2017-08-02 lijia modify, 记录本侧第一个ACK号, 和ack_seq一起可以计算出单向流对侧的数据总量 */
			if(0 == pdetail_pr->C2S_first_ack_seq){
				pdetail_pr->C2S_first_ack_seq = ntohl (this_tcphdr->th_ack);
			}
			pdetail_pr->C2S_ack_seq = ntohl (this_tcphdr->th_ack);
			cur_half_stream_ack = &pdetail_pr->C2S_ack_seq;
		}
		
		/* 2017-08-03 lijia add, 单向流, 靠本端ack推断出对侧理论上应该收到的数据 */
		if(DIR_C2S == a_tcp->dir){
			pdetail = a_tcp->ptcpdetail;
			//pdetail->clientbytes = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq;
			if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
				pdetail_pr->deduce_flow_stat->C2S_data_byte = pdetail->serverbytes; /* 单向流本端复制流结构体中的变量 */
				pdetail_pr->deduce_flow_stat->C2S_data_pkt = pdetail->serverpktnum;/* 单向流本端复制流结构体中的变量 */
				
				pdetail_pr->deduce_flow_stat->S2C_all_byte = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq; /* 推断出的结果, all和data是一样的, 但没有pkt */
				pdetail_pr->deduce_flow_stat->S2C_data_byte = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq; /* 推断出的结果, all和data是一样的, 但没有pkt */
			}
		}else if(DIR_S2C == a_tcp->dir){
			pdetail = a_tcp->ptcpdetail;
			//pdetail->serverbytes = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq;
			if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
				pdetail_pr->deduce_flow_stat->S2C_data_byte = pdetail->clientbytes; /* 单向流本端复制流结构体中的变量 */
				pdetail_pr->deduce_flow_stat->S2C_data_pkt = pdetail->clientpktnum;/* 单向流本端复制流结构体中的变量 */
				
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
	u_char* data, int datalen, u_int this_seq,char fin)
{
  	int havelen;
	int len_new=0;
	unsigned char *pdata_new=NULL;
	struct tcpdetail_private*pdetail_pr=(struct tcpdetail_private*)a_tcp->pdetail;
	struct tcpdetail *pdetail=(struct tcpdetail *)&pdetail_pr->tcpdetail_public;

   //不一定是乱序的可能是重传包但是长度比原来大
   if(this_seq< EXP_SEQ)
   {
   	havelen = EXP_SEQ - this_seq;
	if (datalen - havelen > 0)
	{
		//20150225 记录重叠的长度
		pdetail_pr->tcpoverlen=havelen;		
	   len_new= datalen - havelen; 
	   pdata_new=data+havelen;
	}
   }
   else //正序的报文
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

	pdetail->lostlen=rcv->count_ideal-rcv->count-rcv->totallost;
	rcv->totallost+=pdetail->lostlen;

	sapp_global_val->mthread_volatile[a_tcp->threadnum]->sys_stat.length[SAPP_STAT_TCP_LOST_PKT] += pdetail->lostlen;		
	
   	pdetail->datalen=len_new;
	pdetail->pdata=pdata_new;

	if (fin)
		rcv->finstate = FIN_SENT;
 
}

/*
	LiJia add, to do:
	如果因为丢包乱序, 1,2,3,4,x,6, 第5个包丢了, 第6个包被缓存,
	假设第6个包内有特殊信息, 需要kill_tcp,
	当第5个包到来时, streaminfo里存储的都是第5个包的信息,
	然后再处理缓存中第6个包的数据, 此时调用kill_tcp, 相关参数是不对的,
	实际的seq和ack使用的是第5个包的!
	应该使用buf_unorder中的seq和ack, 而不是当前流的原始包.
*/
#if 0
int tcp_save_unorder(struct streaminfo *a_tcp,struct  half_tcpstream  *rcv,char *rawdata,int rawlen,struct mesa_tcp_hdr *this_tcphdr,int tcpdatalen)
#else
static int tcp_save_unorder(struct streaminfo *a_tcp,struct  half_tcpstream  *rcv,
	const void *this_iphdr, const raw_pkt_t *stack_raw_pkt,struct mesa_tcp_hdr *this_tcphdr, 
	unsigned char *tcpdata, int tcpdatalen)
#endif
{
	int threadnum = a_tcp->threadnum;
	struct buf_unorder *p = rcv->unorderlisttail;
	struct buf_unorder *pakiet=NULL;
	unsigned int this_seq = ntohl (this_tcphdr->th_seq);

#if 0	 /* 2015-01-12 lijia modify */
	pakiet = (struct buf_unorder*)dictator_malloc(threadnum,sizeof(struct buf_unorder));
	memset(pakiet, 0, sizeof(struct buf_unorder));

/* 2014-10-20 lijia modify, 因IP分片重组后, raw_pkt和tcpdatalen不对应
raw_pkt指向最后一个分片包, 而tcpdatalen是重组完成后的完整IP包负载!
分别存储!
*/		
	if(tcpdatalen > 0){
		pakiet->data = dictator_malloc(threadnum,tcpdatalen);
		pakiet->len = tcpdatalen;
		memcpy (pakiet->data, tcpdata, tcpdatalen);
	}
	memcpy(&(pakiet->raw_pkt),  stack_raw_pkt, sizeof(raw_pkt_t));	
	pakiet->raw_pkt.raw_pkt_data = dictator_malloc(threadnum, stack_raw_pkt->raw_pkt_len);
	memcpy((void *)pakiet->raw_pkt.raw_pkt_data, stack_raw_pkt->raw_pkt_data, stack_raw_pkt->raw_pkt_len);

	pakiet->tcpdatalen=tcpdatalen;
	pakiet->fin = (this_tcphdr->th_flags & TH_FIN);
	pakiet->rst = (this_tcphdr->th_flags & TH_RST);
	pakiet->seq = this_seq;
	pakiet->urg = (this_tcphdr->th_flags & TH_URG);
	pakiet->urg_ptr = ntohs (this_tcphdr->th_urp);
#else
	pakiet = tcp_save_unorder_pkt(a_tcp, this_iphdr, stack_raw_pkt, this_tcphdr, tcpdata, tcpdatalen);
#endif

	for (;;)
	{
		if (!p || !after (p->seq, this_seq))
			break;
		p = p->prev;
	}
	if (!p)
	{
		pakiet->prev = 0;
		if(rcv->unorderlist)
		  rcv->unorderlist->prev=pakiet;
		pakiet->next = rcv->unorderlist;
		rcv->unorderlist = pakiet;
		if (!rcv->unorderlisttail)
			rcv->unorderlisttail = pakiet;
	}
	else
	{
           //from being repeatly added to the list
            //if (p->seq == this_seq)
		//add by yw 20150311
		if (p->seq == this_seq 
		  || (p->seq+p->tcpdatalen) == (this_seq+pakiet->tcpdatalen)
		  ||after(p->seq+p->tcpdatalen,this_seq+pakiet->tcpdatalen))
             {
#if 0/* 2015-01-12 lijia modify */
             	if(pakiet->data){
				dictator_free(threadnum,pakiet->data);
			}
			dictator_free(threadnum,(void *)pakiet->raw_pkt.raw_pkt_data);
			pakiet->data = NULL;	

			dictator_free(threadnum,pakiet);
			pakiet = NULL;
#else
			tcp_free_unorder_pkt(threadnum, pakiet);
#endif
			return PASS;
               }

		pakiet->next = p->next;
		p->next = pakiet;
		pakiet->prev = p;
		if (pakiet->next)
			pakiet->next->prev = pakiet;
		else
			rcv->unorderlisttail = pakiet;
	}
	rcv->unorder_cnt++;

	//add by yw 20150311, remove overlab saved pkt
	p=pakiet->next;
	while(p != NULL){
		if(before(p->seq+p->tcpdatalen,this_seq+pakiet->tcpdatalen)
		  ||(p->seq+p->tcpdatalen)==(this_seq+pakiet->tcpdatalen)){
			pakiet->next = p->next;
			if(p->next != NULL)	
				p->next->prev = pakiet;
			else
				rcv->unorderlisttail = pakiet;
				
			tcp_free_unorder_pkt(threadnum, p);
			
			rcv->unorder_cnt--;
		}else{
			break;
		}
		p=pakiet->next;
	}

	return 1;
}

static int tcp_deal_unorder(struct streamindex *pindex,struct streaminfo *a_tcp,
		struct  half_tcpstream  *rcv, struct half_tcpstream *snd,int orderflag)
{
	struct buf_unorder *pakiet, *tmp;
	int ret;
	unsigned char tmpktype;
   	struct tcpdetail_private *pdetail_pr;
   	struct streaminfo_private *a_tcp_pr;
   	const raw_pkt_t *cur_raw_pkt;
   	UCHAR last_link_state;

	pakiet = (struct buf_unorder *) rcv->unorderlist;
	if(likely(NULL == pakiet)){
		return PASS;
	}

	ret=PASS;
	pdetail_pr=(struct tcpdetail_private*)(a_tcp->pdetail);
	a_tcp_pr = (struct streaminfo_private *)a_tcp;
	cur_raw_pkt = a_tcp_pr->raw_pkt;
	
	//add by yw 20150316 save tcpoverlen before deal_unorder
	UINT16 t_tcpoverlen = pdetail_pr->tcpoverlen;
	pdetail_pr->tcpoverlen = 0;
	
	while (pakiet)
	{
		if(a_tcp->opstate== OP_STATE_CLOSE)
		{
			ret = PASS;
			goto done;
		}	
		
		if ((after (pakiet->seq, EXP_SEQ)) && (orderflag==CHECK_ORDER_DATA)){
			ret = PASS;
			goto done;
		}

		if (after (pakiet->seq + pakiet->tcpdatalen+pakiet->fin+pakiet->rst, EXP_SEQ))
		{                    
			/* 2015-01-13 lijia add, 如果因乱序包触发kill_tcp或inject相关函数, 需要更新原始包信息 */
			update_stream_list_raw_pkt_pointer(a_tcp_pr, &pakiet->raw_pkt);
			
			if(pakiet->rst )//add by lqy 20100805)
			{
				last_link_state = pdetail_pr->link_state;
				pdetail_pr->link_state=STREAM_LINK_RESET;
				a_tcp->opstate = OP_STATE_CLOSE;
#if (0 == HIGH_PERF)  				
				update_stream_ip_frag_list(a_tcp, pakiet->ipfrag_list); /* lijia add for raw ip frag list */
				pakiet->ipfrag_list = NULL;
#endif				
				tmpktype=a_tcp->addr.pkttype;
				//a_tcp->addr.pkttype=tmpktype|PKT_TYPE_TCPUNORDER|a_tcp->pfather->addr.pkttype; /* lijia add, 将IP分片类型带到上层 */
				a_tcp->addr.pkttype=PKT_TYPE_TCPREORDER;
				//ret=stream_process_tcp(a_tcp,pakiet->data,&(pdetail->apme),&(a_tcp->opstate));
				ret=stream_process_tcp(a_tcp,pakiet->this_ip_hdr, pakiet->this_tcp_hdr, &(pakiet->raw_pkt),&(pdetail_pr->apme),&(a_tcp->opstate));
				a_tcp->addr.pkttype=tmpktype;
#if (0 == HIGH_PERF)					
				raw_frags_list_free_stream(a_tcp->threadnum, a_tcp);/* lijia add for raw ip frag list */
#endif		
				/* 2016-05-12 lijia add, 解决因乱序包导致unorder_list超长BUG, 此处应将流置于nouse状态 */
				if(STREAM_LINK_DATA == last_link_state){
				    tcp_update_should_close_reason_stat(a_tcp->threadnum);
					tcp_change_stream_tonouse(pindex);
					ret = DROP;
					goto done;
				}
				/* 因为调用了update_stream_list_raw_pkt_pointer, 此处不能返回, 先恢复原始包指针 */
				ret = PASS;
				goto done;
			}
			else
			{
				if(rcv->unorder_cnt > rcv->maxunorder || orderflag!=CHECK_ORDER_DATA)//add by lqy 20150325
				{
					//20150401 lqy
					if(after(pakiet->seq,EXP_SEQ))
					{
						rcv->count_ideal = pakiet->seq   - rcv->first_data_seq;
					}
					//add by lqy 20150331 for payload overlap in deal reorder 
					if(rcv->unorder_cnt > rcv->maxunorder)
						orderflag = CHECK_ORDER_DATA;
				}

				//get tcp的data和len
#if 0	/* 2014-01-12 lijia modify */			
				tcp_set_new_data(a_tcp,rcv,snd,(u_char *)(pakiet->data)+(pakiet->len-pakiet->tcpdatalen),
					pakiet->tcpdatalen,pakiet->seq,pakiet->fin);
#else
				tcp_set_new_data(a_tcp,rcv,snd,(u_char *)(pakiet->tcpdata),
					pakiet->tcpdatalen,pakiet->seq,pakiet->fin);
#endif
				if(pakiet->tcpdatalen >0)
				{
					/* 2021-04-29 lijia add, 插件调用了Kill_tcp,或者设置了MSO_DROP_STREAM, 即便是暂存的乱序包, 也不再调用插件 */
					if((0 == a_tcp_pr->stream_killed_flag) && (0 == pdetail_pr->drop_stream_flag)){
#if (0 == HIGH_PERF)  				
						update_stream_ip_frag_list(a_tcp, pakiet->ipfrag_list);
						pakiet->ipfrag_list = NULL;
#endif					
						tmpktype=a_tcp->addr.pkttype;
						//a_tcp->addr.pkttype=tmpktype|PKT_TYPE_TCPUNORDER|a_tcp->pfather->addr.pkttype;	
						a_tcp->addr.pkttype=PKT_TYPE_TCPREORDER;
						//ret=stream_process_tcp(a_tcp,pakiet->data,&(pdetail->apme),&(a_tcp->opstate));
						ret=stream_process_tcp(a_tcp,pakiet->this_ip_hdr,pakiet->this_tcp_hdr,&(pakiet->raw_pkt),&(pdetail_pr->apme),&(a_tcp->opstate));
						a_tcp->addr.pkttype=tmpktype;	
#if (0 == HIGH_PERF)
						raw_frags_list_free_stream(a_tcp->threadnum, a_tcp);
#endif					
						tcp_clear_newdata(a_tcp,rcv);
					}
					
					//发现到信息，立即返回
					//if(ret!=PASS)
					/* 2015-01-16 lijia modify, 并联模式下, 插件调用了Kill_tcp(), 但不会返回DROP, 为了让其他插件仍可以看到此包 */
					//if((ret!=PASS) || (a_tcp_pr->stream_killed_flag != 0)) 
					if((a_tcp_pr->stream_killed_flag != 0) || (pdetail_pr->drop_stream_flag != 0))  /* 2015-11-02 lqy modify, 乱序包处理不判断返回值 */
					{
						/* 因为调用了update_stream_list_raw_pkt_pointer, 此处不能返回, 先恢复原始包指针 */
						goto done;
					}
				}
			}
			if (pakiet->prev)
					pakiet->prev->next = pakiet->next;
			else
					rcv->unorderlist= pakiet->next;
			if (pakiet->next)
					pakiet->next->prev = pakiet->prev;
			else
					rcv->unorderlisttail= pakiet->prev;
			tmp = pakiet->next;
#if 0	/* 2015-01-12 lijia modify */		
			if(pakiet->data){
				dictator_free(a_tcp->threadnum,pakiet->data);
			}
			if(pakiet->ipfrag_list){//2014-11-25 lijia add for memory leak.
				raw_frags_list_free_one(a_tcp->threadnum, pakiet->ipfrag_list);
				pakiet->ipfrag_list = NULL;
			}
			dictator_free(a_tcp->threadnum, (void *)pakiet->raw_pkt.raw_pkt_data);
			dictator_free(a_tcp->threadnum,pakiet);
#else
			tcp_free_unorder_pkt(a_tcp->threadnum, pakiet);
#endif
			pakiet = tmp;
			rcv->unorder_cnt--;                    
		}
		else
		 {
			pakiet = pakiet->next;
		 }			
	}

done:	
	update_stream_list_raw_pkt_pointer(a_tcp_pr, cur_raw_pkt); /* 2015-01-13 lijia add, recover pointer */

	pdetail_pr->tcpoverlen = t_tcpoverlen;//add by yw 20150316 set tcpoverlen back
	return ret;
}
#if 0
int tcp_deal_data(struct streamindex *pindex,void *rawdata,int rawlen,
	struct mesa_tcp_hdr *this_tcphdr,unsigned char *tcpdata,int datalen)
#else
static int tcp_deal_data(struct streamindex *pindex,const void *this_iphdr,const raw_pkt_t *raw_pkt,
	struct mesa_tcp_hdr *this_tcphdr,unsigned char *tcpdata,int datalen)
#endif
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
		//正序数据包
		if (after(this_seq + datalen + 
			(this_tcphdr->th_flags & TH_FIN), EXP_SEQ))
		{
			tcp_set_new_data(pstream,rcv,snd,tcpdata,datalen,this_seq,this_tcphdr->th_flags & TH_FIN);
			if(datalen >0)
			{
				ret=stream_process_tcp(pstream,this_iphdr,(const void *)this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
				//tcp_clear_newdata(pstream,rcv); /*  2016-09-12 lijia move to outside if(datalen > 0) */
			}
			tcp_clear_newdata(pstream,rcv); /* 2016-09-12 lijia move to here, 不论datalen是否>0, 因为调用了tcp_set_new_data, 所以要调用clear */

#if 0	/* lqy 2015-11-02 modify, 对乱序包的处理结果, 不影响当前包的返回值 */		
			if(ret==PASS) 
			{	
				ret = tcp_deal_unorder(pindex,pstream,rcv,snd,CHECK_ORDER_DATA);
				
			}
#else
		/* 2020-04-24 lijia modify, 如果ret=stream_process_tcp返回值是DROP,   tcp_deal_unorder()返回值是PASS, 当前包就是PASS, 结果就CT了! */
			ret_unorder = tcp_deal_unorder(pindex,pstream,rcv,snd,CHECK_ORDER_DATA);
#endif			
			if((DROP == ret_unorder) || (DROP == ret)){
				ret = DROP;
			}
			return ret;			
		}
		//处理原来缓冲的数据包是否已经正序，进行处理
	}
	else
	{
		//乱序数据包缓冲
		tcp_save_unorder(pstream,rcv,this_iphdr,raw_pkt,this_tcphdr,tcpdata, datalen);		
		if(rcv->unorder_cnt > rcv->maxunorder)
		{
			ret=tcp_deal_unorder(pindex,pstream,rcv,snd, !CHECK_ORDER_DATA);
		}
		pdetail_pr->has_lost_pkt_flag = 1;
	}     
	return ret;
} 

/*
	2017-10-16 lijia add,
	判断NOUSE状态下, 收到SYN, SYN/ACK是真的四元组重用, 还是乱序重传, 或分流汇聚导致的时序错乱.
	TODO:
	    增加超时判断, 在线统计发现, 真正的四元组重用通常都在30秒以上.
*/
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
			is_reuse = 0; /* 四元组相同, 但序号不同的两个流间隔时间太短, 一般30秒以上, 疑似攻击或逃逸 */
		}
	}

	return is_reuse;
}


#if 0
static int tcp_deal_data_stream(struct streamindex *pindex,const raw_pkt_t *raw_pkt,struct mesa_tcp_hdr *this_tcphdr,int datalen)
#else
static int tcp_deal_data_stream(struct streamindex *pindex,const void *this_iphdr, 
				const raw_pkt_t *raw_pkt,struct mesa_tcp_hdr *this_tcphdr,int datalen)
#endif
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
	pstream_pr->stream_lastupdate_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;

	
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
	//重传包丢弃
	//if((thisseq<curseq)&&(thisseq+datalen<=curseq)&&(!(this_tcphdr->th_flags & TH_SYN))){ // modify by lqy 20150325
	if(before(thisseq,curseq)&&before(thisseq+datalen,curseq+1)&&(!(th_flags & TH_SYN))){
		pstream->addr.pkttype = PKT_TYPE_TCPRETRANS;
		return PASS;
	}
	//rst
#if 0	
	if( (this_tcphdr->th_flags & TH_RST)&&(curseq!=0))    
#else //modify by LiJia 2015-11-12
	if( (th_flags & TH_RST)&&(curseq!=0)&&(pdetail_pr->ignore_rst_fin==0))
#endif
	{
		/* 2014-07-31 LiJia modify, for one stream unorder number  */
		//if(thisseq>curseq+(pcurhalf->maxunorder+1)*1460)
		if(after(thisseq, curseq+(pcurhalf->maxunorder+1)*1460))//modify by lqy 20150325
			 return PASS;
		 //syn+rst drop packet
		 if(th_flags & TH_SYN)
			return PASS; 
		 //正序的rst报文
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
		 //乱序的rst报文，如果链接未建立，会丢弃，链接已经建立，会进入排序
	}

	//链接复用 
	if (th_flags & TH_SYN)
	{
		//syn重传 add by lqy 20100808
#if 0		
	   if(thisseq+1 == rcv->first_data_seq) return PASS;
#else
	   if((datalen>0) || ((UINT32)thisseq+1 == rcv->first_data_seq) || ((UINT32)thisseq==rcv->first_data_seq)) 
	   {
		pstream->addr.pkttype = PKT_TYPE_TCPRETRANS;
		return PASS;
	   }else{
			/* 2017-12-19 lijia add, 
				非SYN重传, 要判断超时时间, 再决定是否按四元组重用重置当前连接 ,
				距离上一次收到包, 还不超过3秒, 基本不太可能是四元组重用, 
				认为是恶意逃逸.
				
				根据在线统计值, 四元组重用两个连接的时间间隔一般在分钟级.
			*/
			if(tcp_tuple4_reuse(pstream, pdetail_pr, this_tcphdr) == 0){
				return PASS;
			}
	   }
#endif   
	   //adjust by lqy 20150107
	   //if(thisseq==rcv->first_data_seq) return PASS;
	   //add by lqy 20110507 syn带数据的认为是攻击丢弃
	   //if(datalen>0) return PASS;
	   //return PASS;	
	   if(th_flags & TH_RST)
	   {
	   		//MESA_runtime_log(RLOG_LV_FATAL, "[tcp_deal_data_stream]:","syn_rst,curseq:%d\n",curseq);
			return PASS;
	   }
	    pdetail_pr->link_state=STREAM_LINK_REUSE_BYSYN;
		pstream->opstate= OP_STATE_CLOSE;
		
#if 0		//del by lqy 20150107 tcp_reset_stream里面会更正计数后调用
		ret=stream_process_tcp(pstream,raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
#endif		
		tcp_reset_stream(pindex,this_iphdr,this_tcphdr,datalen,raw_pkt);
		return PASS;		
	}
	if(datalen + (th_flags & TH_FIN) +(th_flags & TH_RST)> 0)//处理TCP负载
	{
		tcpdata=(unsigned char*)(this_tcphdr) + 4 * this_tcphdr->th_off;
		ret=tcp_deal_data(pindex,this_iphdr,raw_pkt,this_tcphdr,tcpdata,datalen);	

/* 2016-05-12 lijia modify, 解决因乱序包导致unorder_list超长BUG, 当前流如果已经是CLOSE状态, 此处应无条件return, 不用继续执行 */			

		
		//当上层关闭链接，或者处理到了乱序的rst报文
		if((pstream->opstate==OP_STATE_CLOSE)&&(pdetail_pr->link_state!=STREAM_LINK_RESET))
		{	
			tcp_change_stream_tonouse(pindex);
			return ret;
        	}

		if(ret==DROP)
			return DROP;
	}
	//add by lqy 20120922 上层需要ack的信息时上传不带数据的报文
	else if(pdetail_pr->needackflag!=0)
	{
		ret=stream_process_tcp(pstream,this_iphdr,this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
		//当上层关闭链接，或者处理到了乱序的rst报文
		/* 2017-08-01 lijia modify, 还要判断TCPALL插件状态, 单独只挂载TCPALL插件时, opstate已经是CLOSE了, 不能置于NOUSE态 */
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
	//正序带数据的rst报文要关闭	
	if ((th_flags & TH_RST)&&(thisseq==curseq) &&(datalen!=0))
	{
		pdetail_pr->link_state=STREAM_LINK_RESET;
		finclose=1;
	}
	/* 2015-11-12 lijia add, 不会因RST, FIN包将流结束 */
	if(pdetail_pr->ignore_rst_fin != 0){
		finclose = 0;
	}
	if(finclose)
	{
		pstream->opstate = OP_STATE_CLOSE;
	
		ret=stream_process_tcp(pstream,this_iphdr,this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
		//adjust by lqy 如果有全包接收的函数挂载时
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

	//add by lqy 20141213
	//如果是靠ack建立的链接，应用层未分析过,则恢复到数据链进行分析
	//if((pstream->opstate == OP_STATE_PENDING) && (datalen>0)) //modify by lqy 20150325
	if((pstream->opstate == OP_STATE_PENDING) 
	  && (datalen>0) 
	  && (!(this_tcphdr->th_flags & TH_FIN)) 
	  && (!(this_tcphdr->th_flags & TH_RST))
	  && (TCP_CTEAT_LINK_BYDATA & tcp_creatlink_model))
	{
		tcp_change_stream_todata(pindex,this_tcphdr,datalen);
		return tcp_deal_data_stream(pindex,this_iphdr,raw_pkt,this_tcphdr,datalen);
	}


	//fin和rst都有可能是乱序报文，如果在此处淘汰，则乱序报文有可能会继续去按照数据建立链接，因此不淘汰
	
	//链接复用 add by lqy 20150210 当该链接后继有数据时能恢复到data链表中
	//add by lqy 20130822 当有所有包都接收的函数挂载时，不做主动淘汰
	if (this_tcphdr->th_flags & TH_SYN)
	{
		if(1 == tcp_tuple4_reuse(pstream, pdetail_pr, this_tcphdr)){
			pdetail_pr->link_state=STREAM_LINK_REUSE_BYSYN;
			tcp_reset_stream(pindex,this_iphdr,this_tcphdr,datalen,raw_pkt);
		}
		return PASS;
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

	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_S2C == pstream->curdir){
			pdetail_pr->flow_stat->S2C_all_pkt++;
			pdetail_pr->flow_stat->S2C_all_byte += tcplen;
			pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
		}else{
			pdetail_pr->flow_stat->C2S_all_pkt++;
			pdetail_pr->flow_stat->C2S_all_byte += tcplen;
			pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
		}
	}
	
	//新建链接必须先调用all函数
	ret=tcp_processallpkt(pstream,this_iphdr,this_tcphdr,tcplen,raw_pkt);	

	if(DROP == ret){ 
		/* 2016-06-08 lijia add,
			for HMD, 如果命中规则当前流被kill, 不继续再调用后续插件.
		*/
		return DROP;
	}
	
	if(pstream->stream_state==TCP_DATA_STATE)
	{
			ret=tcp_deal_data_stream(pindex_tcp,this_iphdr,raw_pkt, this_tcphdr,tcplen); 		
	}
	else if(pstream->stream_state==TCP_NOUSE_STATE)
	{
			ret=tcp_deal_nouse_stream(pindex_tcp,this_iphdr,raw_pkt,this_tcphdr,tcplen);
	}
		
	return ret;
}


static int deal_tcp_stream_dup_pkt_check(int tid, struct streaminfo_private *pstream_pr, struct tcpdetail_private *ptcpdetail_pr,
										   const struct mesa_ip4_hdr * this_iphdr, struct mesa_tcp_hdr *this_tcphdr)
{
	int is_dup_pkt = 0;
	int need_add_bloom_filter = 0;
	int dup_check_enabled = 0;
	
	if((ADDR_TYPE_IPV4 == pstream_pr->stream_public.addr.addrtype)
	 && sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp){
		// 对于原始输入包, 只判断前N个包, 如果没发现重复流量, 就认为以后的都不是重复包!
		// todo: 此处是否要通过配置文件指定？
		if((0 == pstream_pr->has_duplicate_pkt) 
		  && (ptcpdetail_pr->tcpdetail_public.clientpktnum+ptcpdetail_pr->tcpdetail_public.serverpktnum >= SAPP_DUP_FIRST_PKT_NUM)){ 
			dup_check_enabled = 0;
			need_add_bloom_filter = 0;
		}else{	
			dup_check_enabled = 1;
			need_add_bloom_filter = 1;
		}
	}
	
	if(sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_all_inject){
		/* 对于注入包查询来说, 此处只查询但不加入bloom filter, 发包时已经加过一次了 */
		dup_check_enabled = 1;
	}
	
	if(dup_check_enabled != 0){
		is_dup_pkt = sapp_dup_pkt_identify_tcp(tid, pstream_pr, this_iphdr, this_tcphdr, need_add_bloom_filter);
	}
	
	
return is_dup_pkt; 

}


/* LiJia comment: pstream指向栈里的内存 */
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
	int call_tcpall_after_reset = 0; /* 2019-10-18 lijia modify, 当前流被reset之后,保证先调用tcpall,再调用tcp */	
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[pstream->threadnum]->sys_stat;

	pindex_tcp = findstreamindex (pindex, raw_pkt);
	if(unlikely(!pindex_tcp)){
		/* 每个流的首包无需检测, 也无法得知是否重复, 但要加入bloom filter */
		if((ADDR_TYPE_IPV4 == pstream->addr.addrtype) 
		  && sapp_global_val->config.packet_io.dup_pkt_para.dup_pkt_distinguish_ipv4_tcp){
			sapp_dup_pkt_mark_tcp(pstream->threadnum,pstream->addr.addrtype, this_iphdr, this_tcphdr);
		}

		if(this_tcphdr->th_flags & TH_SYN)
		{
			//add by yw to detect synflood attack
			//if(g_RunSYNFloodDetect == 1)
			if (unlikely(TCP_SYNFLOOD_DETECT_ON & tcp_flood_detect_model))
			{
#if 0			
				if( synflood_detector(pstream->threadnum) == ATTACKING)
               	{     
                    tcp_creatlink_model = TCP_CTEAT_LINK_BYDATA;
					return PASS;
               	}
                else
#endif                
                {
                	tcp_creatlink_model = TCP_CTEAT_LINK_BYSYN;
                }
			}

			//end of add by yw to detect synflood attack		
			if(0==(TCP_CTEAT_LINK_BYSYN & tcp_creatlink_model ))
				return PASS;
		
			pindex_tcp=tcp_add_new_stream_bysyn(pindex,this_iphdr, this_tcphdr,tcplen,CTREAT_LINK,raw_pkt);
			if(likely(pindex_tcp != NULL))
			{
				pstream_pr = &pindex_tcp->stream;
				pstream = &pstream_pr->stream_public;
				//terminal_tag_probe(pstream, this_tcphdr, this_iphdr);
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
					sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream:%s under ddos bypass!", printaddr(&pstream->addr, pstream->threadnum));
					ret = PASS;
				}else{
					ret=tcp_processallpkt(pstream,this_iphdr,this_tcphdr,tcplen,raw_pkt);
				}
			}
			return ret; 
		}
//		else if(tcplen>0)
		else
		{
			/*   2017-12-07 lijia add,  
				TCPRFC规定, 在链接还未建立的情况下, 收到对端的数据包, 回应的RST包序号为0, 
				如果一个流的第一个包, 就是个seq=0的RST包, 暂时丢弃不处理, 无意义.
			*/
			if((this_tcphdr->th_flags & TH_RST) && (0 == this_tcphdr->th_seq)){
				return PASS;
			}
			//add by lqy 20141213全包接口下才用tcplen=0的包建链接
			if((tcplen==0)&&(tcp_support_all==TCP_SUPPORT_ENTRYALL_OFF))
				return PASS;		
			if(TCP_CTEAT_LINK_BYDATA  & tcp_creatlink_model )
			{
				//add by yw to detect dataflood attack
#if 0				
				//if(tcplen < g_DataFloodPacketLen && g_RunDataFloodDetect == 1)
				if((tcplen<tcp_dataflood_pktlen) && (1==(TCP_DATAFLOOD_DETECT_ON  & tcp_flood_detect_model)))
				{
					if( dataflood_detector(pstream->threadnum) == ATTACKING)
					{
						tcp_creatlink_model = TCP_CTEAT_LINK_BYSYN;
						return PASS;
					}
				}
#endif				
				//end of add by yw to detect dataflood attack			
			pindex_tcp=tcp_add_new_stream_bydata(pindex,this_tcphdr,tcplen,CTREAT_LINK, raw_pkt);
			
			if(likely(pindex_tcp != NULL))
			{
				pstream_pr = &pindex_tcp->stream;
				pstream = &pstream_pr->stream_public;
				pstream_pr->raw_pkt = raw_pkt;  //add by lijia 20171206
				//add by lqy 20150114 新建立的链接必须先调用all函数
				if(pstream_pr->under_ddos_bypass){
					local_sys_stat->count[SAPP_STAT_TCP_BYPASS_STREAM]++;
					local_sys_stat->count[SAPP_STAT_TCP_BYPASS_PKTS]++;
					local_sys_stat->length[SAPP_STAT_TCP_BYPASS_BYTES]+= tcplen;	
					cycle_pkt_dump_by_classify(pstream->threadnum, raw_pkt, PKT_CLASSIFY_BYPASS);
					sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream:%s under ddos bypass!", printaddr(&pstream->addr, pstream->threadnum));			
					ret = PASS;
				}else{
					ret = tcp_process_newstreambydata(pindex_tcp,this_iphdr, this_tcphdr,tcplen,raw_pkt);
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
		/* 2015-11-04 lijia add, IP分片类型更新, pstream指向流表中的结构, pindex为栈里当前包结构 */	
		pstream->addr.pktipfragtype = pindex->stream.stream_public.addr.pktipfragtype; 
	}

	pdetail_pr =(struct tcpdetail_private*)(pstream->pdetail);
	pdetail =(struct tcpdetail *)(&pdetail_pr->tcpdetail_public);

	pdetail->lastmtime=g_CurrentTime;
	pstream_pr->stream_lastupdate_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;

	/* ddos bypass优先级最高 */
	if(pstream_pr->under_ddos_bypass){
		local_sys_stat->count[SAPP_STAT_TCP_BYPASS_PKTS]++;
		local_sys_stat->length[SAPP_STAT_TCP_BYPASS_BYTES]+= tcplen;
		/* 疑似ddos攻击时只是保护自身, 不调用插件节约CPU, 不对包进行丢弃操作, 所以是返回PASS */
		cycle_pkt_dump_by_classify(pstream->threadnum, raw_pkt, PKT_CLASSIFY_BYPASS);
		return PASS;
	}

	/* 2014-10-11 lijia add, Fd补救由平台实现 */
	if(unlikely(pstream_pr->stream_killed_flag != 0)){
		if((pdetail_pr->auto_remedy_flag != 0) && (tcplen > 0)){ /* 防止flood攻击, 只有带数据的包才发RST */
			sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream: %s, kill_tcp remedy, curdir:%d, send RST pkt.", 
				printaddr(&pstream->addr, pstream->threadnum), pstream->curdir);
			MESA_kill_tcp_remedy(pstream, raw_pkt);
		}
		
#if 0 /* MSO_TCPALL_VALID_AFTER_KILL option is obsoleted! */ 
		pdetail_pr = (struct tcpdetail_private *)(pindex_tcp->stream.stream_public.pdetail);
		if(pdetail_pr->tcpall_valid_after_kill != 0){
			tcp_processallpkt(pstream,this_iphdr,this_tcphdr,tcplen,raw_pkt);
		}
#endif		
		//return DROP; /* 2019-11-20 lijia modify, kill_tcp后默认行为不是DROP, 只发送rst包, 是否丢包取决于drop_stream_flag */
	}

	/* 
		2021-05-18 lijia close ipv6 dup pkt check:
		IPv6因为没有Ipid字段, 无法区别真正的应用层重传和重复流量, 开启了会导致断网或者CT, 所以不支持!!!
	
		对于IPv6的两种情况:
		   1)如果开启了代理策略, 重传包被识别成了重复包的话, sapp就直接PASS了, 实际那个包是真实通信双方发的, 没有经过tfe处理, 可能就断网了.
		   2)如果开启了firewall的drop策略, 第一次drop成功了, 但应用层会重传, 重传包被识别成了重复包的话, sapp就直接PASS了, 导致CT.
	*/
	if(deal_tcp_stream_dup_pkt_check(pstream->threadnum, pstream_pr, pdetail_pr, this_iphdr, this_tcphdr) != 0){
		local_sys_stat->count[SAPP_STAT_RCV_DUP_TCP]++;
		local_sys_stat->length[SAPP_STAT_RCV_DUP_TCP] += tcplen;	
		cycle_pkt_dump_by_classify(pstream->threadnum, raw_pkt, PKT_CLASSIFY_REPEAT);
		return PASS;
	}

	if(unlikely(pdetail_pr->drop_stream_flag != 0)){
		sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream: %s, has been set drop flag, curdir:%d, return DROP.", 
						printaddr(&pstream->addr, pstream->threadnum), pstream->curdir);
		lrustream(pindex_tcp);
		return DROP;
	}

	if(pstream->curdir==DIR_S2C)
	{
		if(pdetail->clientpktnum == 0) /* 当前方向的第一个包, 尝试更新底层隧道的单向地址信息(如MPLS, GTP) */
		{
			try_to_update_addr_info = 1;
		}
		pdetail->clientbytes+=tcplen;
		pdetail->clientpktnum++;
	}
	else
	{
		if(pdetail->serverpktnum == 0) /* 当前方向的第一个包, 尝试更新底层隧道的单向地址信息(如MPLS, GTP) */
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

	/* flow_stat是全包无状态记录, 不关心重传、乱序问题 */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->flow_stat->C2S_all_pkt++;
			pdetail_pr->flow_stat->C2S_all_byte += tcplen;
			pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
		}else{
			pdetail_pr->flow_stat->S2C_all_pkt++;
			pdetail_pr->flow_stat->S2C_all_byte += tcplen;
			pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len - raw_pkt->overlay_layer_bytes;
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
	
	/* note: reset会重置计数, 放在clientbytes+=, clientpktnum++代码之后 */
	if(1 == lrustream(pindex_tcp)){
		ret = tcp_reset_stream(pindex_tcp, this_iphdr,this_tcphdr, tcplen,raw_pkt);		
		if(0 == ret){
			return PASS;
		}
		/* 如果在tcp_reset_stream()新建流时, 被设置了bypass标志, 此处直接返回, 不能再调用tcp_processallpkt */
		if(pstream_pr->under_ddos_bypass){
			return PASS;
		}
		ret = tcp_processallpkt(pstream, this_iphdr, this_tcphdr, tcplen, raw_pkt);
		if(DROP == ret){
			return DROP;
		}

		call_tcpall_after_reset = 1;		
	}

	pstream->addr.pkttype = PKT_TYPE_NORMAL;//add by lqy 20151222, init pkttype
	pdetail_pr->tcpoverlen=0;//add by lqy 20150325
	
	if(pdetail_pr->takeoverflag==TCP_TAKEOVER_STATE_FLAG_ON)
	{
		//ret=stream_process_tcp_takeover(pstream,raw_pkt);
		ret=stream_process_tcp_takeover(pstream,this_iphdr); /* 20160928 lijia modify, iphdr */		
	}
	else
	{
		if(pstream->stream_state==TCP_DATA_STATE)
		{
			//ret=tcp_deal_data_stream(pindex_tcp,rawippkt,iplen,this_tcphdr,tcplen);			
			ret=tcp_deal_data_stream(pindex_tcp,this_iphdr, raw_pkt,this_tcphdr,tcplen);	
		}	
		else if(pstream->stream_state==TCP_SYN_STATE)
		{
			ret=tcp_deal_syn_stream(pindex_tcp,raw_pkt,this_iphdr, this_tcphdr,tcplen);
			// 不正常的报文，不继续进行后继处理
			if(DROP==ret)
			{
				   //return PASS;//不进行后继处理，但是必须返回PASS否则串联逻辑不对
				   ret = PASS;
				   goto fun_exit;
			}
			if((tcplen>0) && (checkcreatlinkseq(&(pindex_tcp->stream),htonl(this_tcphdr->th_seq))==1))
			{
				tcp_change_stream_todata(pindex_tcp,this_tcphdr,tcplen);
				 //ret=tcp_deal_data_stream(pindex_tcp,rawippkt,iplen,this_tcphdr,tcplen);
				 ret=tcp_deal_data_stream(pindex_tcp,this_iphdr,raw_pkt,this_tcphdr,tcplen);
			}
			//add by lqy 20150215 新建链接刚开始的乱序报文
			else
			{
				pindex_tcp->stream.stream_public.addr.pkttype=PKT_TYPE_TCPUNORDER;
			}			
		}
		else if(pstream->stream_state==TCP_NOUSE_STATE)
		{
			ret=tcp_deal_nouse_stream(pindex_tcp,this_iphdr,raw_pkt,this_tcphdr,tcplen);
		}
	}
	
	/* 如果在tcp_deal_nouse_stream(),tcp_deal_data_stream()函数中, 调用过tcp_reset_stream()重置当前流时, 
	   凑巧被设置了bypass标志, 此处要直接返回, 不能再调用stream_process_tcp_allpkt()  
	 */
	if(pstream_pr->under_ddos_bypass){
		return ret;
	}	
	
	//adjust by lqy 20150107 为了防止SYN重建链接时SYN在第一个链接中
	if((0 == call_tcpall_after_reset) && pindex_tcp && (pstream->pktstate!=OP_STATE_CLOSE))
	{
		//全包接口拿到的数据指向当前包的原始数据
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

fun_exit:    

	if(DROP == ret){
		sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream: %s, tcphdr->checksum:0x%x, curdir:%d, return DROP.", 
						printaddr(&pstream->addr, pstream->threadnum), ntohs(this_tcphdr->th_sum), pstream->curdir);
	}

	return ret;
}

/*
	lijia 2015-01-12 add this_iphdr, 
	如果是IP分片重组的包, 必须显式的传递IP包头, 否则只传tcp_hdr和raw_hdr, 无法获取重组后的IP包头.
*/
static int dealtcppkt(struct streamindex *pfindex, const void *this_iphdr, struct mesa_tcp_hdr *this_tcphdr, 
	int thread_num,unsigned char routedir, int tcpdatalen, const raw_pkt_t *raw_packet, int offset_to_raw_pkt_hdr)
{
#if 0
	struct layer_addr_tcp tcp_addr;
#else
	//struct layer_addr *tcp_stream_addr;
#endif

	/* IPPORT-union版本, IP和TCP层使用同一个index结构, 即直接通过IP层传递的pfindex */
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
	set_transport_addr(pstream, !(this_tcphdr->th_flags & TH_SYN), this_tcphdr->th_sport, this_tcphdr->th_dport);

	pstream->addr.pkttype = PKT_TYPE_NORMAL;//add by lqy 20151222, init pkttype
	
	pstream_pr->addr_use_as_hash = 1; /* 四元组信息存于IP层 */
//	ptmp->stream.p_layer_header = this_tcphdr;
	//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_tcphdr - (char *)raw_packet->raw_pkt_data;
	pstream_pr->offset_to_ip_hdr = (char *)this_tcphdr - (char *)this_iphdr;
	pstream_pr->raw_pkt = raw_packet; /* 2014-12-30 lijia add */
	
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;

	local_sys_stat->count_per_layer[ADDR_TYPE_TCP][pstream_pr->layer_index]++; /* tcp和ip算作一层 */
	local_sys_stat->length_per_layer[ADDR_TYPE_TCP][pstream_pr->layer_index] += tcpdatalen + this_tcphdr->th_off*4; /* tcp和ip算作一层 */
	
	//return deal_tcp_stream(ptmp,this_tcphdr,tcpdatalen,raw_packet,raw_len);
	return deal_tcp_stream(pfindex,this_iphdr, this_tcphdr,tcpdatalen, raw_packet, offset_to_raw_pkt_hdr);
}

/* lijia comment: this_iphdr可能是真实原始包, 也可能是malloc的IP重组包, 靠addr.pkttype区分 */
int dealipv4tcppkt(struct streamindex *pfindex, const struct mesa_ip4_hdr *this_iphdr,int thread_num,
					unsigned char routedir, const raw_pkt_t *raw_pkt,  int offset_to_raw_pkt_hdr)
{
	int iphdr_len, datalen, iplen;

	iphdr_len = this_iphdr->ip_hl << 2;
	struct mesa_tcp_hdr *this_tcphdr = (struct mesa_tcp_hdr *)((char *)this_iphdr + iphdr_len);

	iplen = ntohs (this_iphdr->ip_len);
	if(unlikely(iplen - iphdr_len < (int)sizeof (struct mesa_tcp_hdr))){
		return PASS;
	}
	
	datalen = iplen - iphdr_len - (this_tcphdr->th_off<<2);
	if(unlikely(datalen < 0)){
		return PASS;
	}

	/* lijia 2016-06-15 add, 性能优化, 丢弃纯ACK包 */
#if HIGH_PERF /* 高性能模式下自动丢弃ACK */
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

	//return dealtcppkt(pfstream, this_tcphdr, thread_num, routedir, datalen, iplen, raw_pkt);
	return dealtcppkt(pfindex, (const void *)this_iphdr, this_tcphdr, thread_num, routedir, datalen, raw_pkt, offset_to_raw_pkt_hdr);
}

/* 2012-06-09 LiJia add */
int dealipv6tcppkt(struct streamindex *pfindex, const struct mesa_ip6_hdr *this_iphdr,
	char *data, int datalen, int thread_num,unsigned char routedir, const raw_pkt_t *raw_pkt, int offset_to_raw_pkt_hdr)
{
	struct mesa_tcp_hdr *this_tcphdr = (struct mesa_tcp_hdr *)data;

	datalen -= (this_tcphdr->th_off << 2);
	if(unlikely(datalen < 0)){
		return PASS;
	}

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


/*
	原始配置来自: etc/well_known_port.conf
	return value:
		0      : not found in well known port array;
		1: in well known port array;
*/
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


/*
	2021-06-08之前, 对于udp和tcp无SYN包的情况, 都是按"大端口是客户端"规则确定流的方向,
	2021-06-08之后, 优先判断公知端口, 比如80, 8088, 53等端口的, 认为是服务端.

	return value:
		0      : not found in well known port array;
		DIR_C2S: in well known port array, and it's dir;
		DIR_S2C: in well known port array, and it's dir;	
*/
static int adjust_stream_dir_by_well_known_ports(unsigned char stream_type,UINT16 sport_host, UINT16 dport_host)
{
	int ret;

	ret = is_well_known_port(stream_type,dport_host);
	if(ret != 0){
		return DIR_C2S; /* dport命中规则, 即C2S方向 */
	}

	ret = is_well_known_port(stream_type,sport_host);
	if(ret != 0){
		return DIR_S2C; /* sport命中规则, 即S2C方向 */
	}	

	/* 两个端口都没有命中well known port, 按之前的判断逻辑, "大端口是客户端"规则 */
	return 0;
}


#if 0 /* 20141014 lijia modify */
int set_stream_addr(struct streaminfo *pfstream, UINT16 sport, UINT16 dport, struct layer_addr *this_addr)
{
	
	if(__ADDR_TYPE_IP_PAIR_V4 == pfstream->addr.addrtype){
		struct layer_addr_ipv4 *ip4_addr = pfstream->addr.ipv4;
		ip4_addr->source = sport;
		ip4_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV4;
		this_addr->addrlen = sizeof(struct layer_addr_ipv4);
	}else if(__ADDR_TYPE_IP_PAIR_V6 == pfstream->addr.addrtype){
		struct layer_addr_ipv6 *ip6_addr = pfstream->addr.ipv6;
		ip6_addr->source = sport;
		ip6_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV6;
		this_addr->addrlen = sizeof(struct layer_addr_ipv6);
	}else{
		assert(0);
	}

	this_addr->paddr = pfstream->addr.paddr;
			
	return 0;
}
#else
int set_transport_addr(struct streaminfo *this_stream, int enable_well_known_port, UINT16 sport, UINT16 dport)
{
	struct streaminfo_private *this_stream_pr = (struct streaminfo_private *)this_stream;
	struct layer_addr *this_addr = &this_stream->addr;
	unsigned char dir_by_well_known_port = 0;
	
	if(__ADDR_TYPE_IP_PAIR_V4 == this_addr->addrtype){
		struct stream_tuple4_v4 *ip4_addr = this_addr->tuple4_v4;
		/* 设置端口, 在IP-PORT-union版本以port顺序做为layer_dir的参照,
		   同时更新layer_dir, 用于计算HASH时, 地址出现顺序 */
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
				this_stream_pr->layer_dir = 1; /* 按端口顺序更新四元组layer_dir */
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
		this_addr->addrtype = ADDR_TYPE_IPV4; /* 兼容papp平台, 传输层的四元组使用'ADDR_TYPE_IPV4表示' */
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
		this_addr->addrtype = ADDR_TYPE_IPV6; /* 兼容papp平台, 传输层的四元组使用'ADDR_TYPE_IPV6表示' */
		this_addr->addrlen = sizeof(struct stream_tuple4_v6);
	}else{
		assert(0);
	}
	
	return 0;
}
#endif




/* 2014-12-30 lijia add, 代理流做为一个虚拟结构, 不做为获取地址的实际结构, 跳过之 */
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

	/* 存储原始包 */
	memcpy(&(uo_packet->raw_pkt),  stack_raw_pkt, sizeof(raw_pkt_t));	
	uo_packet->raw_pkt.raw_pkt_data = sapp_mem_malloc(SAPP_MEM_DYN_TCP_UNORDER,a_tcp->threadnum, stack_raw_pkt->raw_pkt_len);
	memcpy((void *)uo_packet->raw_pkt.raw_pkt_data, stack_raw_pkt->raw_pkt_data, stack_raw_pkt->raw_pkt_len);


	/* 	iphdr分两类情况:
		1)非IP分片包:
			只需存储真正的原始包, 其他的都用指针引用, 只需free一次;
		2)IP重组的包:
			存储真正的原始包(最后一个分片), 和重组后malloc的IP包, 其他使用指针引用;
	*/
#if 0	 
	if(carry_ip_stream->addr.pktipfragtype & PKT_TYPE_IPREBUILD){
#else
	/* 因为IPv4有可能多层嵌套, 比如: MAC->IPv4->UDP->IPv6->IPv4->TCP->APP,
		不能仅判断当前流的IPv4层是否是分片, 最底层的IPv4包也可能来源于IP分片重组的包.
		所以, 使用原始包指针和当前IP头指针的绝对值偏移来判断, 
		正常的包, 当前包头和原始包头的地址偏移量肯定在MTU范围内,
		如果超过了MTU, 则当前IP包肯定是新malloc的, 即分片重组的包.
	*/
	if(abs((char *)this_iphdr - (char *)stack_raw_pkt->raw_pkt_data) > MTU_MAX){
#endif
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

	/* IP分片链表指针移动到pakiet结构中, 将全局的G_IP_FRAG_LIST[tid]指针置空, 避免被ip_entry层释放 */
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

/* 2015-01-13 lijia add, 
	因为kill_xxx系列函数使用stream_pr结构中的raw_pkt指针,
	如果是乱序包触发了某规则, 调用kill_xxx系列函数,
	此时的
*/
static inline void update_stream_list_raw_pkt_pointer(struct streaminfo_private *a_tcp_pr, const raw_pkt_t *raw_pkt)
{
	a_tcp_pr->raw_pkt = raw_pkt;

	/* TODO 3: 是否需要递归的将a_tcp->pfather->raw_pkt也全部更新?! */

	return;
}

static void tcp_flow_stat_free(int thread_seq, void *project_req_value)
{
	sapp_mem_free(SAPP_MEM_DYN_TCP_FLOW_STAT,thread_seq, project_req_value);
	return;
}


/* 2015-12-25 lijia add, for TCP/UDP流量统计 */
int tcp_flow_stat_init(void)
{
	int project_req_id;
	
	project_req_id = project_producer_register(PROJECT_REQ_TCP_FLOW, "struct", tcp_flow_stat_free);
	if(project_req_id >= 0){
		G_TCP_FLOW_STAT_PROJECT_ID = project_req_id;
	}else{
		/* 配置文件没有'tcp_flow_stat'项, 关闭此功能 */
		G_TCP_FLOW_STAT_PROJECT_ID = -1;
	}

	project_req_id = project_producer_register(PROJECT_REQ_TCP_DEDUCE_FLOW, "struct", tcp_flow_stat_free);
	if(project_req_id >= 0){
		G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = project_req_id;
	}else{
		/* 配置文件没有'tcp_flow_stat'项, 关闭此功能 */
		G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = -1;
	}
	
	return 0;
}

#ifdef __cplusplus
}
#endif

