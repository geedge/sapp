/*
20120603 : 1)�޸Ľ������ӵĲ��� ��datalen>0�İ�ֱ�ӽ�������
		   2)Ӧ�ò㲻��Ҫ�����ӣ�ת��nouse״̬��������ֱ���ͷ�

20140322 : 1)ԭ�����ֻ�е�����data״̬�󣬲ŷ���pdetail�Ŀռ䣻�����޸�Ϊ
			��һ�����ͷ���pdetail�Ŀռ䣬������data��ŷ���half�Ŀռ�
		    2)ԭ��������ص�һЩ������ȫ������pdetail
		    3) �����Ĺ������������ĵ�ַ��hash���ö���ַ���бȽ�
		    
20140329 1)�ָ���tcpdetail��¼���ζ����ֽ���pdetail->lostlen
		 2)������tcpallpktģʽ�����ڲ������������飬����ȷ��fin��rst�ȵĵ���shunx
			˳����˲���������close״̬��ֻ�ܵ���̭��
	        3)�������м�¼ÿ��İ����ֽ�����λ�õ�����Ϊʵ�ʵ����˳��
			��¼����¼�а����˲������صİ���Ŀ����ͳϵͳ�м�¼�˴����صİ���

20141210 1)ȫ�����streaminfo����ؽṹ�壬ʹ�÷���ṹ��Ĳ�ͬ����
20141213 1)����tcp_add_new_stream_bydata���水tcplen=0�İ������ӣ�����nouse����
			nouse���������������һ����data��������opstate=close�����
			�ڶ����Ǵ�һ�����ͽ�����nouse����ʱopsate=pending,
		 2) �������ڶ������nouse���������ݰ�ʱ���ָ���data������

20141217 1)����c2s�������ĵڶ�������ack���Ƿ������ڣ�һֱ�������飬
	   Ŀǰ�汾�в����ϸ���


20150114 ���ں����ĵ���˳�����ȵ���tcpall�ӿڣ������ȵ���tcp�ӿڽ����˷�������
	 ԭ���ȵ���tcpall�������tcp�����ֶ�syn�ش��޷��ж��Ƿ���Ч���Ƿ�����
	 ���Ϊ�ȵ���tcp���ٵ���tcpall������ ����ĳˮ䰹��̣�tcp�ӿڣ�����tcpall�ı�ǩ
	 ���ڵ���Ϊ���½���������data�����ӣ������ȵ���all���ڵ���tcp��	   
20150126 ������
	����tcp_free_stream,tcp_reset_stream�Ĳ�������Ϊ�ȵ���tcp���ٵ���tcpall
20150210 lqy
	����syn+ack����syn�����ݵ���������±�������seqʱҪ�ж��Ƿ��syn
	 nouse�����ĵ��������
	���Ӹ��� ,syn״̬��Ҫ����tcp��״̬
*/
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif
int set_transport_addr(struct streaminfo *pfstream, UINT16 sport, UINT16 dport);
extern void free_heap_stream_info(struct streaminfo *heap_stream, int layer);
struct streaminfo_private *copy_stream_info_to_heap(const struct streaminfo_private *stack_stream_pr, int reverse);		
int set_stream_addr_transport(struct streaminfo_private *pfstream_pr, UINT16 sport, UINT16 dport);
struct streaminfo *skip_proxy_phony_stream(struct streaminfo *a_tcp);
static struct buf_unorder *tcp_save_unorder_pkt(struct streaminfo *a_tcp,const void *this_iphdr, 
	const raw_pkt_t *stack_raw_pkt,struct mesa_tcp_hdr *this_tcphdr, 
	unsigned char *tcpdata, int tcpdatalen);
static void tcp_free_unorder_pkt(int threadnum, struct buf_unorder *uo_packet);	
static int get_ip_pkt_tot_len(struct streaminfo *ipinfo, const void *this_iphdr);
static inline void update_stream_list_raw_pkt_pointer(struct streaminfo_private *a_tcp_pr, const raw_pkt_t *raw_pkt);
void addr_reverse_memcpy(void *daddr, const void *saddr, int addrtype, int addrlen);
int copy_ipport_union_addr(struct streaminfo *pstream_heap, struct streaminfo *pstream_stack, int reverse);
void iterate_stream_list(const struct streaminfo *stream);
int del_stream_by_time(struct stream_list *plist, const struct streamindex *current_drive_index);

//int g_kill_tcp_remedy_sw = 0; /* 2016-06-21 lijia add, �Ƿ����FD���� */

int G_TCP_FLOW_STAT_PROJECT_ID = -1; /* 2016-07-14 lijia copy from sapp */
int G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = -1; /* ������, ����ACK����ƶϳ��ĶԶ����۽��յ����ݳ��� */

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
	//��һ�γ������ݣ���Ϊ������
	if(curseq==0) return 1;
	//��γ���syn����һ�����ݰ����Ϊ׼
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
	int parsed_opt; /* ��ȷ������OPT��׼λ */

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
			case TCP_OPT_EOL: /* ��ʵ������, ����¼��ѡ�������� */
				goto done;
			break;

			case TCP_OPT_NOP: /* ��ʵ������, ����¼��ѡ�������� */
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
				out_raw_result->char_value = 1; /* SACKʵ��û��ֵ, �˴���ֵ��Ϊ�˱����ⲿ���ʹ�� */
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

			/* ����ʶ���ݲ�������ѡ��, ���� */
			case TCP_OPT_SACK_EDGE:
			case TCP_OPT_MD5:
			case TCP_OPT_MULTI_PATH_TCP:
			case TCP_OPT_RIVER_PROBE:
			{
				/*  */
				int this_opt_len;
				
				if(opt_len <= 1){ /* ��ǰѡ���Ϊ0, ��ʣ��ѡ���ֻ��һ���ֽ�, ��ѡ�����ͷ�0��1, �����! */
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
				
				if(opt_len <= 1){ /* ��ǰѡ���Ϊ0, ��ʣ��ѡ���ֻ��һ���ֽ�, ��ѡ�����ͷ�0��1, �����! */
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
	//printf("tcp-opt error, pkt number is:%ld\n", g_SysInputInfo[0][0]);
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
	int parsed_opt; /* ��ȷ������OPT��׼λ */

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
			case TCP_OPT_EOL: /* ��ʵ������, ����¼��ѡ�������� */
				goto done;
			break;

			case TCP_OPT_NOP: /* ��ʵ������, ����¼��ѡ�������� */
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
				out_raw_result->char_value = 1; /* SACKʵ��û��ֵ, �˴���ֵ��Ϊ�˱����ⲿ���ʹ�� */
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

			/* ����ʶ���ݲ�������ѡ��, ���� */
			case TCP_OPT_SACK_EDGE:
			case TCP_OPT_MD5:
			case TCP_OPT_RIVER_PROBE:
			{
				/*  */
				int this_opt_len;
				
				if(opt_len <= 1){ /* ��ǰѡ���Ϊ0, ��ʣ��ѡ���ֻ��һ���ֽ�, ��ѡ�����ͷ�0��1, �����! */
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
				
				if(opt_len <= 1){ /* ��ǰѡ���Ϊ0, ��ʣ��ѡ���ֻ��һ���ֽ�, ��ѡ�����ͷ�0��1, �����! */
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
	//printf("tcp-opt error, pkt number is:%ld\n", g_SysInputInfo[0][0]);
	return -1;
}

static void tcp_store_syn_state_opts(struct streaminfo_private *pstream_pr, char dir, 
									struct tcp_option *opts, int optnum)
{
	if(DIR_C2S == dir){
		if(NULL == pstream_pr->syn_opt_array){
			pstream_pr->syn_opt_array = (struct tcp_option *)dictator_malloc(pstream_pr->stream_public.threadnum, sizeof(struct tcp_option) * optnum);
			memcpy(pstream_pr->syn_opt_array, opts, sizeof(struct tcp_option) * optnum);
			pstream_pr->syn_opt_num = optnum;
		}
	}else{
		if(NULL == pstream_pr->synack_opt_array){
			pstream_pr->synack_opt_array = (struct tcp_option *)dictator_malloc(pstream_pr->stream_public.threadnum, sizeof(struct tcp_option) * optnum);
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


/* LiJia comment: ������½�����, ��resetflag=0, ����pindexָ��ջ����ڴ�;
				�������Ԫ������, ����pindexָ�������ڴ�;
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
	int need_reverse = 0; /* copy��ַʱ, �Ƿ���Ҫ��src, dst�ߵ� */

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
		//ֻ�е����ν���ʱֱ�ӷ���
		if(resetflag==0)
			return NULL;
	}
	if(likely(0 == resetflag)){
		/* �˺���copy������pindex�ṹ, ��addr��ַ��������һ���ڴ�, ���Բ�û��copy, ʵ�ʻ�����pindexָ����ڴ���� */
		pindex_tcp=malloc_and_copy_streamindex(threadnum, pindex);
		
		//memcpy(pindex_tcp,pindex,sizeof(struct streamindex));
		pstream_pr = &pindex_tcp->stream;
		pstream = &pstream_pr->stream_public;		

		/* 2014-11-13 lijia modify */
		if(DIR_C2S == createdir){ /* ��ǰ��ַ��TCP�߼������Ϸ���C->S���䷽�� */
			if(1 == pstream_pr->layer_dir){
				pstream_pr->stream_dir = 1; /* �ڵ�ַ�������, ��"���ַ�ǿͻ���"�����෴ */
				//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
			}else{
				pstream_pr->stream_dir = 0;
				//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1;
			}
			need_reverse = 0;
		}else{
			need_reverse = 1; /* ���뽫��ַ����ߵ�, �����ȡ��ַ�ṹʱ, src�̶�ָ���߼��ϵ�Դ��ַ */
			if(1 == pstream_pr->layer_dir){
				/* ��Ϊ��copy_stream_info_to_heap()�л�����ַ�ߵ�, ���Դ˴��ͺ�"���ַ�ǿͻ���"������ͬ�� */
				pstream_pr->stream_dir = 0; 
				//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1;
			}else{
				pstream_pr->stream_dir = 1;
				//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
			}
		}

#if USE_RBTREE_INSTEAD_LIST
		/* note:
			��Ϊ����rbtreeʱ��Ҫ���������������Ƚ�, ����ȷ������left����right��֧,
			���ڱ�����˵, layer_dir����û��������, ��Ҫ���ں��������Ƚϵ�ַ��С, 
			���Խ�layer_dir = stream_dir;
		*/
		pstream_pr->layer_dir = pstream_pr->stream_dir;
#endif

		copy_ipport_union_addr(pstream, &pindex->stream.stream_public, need_reverse);

		hash_add_stream(pindex_tcp);

		pstream->pfather = (struct streaminfo *)copy_stream_info_to_heap((struct streaminfo_private *)pindex->stream.stream_public.pfather, need_reverse);	   

#if SAPP_INSECTICIDE
		iterate_stream_list(pstream);
#endif
		/* 2016-07-25 lijia add, ��¼��ǰ����ײ���������, ÿ����ֻ�ڴ���ʱ��һ�μ��� */
		get_stream_carry_tunnel_type(pstream, NULL, &pstream_pr->stream_low_layer_tunnel_type);
		
#if 0
		/* TCP��洢����ָ��, ��ʵ��ַ���ݴ洢��IP��, ����� */
		//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream.addr);
		//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);

		if(0 == need_reverse){
			set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
		}else{
			set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
		}
#endif	
		pdetail_pr=(struct tcpdetail_private *)dictator_malloc(threadnum,sizeof(struct tcpdetail_private));
		pdetail=&pdetail_pr->tcpdetail_public;
		pindex_tcp->stream.stream_public.pdetail=(void *)pdetail_pr;
		memset(pdetail_pr,0,sizeof(struct tcpdetail_private));   
		pdetail->createtime=g_CurrentTime;
		pstream_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;
		//adjust by lqy 20140515 ֻ���½�ʱ����
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
		�����������, ��ò�ʹ��ԭ����streamindex�ṹ, free��������һ���µ�,
		����ʹstreamindex��ַ��ԭ����һ��, ��Ҫ����DEBUG.
	 */
	   pindex_tcp=pindex;
		pstream_pr = &pindex_tcp->stream;
		pstream = &pstream_pr->stream_public;	   
	   pdetail_pr = (struct tcpdetail_private *)pstream->pdetail;
	   pdetail=(struct tcpdetail *)pdetail_pr;
		//add by lqy 20150107, ���ü���
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
		/* ���Ӹ���, ��������һ���µ�streamid */
		pindex_tcp->stream.global_stream_id = get_global_stream_id(threadnum);
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
	//δ����ȫ���ӿ�ģʽ�£�ֱ�ӹر�, add by lqy 20141213
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
		//��ʱ������ʼ��seq
		pdetail_pr->iclientseq =ntohl (this_tcphdr->th_seq) + 1;
		pdetail_pr->iserverseq=ntohl (this_tcphdr->th_ack);
		//pdetail->clientpkt++; //adjust by lqy 20140515 ֻ���½�ʱ����
		pdetail_pr->S2C_first_ack_seq = pdetail_pr->iserverseq;
		pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir ^ 1;
	}
	else if(createdir==DIR_C2S)
	{
		pdetail_pr->iclientseq = 0; /* 2017-12-06 lijia add, ��ʱS2C�����ISN��δ��ȡ�� */
		pdetail_pr->iserverseq=ntohl (this_tcphdr->th_seq)+1;
		//pdetail->serverpkt++; //adjust by lqy 20140515 ֻ���½�ʱ����
		pdetail_pr->C2S_first_ack_seq = ntohl (this_tcphdr->th_ack);
		pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir;
	}
	pdetail->lastmtime=g_CurrentTime;	
	pdetail_pr->link_state=STREAM_LINK_JUST_EST;	
	pstream->stream_state=TCP_SYN_STATE;
	streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[TCP_SYN_STATE]));

	/* LiJia add, ĳЩ��Ŀ����Ӧ�ó�ʼ��, ���ǩ��ԭʼIP��Ƭ�б��� */
	pstream_pr->pproject = project_requirement_create(pstream->threadnum);

	/* 2015-12-28 lijia add */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->flow_stat = (struct tcp_flow_stat *)dictator_malloc(pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);

		if(0 == resetflag){
			if(DIR_C2S == pstream->curdir){
				pdetail_pr->flow_stat->C2S_all_pkt++;
				pdetail_pr->flow_stat->C2S_all_byte += datalen;
				pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len;
			}else{
				pdetail_pr->flow_stat->S2C_all_pkt++;
				pdetail_pr->flow_stat->S2C_all_byte += datalen;
				pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len;
			}
		}else{
			if(DIR_C2S == pstream->curdir){
				pdetail_pr->flow_stat->C2S_all_pkt = 1;
				pdetail_pr->flow_stat->C2S_all_byte = datalen;
				pdetail_pr->flow_stat->C2S_all_byte_raw = raw_pkt->raw_pkt_len;
			}else{
				pdetail_pr->flow_stat->S2C_all_pkt = 1;
				pdetail_pr->flow_stat->S2C_all_byte = datalen;
				pdetail_pr->flow_stat->S2C_all_byte_raw = raw_pkt->raw_pkt_len;
			}
		}
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->deduce_flow_stat = (struct tcp_flow_stat *)dictator_malloc(pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->deduce_flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID, pdetail_pr->deduce_flow_stat);

		if(DIR_S2C == createdir){
			pdetail_pr->S2C_first_ack_seq = ntohl(this_tcphdr->th_ack);
		}else{
			; /* SYN��ľ��ACK, ���� */
		}
	}

	
	tcp_parse_opts(pstream_pr, createdir, (const struct tcphdr *)this_tcphdr); /* 2016-07-07 lijia add, for janus hijack */


#if SAPP_INSECTICIDE
	iterate_stream_list(pstream);
#endif

	save_polling_inject_context(pstream_pr, raw_pkt);

	pdetail_pr->auto_remedy_flag = sapp_global_val->config.stream.tcp.inject.auto_remedy;

	return pindex_tcp;
}

/*
	1)ԭ�����Ϊû��syn������£�ֱ�ӿ���һ�����ݰ���������
	2) Ϊ�˼���ȫ���ӿڣ�����û�����ݵİ�Ҳ���������ӽ���NOUSE ״̬

	2015-06-10 lijia add "resetflag", ��������ʱ��̭�½�����.
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
 		//copy_fstream_info_to_heap(&(pindex_tcp->stream), 0);

 		copy_ipport_union_addr(pstream, &pindex->stream.stream_public, pstream_pr->layer_dir ^1);
 		
 		pstream->pfather = (struct streaminfo *)copy_stream_info_to_heap((struct streaminfo_private *)(pindex->stream.stream_public.pfather),  pstream_pr->layer_dir ^1);

#if SAPP_INSECTICIDE
		iterate_stream_list(pstream);
#endif

 		/* 2016-07-25 lijia add, ��¼��ǰ����ײ���������, ÿ����ֻ�ڴ���ʱ��һ�μ��� */
		get_stream_carry_tunnel_type(pstream, NULL, &pstream_pr->stream_low_layer_tunnel_type);
		
		pstream->dir=createdir;
		pstream->curdir=createdir;
		pdetail_pr=(struct tcpdetail_private *)dictator_malloc(threadnum,sizeof(struct tcpdetail_private));
		pdetail=&pdetail_pr->tcpdetail_public;
		memset(pdetail_pr,0,sizeof(struct tcpdetail_private));

#if USE_RBTREE_INSTEAD_LIST
		if(1 == pstream_pr->layer_dir){
			pstream_pr->stream_dir  = 1; /* ��Ϊ�ǰ�DATA������, ����stream_dir�϶���Ĭ�Ϲ�����ͬ */
			//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
			//set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
		}else{
			pstream_pr->stream_dir  = 1; /* ��Ϊ�ǰ�DATA������, ����stream_dir�϶���Ĭ�Ϲ�����ͬ */
			//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1; /* IP�㴴�����ķ����뵱ǰ�����䷽���෴ */
			//set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
		}

		/* note:
			��Ϊ����rbtreeʱ��Ҫ���������������Ƚ�, ����ȷ������left����right��֧,
			���ڱ�����˵, layer_dir����û��������, ��Ҫ���ں��������Ƚϵ�ַ��С, 
			��data��������, layer_dir = 1;
		*/
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
		}
		else if(createdir==DIR_C2S)
		{
			pdetail->clientpktnum=0;
			pdetail->clientbytes=0;
			pdetail->serverpktnum=1;
			pdetail->serverbytes=datalen;
		}
		
		pstream_pr->stream_killed_flag = 0;
		/* ���Ӹ���, ��������һ���µ�streamid */
		pindex_tcp->stream.global_stream_id = get_global_stream_id(threadnum);		
	}

	pstream->dir=createdir;
	pstream->curdir=createdir;
	//pindex_tcp->stream.stream_dir=pindex_tcp->stream.layer_dir;

	//�����ݱ���ֱ�ӽ���data״̬, by lqy 20141213
	//if(datalen>0)
	//�����ĵ��ǲ���������־�ı���adjust by lqy 20150215
	if((datalen>0) && (!(this_tcphdr->th_flags & TH_FIN)) && (!(this_tcphdr->th_flags & TH_RST)))	
	{
		pstream->stream_state=TCP_DATA_STATE;
	}
	else
	{
		pstream->stream_state=TCP_NOUSE_STATE;	
	}
	
	/* TCP��洢����ָ��, ��ʵ��ַ���ݴ洢��IP��, ����� */
	//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream.addr);
	//set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);

 #if 0	
	set_stream_addr(pindex_tcp->stream.pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, &pindex_tcp->stream);
#else  /* 2014-12-16 lijia modify */
	if(1 == pstream_pr->layer_dir){
		pstream_pr->stream_dir  = 1; /* ��Ϊ�ǰ�DATA������, ����stream_dir�϶���Ĭ�Ϲ�����ͬ */
		//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir;
		//set_stream_addr(pstream->pfather, this_tcphdr->th_sport, this_tcphdr->th_dport, pstream);
	}else{
		pstream_pr->stream_dir  = 1; /* ��Ϊ�ǰ�DATA������, ����stream_dir�϶���Ĭ�Ϲ�����ͬ */
		//((struct streaminfo_private *)pstream->pfather)->stream_dir = ((struct streaminfo_private *)pstream->pfather)->layer_dir ^ 1; /* IP�㴴�����ķ����뵱ǰ�����䷽���෴ */
		//set_stream_addr(pstream->pfather, this_tcphdr->th_dport, this_tcphdr->th_sport, pstream);
	}
#endif

	streamaddlist(pindex_tcp,&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]));

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
	pstream_pr->stream_create_timestamp_ms=sapp_global_val->individual_volatile->current_time_ms;
	pdetail->lastmtime=g_CurrentTime;
	pdetail_pr->link_state=STREAM_LINK_DATA;	
	//if(datalen>0)
	//�����ĵ��ǲ���������־�ı���adjust by lqy 20150325
	if((datalen>0) && (!(this_tcphdr->th_flags & TH_FIN)) && (!(this_tcphdr->th_flags & TH_RST)))	
	{
		if(pstream->dir==DIR_C2S)
		{
			pdetail_pr->pserver=(struct half_tcpstream *)dictator_malloc(threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
			//������
			pdetail_pr->pserver->first_data_seq=(ntohl (this_tcphdr->th_seq) );
			/* 2014-07-31 LiJia add, for set one stream unorder number */
			pdetail_pr->pserver->maxunorder = tcp_default_unorder;
		}
		 if(pstream->dir == DIR_S2C)
		{
			pdetail_pr->pclient=(struct half_tcpstream *)dictator_malloc(threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
			//������
			pdetail_pr->pclient->first_data_seq=(ntohl (this_tcphdr->th_seq) );
			/* 2014-07-31 LiJia add, for set one stream unorder number */
			pdetail_pr->pclient->maxunorder = tcp_default_unorder;
		}
	}
	else //�����ݵ������¼��ʱseqֵ
	{
		if(createdir==DIR_S2C)
		{
			//��ʱ������ʼ��seq
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

	/* 2014-03-26 LiJia add, ĳЩ��Ŀ����Ӧ�ó�ʼ��, ���ǩ��ԭʼIP��Ƭ�б��� */
	pstream_pr->pproject = project_requirement_create(threadnum);

	/* 2016-07-14 lijia add */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->flow_stat = (struct tcp_flow_stat *)dictator_malloc(pstream->threadnum, sizeof(struct tcp_flow_stat));
		memset(pdetail_pr->flow_stat, 0, sizeof(struct tcp_flow_stat));	
		project_req_add_struct(pstream, G_TCP_FLOW_STAT_PROJECT_ID, pdetail_pr->flow_stat);

		if(resetflag != 0){
			if(pstream->curdir == DIR_C2S){
				pdetail_pr->flow_stat->C2S_all_pkt = 1;
				pdetail_pr->flow_stat->C2S_all_byte = datalen;
				pdetail_pr->flow_stat->C2S_all_byte_raw = raw_pkt->raw_pkt_len;
			}else{
				pdetail_pr->flow_stat->S2C_all_pkt = 1;
				pdetail_pr->flow_stat->S2C_all_byte = datalen;	
				pdetail_pr->flow_stat->S2C_all_byte_raw = raw_pkt->raw_pkt_len;
			}
		}
		/* NOTE, tcp_data������stream_process_tcp()���ۼ� */
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		pdetail_pr->deduce_flow_stat = (struct tcp_flow_stat *)dictator_malloc(pstream->threadnum, sizeof(struct tcp_flow_stat));
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

	save_polling_inject_context(pstream_pr, raw_pkt);

	pdetail_pr->auto_remedy_flag = sapp_global_val->config.stream.tcp.inject.auto_remedy;

	if(createdir==DIR_C2S){
		pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir;
	}else{
		pstream_pr->stream_c2s_route_dir = raw_pkt->route_dir ^ 1;
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
			pdetail_pr->pserver=(struct half_tcpstream *)dictator_malloc(threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pserver,0,sizeof(struct half_tcpstream));
			//������
			pdetail_pr->pserver->first_data_seq=pdetail_pr->iserverseq;
			/* pdetail_pr->iserverseq=0; */  /* 2016-04-27 lijia modify, ���ڻ�ȡ��ǰ����ISN */
			
			/* 2014-10-20 LiJia add, for set one stream unorder number */
			pdetail_pr->pserver->maxunorder = tcp_default_unorder;
		}
	}
	 if(pstream->dir & DIR_S2C)
	{
		if(NULL == pdetail_pr->pclient){
			pdetail_pr->pclient=(struct half_tcpstream *)dictator_malloc(threadnum,sizeof(struct half_tcpstream));
			memset(pdetail_pr->pclient,0,sizeof(struct half_tcpstream));
			//������
			pdetail_pr->pclient->first_data_seq=pdetail_pr->iclientseq;
			/* pdetail_pr->iclientseq=0; */ /* 2016-04-27 lijia modify, ���ڻ�ȡ��ǰ����ISN */
			
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
	dictator_free(threadnum,phalf);
	//phalf = NULL;
}

/* ������֤pindex�Ƿ���plist�� */
static int inline stream_in_timeout_list(const struct streamindex *pindex, const struct stream_list *plist)
{
	if(plist->cnt <= 1){
		/* ֻ��һ��Ԫ��ʱ, head==tail==pindex */
		if(plist->head == pindex){
			return 1;
		}else{
			return 0;
		}
	}else{
		/* ���Ԫ��ʱ, next��prev�ض���һ����ΪNULL */
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
	   �����tcp_reset_stream()����ջ��, ������tcp_change_stream_tonouse, 
	   pindex�Ѿ����Ƴ���ǰ����list, �����ټ���ִ��streamleavlist��streamaddlist��.
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
	   ��FIN������������NOUSE״̬,
	   deal_tcp_stream()ÿ�ζ���TCP_SYN_STATE��TCP_DATA_STATE״̬,
	   �޷���TCP_NOUSE_STATE״̬�µ�����̭��ȥ,
	   ���Դ˴���ɨ��һ��TCP_NOUSE_STATE�ĳ�ʱ��.
	 */
	del_stream_by_time(plist, pindex);
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
	
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]);

	/* TODO 1,
		free��ƽ̨��time, list_lruԭ��, ��ʱ����������free,
		����ǲ������CLOSEME, ��ֻ�ͷ����pdetail�ڴ�, ���Խ�tcp���ṹ����, Ϊ��FD���ȹ���.

		���Ϊ��������:
		tcp_lite_free(); //ֻfree data, ���������ṹ

		tcp_struct_free(); //free Ӧ�ò�����
		
		tcp_thorough_free(); // del_stream_by_time(), streamaddlist()ʱ������������Ⱥ���Ҫ����, ������free
							// ����tcp_light_free(); tcp_struct_free();��������

		TODO 1:
			����ڵ���tcp_deal_unorder()��, �������������kill_tcp, Ӧ���ж�stream_killed_flag���, 
			���stream_killed_flag=1, ������İ����ٴ���, ֱ��tcp_free_half()�ͷ�.
	*/

	/* 2014-07-24 lijia add, ������ǰ��������� */
	saved_curdir = pstream->curdir; /* 2015-11-16 LiJia add, ���浱ǰ������, �����������Ҫ�ָ���ǰֵ */
	if(pclient && (pclient->unorderlist != NULL)){
		pstream->curdir = DIR_S2C; /* ��ʱ�޸� */
		tcp_deal_unorder(pindex, pstream, pclient, pserver, !CHECK_ORDER_DATA);		
	}
	if(pserver && (pserver->unorderlist != NULL)){
		pstream->curdir = DIR_C2S; /* ��ʱ�޸� */
		tcp_deal_unorder(pindex, pstream, pserver, pclient, !CHECK_ORDER_DATA);		
	}
	pstream->curdir = saved_curdir;

	pstream_pr->raw_pkt = raw_pkt; /* �������ʱ��̭, ��ֵΪNULL; �����RST������̭, Ϊ��ʵԭʼ�� */
	
	if(pstream->stream_state==TCP_DATA_STATE)
	{
		if(pdetail_pr->apme!=NULL)
		{
			pstream->opstate=OP_STATE_CLOSE;
			//tcp stream �ص�
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

	//�����κ�״̬�ص�ȫ��������������
	if(pdetail_pr->pAllpktpme!=NULL)
	{
			pstream->pktstate=OP_STATE_CLOSE;
			//tcp stream �ص�
#if 0			
			pkt_ret = stream_process_tcp_allpkt(pstream, this_ip_hdr, transport_hdr, raw_pkt,&(pdetail_pr->pAllpktpme),&(pstream->pktstate));  
#else
			/* 2017-12-13 lijia modify, TCPALL��Ϊ�ȵ���, ������tcp_free_stream��, ���ֻ��TCPALL���������CLOSE״̬, ���ٸ�ԭʼ��, ָ��̶�ΪNULL, ������ظ��� */
			pkt_ret = stream_process_tcp_allpkt(pstream, NULL, NULL, NULL, &(pdetail_pr->pAllpktpme),&(pstream->pktstate)); 
#endif
			pdetail_pr->pAllpktpme=NULL;
	}

	/* �����������ٴӽṹ���Ƴ�, ��Ϊ���ò��ʱ, ���ܻ����stream_set_single_stream_timeout(), �������ǰ����LRU�����е�λ�� */
	streamleavlist(pindex, plist);
	hash_del_stream(pindex);
	
	if(pstream->pdetail != NULL)
	{
		dictator_free(threadnum,pstream->pdetail);
		pstream->pdetail=NULL;
	}

	project_requirement_destroy(threadnum, pstream_pr->pproject);
	pstream_pr->pproject = NULL;

	if(pstream_pr->timeout > link_default_nopkt_time){ /* ���Ӷ��г�ʱʱ��, ���ټ��� */
		sapp_global_mthread[threadnum].tcp_stream_special_timeout_num--;
	}
	
	free_heap_stream_info(pstream, 0);

	if(pstream_pr->syn_opt_array){
		dictator_free(threadnum, pstream_pr->syn_opt_array);
		pstream_pr->syn_opt_array = NULL;
	}

	if(pstream_pr->synack_opt_array){
		dictator_free(threadnum, pstream_pr->synack_opt_array);
		pstream_pr->synack_opt_array = NULL;
	}

	free_polling_inject_context(pstream_pr);
	
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
	
	 //add by lqy 20150107 ���˼���
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
			pdetail_pr->flow_stat->S2C_all_byte_raw -= raw_pkt->raw_pkt_len;
		}
	}

	if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->deduce_flow_stat->C2S_all_pkt--;
			pdetail_pr->deduce_flow_stat->C2S_all_byte -= datalen;
		}else{
			pdetail_pr->deduce_flow_stat->S2C_all_pkt--;
			pdetail_pr->deduce_flow_stat->S2C_all_byte -= datalen;
		}
	}
	
	plist=&(G_MESA_GLOBAL_STREAM[threadnum]->tcpList[pstream->stream_state]);

	/* 2014-07-24 lijia add, ������ǰ��������� */
	saved_curdir = pstream->curdir; /* 2015-11-16 LiJia add, ���浱ǰ������, �����������Ҫ�ָ���ǰֵ */
	if(pdetail_pr->pclient && pdetail_pr->pclient->unorderlist != NULL){
		pstream->curdir = DIR_S2C; 
		tcp_deal_unorder(pindex, pstream, pdetail_pr->pclient, pdetail_pr->pserver, !CHECK_ORDER_DATA);		
	}
	if(pdetail_pr->pserver && pdetail_pr->pserver->unorderlist != NULL){
		pstream->curdir = DIR_C2S;
		tcp_deal_unorder(pindex, pstream, pdetail_pr->pserver, pdetail_pr->pclient, !CHECK_ORDER_DATA);		
	}
	/* tcp_deal_unorder()�������ܻ��޸�pstream_pr->raw_pkt, �˴��ָ�raw_pkt */
	pstream_pr->raw_pkt = raw_pkt;
	pstream->curdir = saved_curdir;

	/* 2015-02-04 lijia add, 
	   �Ƚ�������ʱ������Ԫ��������̭, ��ǰ��������Ϊ������ԭʼ��, 
	   ������˵��ò���������MESA_kill_xxx, ������pstream_pr->raw_pkt = NULL.
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
			//tcp stream �ص�
			stream_process_tcp_allpkt(pstream,NULL,NULL,NULL,&(pdetail_pr->pAllpktpme),&(pstream->pktstate));  
			pdetail_pr->pAllpktpme=NULL;
	}

	/* �����������ٴӽṹ���Ƴ�, ��Ϊ���ò��ʱ, ���ܻ����stream_set_single_stream_timeout(), �������ǰ����LRU�����е�λ�� */
	streamleavlist(pindex, plist);
	
	project_requirement_destroy(threadnum, pstream_pr->pproject);
	pstream_pr->pproject = NULL;

	/* �ָ�֮ǰ�洢��raw_pkt */
	pstream_pr->raw_pkt = saved_raw_pkt;

	pstream_pr->syn_opt_num = 0;     /* ���ѡ����� */
	pstream_pr->synack_opt_num = 0; /* ���ѡ����� */
	if(pstream_pr->syn_opt_array){
		dictator_free(threadnum, pstream_pr->syn_opt_array);
		pstream_pr->syn_opt_array = NULL;
	}

	if(pstream_pr->synack_opt_array){
		dictator_free(threadnum, pstream_pr->synack_opt_array);
		pstream_pr->synack_opt_array = NULL;
	}

	free_polling_inject_context(pstream_pr); //2020-06-08 lijia add, for memory leak
	
	if(this_tcphdr->th_flags & TH_SYN){
		tcp_add_new_stream_bysyn(pindex,this_iphdr,this_tcphdr,datalen,REUSE_OLD_LINK,raw_pkt);
		ret = 1;
	}else{
		if(TCP_CTEAT_LINK_BYDATA & tcp_creatlink_model){
			tcp_add_new_stream_bydata(pindex,this_tcphdr,datalen,REUSE_OLD_LINK, raw_pkt);
			ret = 1;
		}else{
			/* 20190506 lijia add, reset֮�������������, ֱ��free�� */
			hash_del_stream(pindex);
			if(pstream->pdetail != NULL)
			{
				dictator_free(threadnum,pstream->pdetail);
				pstream->pdetail=NULL;
			}			
			if(pstream_pr->timeout > link_default_nopkt_time){ /* ���Ӷ��г�ʱʱ��, ���ټ��� */
				sapp_global_mthread[threadnum].tcp_stream_special_timeout_num--;
			}			
			free_heap_stream_info(pstream, 0);
			free_streamindex(threadnum,pindex);
			ret = 0;
		}
	}	

	//g_SysInputInfo[threadnum][SYS_TCP_LINK_RESET]++;
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
					pstream->dir=DIR_DOUBLE; /* ����dir */
			 		pdetail_pr->link_state=STREAM_LINK_RESET;
					tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
					return PASS;
				}			
			}
			else
			//������������������
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
		else //ͬ������
		{
			//������
			 if(thisseq==curseq)
			 {
			 	if((this_tcphdr->th_flags & TH_RST)&&(datalen==0))
			       {
			 		pdetail_pr->link_state=STREAM_LINK_RESET;
					tcp_free_stream(pindex,  this_iphdr, this_tcphdr, raw_pkt);
					return PASS;
			        }	
				//add by lqy 20130802 �����������������е�������
			        //�������ڶ���ack
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
			   		pstream->dir=DIR_DOUBLE; /* ����dir */
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
		else //ͬ������
		{
			//����rst
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
	//add by lqy 20130805 ˫�����������������������data��
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
	//syn�ش�
	/*
		TODO, 
		��Ԫ����ͬ������SYN��, ��Ҫ��һ���ж�SEQ�Ƿ�һ�²������ش�, ��������Ԫ������,
		��Ҫreset.
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

	//���տ�ʼ��ack_seq��Ϊ0����ʱֱ�ӽ���ͷ��ack_seq��ֵ��rcv->ack_seq
	if (0 == *cur_half_stream_ack)
		*cur_half_stream_ack = ntohl(this_tcphdr->th_ack);
	else
	{
		ackdiff = (int)(ntohl (this_tcphdr->th_ack) - *cur_half_stream_ack);
#if 0 /* 20160930 lijia modify, �������뾯�� */
		if (ackdiff > 0 || ackdiff < -(2 << 30)) //��ֹ�ش�����Խ�������
#else
		if (ackdiff > 0 || ackdiff < (int)0x80000000) //��ֹ�ش�����Խ�������
#endif
		{
			*cur_half_stream_ack = ntohl (this_tcphdr->th_ack);
		}
	}

	//ͬ��
	if (0 == rcv->seq)
		rcv->seq = ntohl(this_tcphdr->th_seq);
	else
	{
		seqdiff = (int)(ntohl(this_tcphdr->th_seq) - rcv->seq);
#if 0	/* 20160930 lijia modify, �������뾯��, ʹ��������0x80000000 */	
		if (seqdiff > 0 || seqdiff < -(2 << 30))
#else
		if (seqdiff > 0 || seqdiff < (int)0x80000000) //��ֹ�ش�����Խ�������
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
		pdetail_pr->pclient=(struct half_tcpstream *)dictator_malloc(threadnum,sizeof(struct half_tcpstream));
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
		pdetail_pr->pserver=(struct half_tcpstream *)dictator_malloc(threadnum,sizeof(struct half_tcpstream));
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
			/* 2017-08-02 lijia modify, ��¼�����һ��ACK��, ��ack_seqһ����Լ�����������Բ���������� */
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
			/* 2017-08-02 lijia add, C2S��������ȡ�Զ�ISN */
			if((0 == pdetail_pr->iclientseq)
			 &&(ntohl(this_tcphdr->th_seq) == pdetail_pr->iserverseq)){ /* C2S����SYN����ĵ�һ��ACK�� */
				pdetail_pr->iclientseq = ntohl (this_tcphdr->th_ack);
			}
			/* 2017-08-02 lijia modify, ��¼�����һ��ACK��, ��ack_seqһ����Լ�����������Բ���������� */
			if(0 == pdetail_pr->C2S_first_ack_seq){
				pdetail_pr->C2S_first_ack_seq = ntohl (this_tcphdr->th_ack);
			}
			pdetail_pr->C2S_ack_seq = ntohl (this_tcphdr->th_ack);
			cur_half_stream_ack = &pdetail_pr->C2S_ack_seq;
		}
		
		/* 2017-08-03 lijia add, ������, ������ack�ƶϳ��Բ�������Ӧ���յ������� */
		if(DIR_C2S == a_tcp->dir){
			pdetail = a_tcp->ptcpdetail;
			//pdetail->clientbytes = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq;
			if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
				pdetail_pr->deduce_flow_stat->C2S_data_byte = pdetail->serverbytes; /* ���������˸������ṹ���еı��� */
				pdetail_pr->deduce_flow_stat->C2S_data_pkt = pdetail->serverpktnum;/* ���������˸������ṹ���еı��� */
				
				pdetail_pr->deduce_flow_stat->S2C_all_byte = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq; /* �ƶϳ��Ľ��, all��data��һ����, ��û��pkt */
				pdetail_pr->deduce_flow_stat->S2C_data_byte = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq; /* �ƶϳ��Ľ��, all��data��һ����, ��û��pkt */
			}
		}else if(DIR_S2C == a_tcp->dir){
			pdetail = a_tcp->ptcpdetail;
			//pdetail->serverbytes = pdetail_pr->C2S_ack_seq - pdetail_pr->C2S_first_ack_seq;
			if(G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID != -1){
				pdetail_pr->deduce_flow_stat->S2C_data_byte = pdetail->clientbytes; /* ���������˸������ṹ���еı��� */
				pdetail_pr->deduce_flow_stat->S2C_data_pkt = pdetail->clientpktnum;/* ���������˸������ṹ���еı��� */
				
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

   //��һ��������Ŀ������ش������ǳ��ȱ�ԭ����
   if(this_seq< EXP_SEQ)
   {
   	havelen = EXP_SEQ - this_seq;
	if (datalen - havelen > 0)
	{
		//20150225 ��¼�ص��ĳ���
		pdetail_pr->tcpoverlen=havelen;		
	   len_new= datalen - havelen; 
	   pdata_new=data+havelen;
	}
   }
   else //����ı���
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
	�����Ϊ��������, 1,2,3,4,x,6, ��5��������, ��6����������,
	�����6��������������Ϣ, ��Ҫkill_tcp,
	����5��������ʱ, streaminfo��洢�Ķ��ǵ�5��������Ϣ,
	Ȼ���ٴ��������е�6����������, ��ʱ����kill_tcp, ��ز����ǲ��Ե�,
	ʵ�ʵ�seq��ackʹ�õ��ǵ�5������!
	Ӧ��ʹ��buf_unorder�е�seq��ack, �����ǵ�ǰ����ԭʼ��.
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

/* 2014-10-20 lijia modify, ��IP��Ƭ�����, raw_pkt��tcpdatalen����Ӧ
raw_pktָ�����һ����Ƭ��, ��tcpdatalen��������ɺ������IP������!
�ֱ�洢!
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
				return PASS;
		}	
		if ((after (pakiet->seq, EXP_SEQ)) && (orderflag==CHECK_ORDER_DATA))
					break;
		if (after (pakiet->seq + pakiet->tcpdatalen+pakiet->fin+pakiet->rst, EXP_SEQ))
		{                    
			/* 2015-01-13 lijia add, ��������������kill_tcp��inject��غ���, ��Ҫ����ԭʼ����Ϣ */
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
				//a_tcp->addr.pkttype=tmpktype|PKT_TYPE_TCPUNORDER|a_tcp->pfather->addr.pkttype; /* lijia add, ��IP��Ƭ���ʹ����ϲ� */
				a_tcp->addr.pkttype=PKT_TYPE_TCPREORDER;
				//ret=stream_process_tcp(a_tcp,pakiet->data,&(pdetail->apme),&(a_tcp->opstate));
				ret=stream_process_tcp(a_tcp,pakiet->this_ip_hdr, pakiet->this_tcp_hdr, &(pakiet->raw_pkt),&(pdetail_pr->apme),&(a_tcp->opstate));
				a_tcp->addr.pkttype=tmpktype;
#if (0 == HIGH_PERF)					
				raw_frags_list_free_stream(a_tcp->threadnum, a_tcp);/* lijia add for raw ip frag list */
#endif		
				/* 2016-05-12 lijia add, ��������������unorder_list����BUG, �˴�Ӧ��������nouse״̬ */
				if(STREAM_LINK_DATA == last_link_state){
					tcp_change_stream_tonouse(pindex);
					return DROP;
				}
				/* ��Ϊ������update_stream_list_raw_pkt_pointer, �˴����ܷ���, �Ȼָ�ԭʼ��ָ�� */
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

				//get tcp��data��len
#if 0	/* 2014-01-12 lijia modify */			
				tcp_set_new_data(a_tcp,rcv,snd,(u_char *)(pakiet->data)+(pakiet->len-pakiet->tcpdatalen),
					pakiet->tcpdatalen,pakiet->seq,pakiet->fin);
#else
				tcp_set_new_data(a_tcp,rcv,snd,(u_char *)(pakiet->tcpdata),
					pakiet->tcpdatalen,pakiet->seq,pakiet->fin);
#endif
				if(pakiet->tcpdatalen >0)
				{
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
					//���ֵ���Ϣ����������
					//if(ret!=PASS)
					/* 2015-01-16 lijia modify, ����ģʽ��, ���������Kill_tcp(), �����᷵��DROP, Ϊ������������Կ��Կ����˰� */
					//if((ret!=PASS) || (a_tcp_pr->stream_killed_flag != 0)) 
					if(a_tcp_pr->stream_killed_flag != 0)  /* 2015-11-02 lqy modify, ������������жϷ���ֵ */
					{
						/* ��Ϊ������update_stream_list_raw_pkt_pointer, �˴����ܷ���, �Ȼָ�ԭʼ��ָ�� */
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
		//�������ݰ�
		if (after(this_seq + datalen + 
			(this_tcphdr->th_flags & TH_FIN), EXP_SEQ))
		{
			tcp_set_new_data(pstream,rcv,snd,tcpdata,datalen,this_seq,this_tcphdr->th_flags & TH_FIN);
			if(datalen >0)
			{
				ret=stream_process_tcp(pstream,this_iphdr,(const void *)this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
				//tcp_clear_newdata(pstream,rcv); /*  2016-09-12 lijia move to outside if(datalen > 0) */
			}
			tcp_clear_newdata(pstream,rcv); /* 2016-09-12 lijia move to here, ����datalen�Ƿ�>0, ��Ϊ������tcp_set_new_data, ����Ҫ����clear */

#if 0	/* lqy 2015-11-02 modify, ��������Ĵ������, ��Ӱ�쵱ǰ���ķ���ֵ */		
			if(ret==PASS) 
			{	
				ret = tcp_deal_unorder(pindex,pstream,rcv,snd,CHECK_ORDER_DATA);
				
			}
#else
		/* 2020-04-24 lijia modify, ���ret=stream_process_tcp����ֵ��DROP,   tcp_deal_unorder()����ֵ��PASS, ��ǰ������PASS, �����CT��! */
			ret_unorder = tcp_deal_unorder(pindex,pstream,rcv,snd,CHECK_ORDER_DATA);
#endif			
			if((DROP == ret_unorder) || (DROP == ret)){
				ret = DROP;
			}
			return ret;			
		}
		//����ԭ����������ݰ��Ƿ��Ѿ����򣬽��д���
	}
	else
	{
		//�������ݰ�����
		tcp_save_unorder(pstream,rcv,this_iphdr,raw_pkt,this_tcphdr,tcpdata, datalen);		
		if(rcv->unorder_cnt > rcv->maxunorder)
		{
			ret=tcp_deal_unorder(pindex,pstream,rcv,snd, !CHECK_ORDER_DATA);
		}
		pdetail_pr->has_lost_pkt_flag = 1;
	}     
	return ret;
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
	//�ش�������
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
		 //�����rst����
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
				tcp_change_stream_tonouse(pindex);
			}										
			else
			{
				tcp_free_stream(pindex, this_iphdr, this_tcphdr, raw_pkt);
			}
		
			return PASS;
		 }
		 //�����rst���ģ��������δ�������ᶪ���������Ѿ����������������
	}
	assert(rcv->count >= 0);
	//���Ӹ��� 
	if (th_flags & TH_SYN)
	{
		//syn�ش� add by lqy 20100808
#if 0		
	   if(thisseq+1 == rcv->first_data_seq) return PASS;
#else
	   if((datalen>0) || ((UINT32)thisseq+1 == rcv->first_data_seq) || ((UINT32)thisseq==rcv->first_data_seq)) 
	   {
		pstream->addr.pkttype = PKT_TYPE_TCPRETRANS;
		return PASS;
	   }else{
			/* 2017-12-19 lijia add, 
				��SYN�ش�, Ҫ�жϳ�ʱʱ��, �پ����Ƿ���Ԫ���������õ�ǰ���� ,
				������һ���յ���, ��������3��, ������̫��������Ԫ������, 
				��Ϊ�Ƕ�������.
				
				��������ͳ��ֵ, ��Ԫ�������������ӵ�ʱ����һ���ڷ��Ӽ�.
			*/
			if(pdetail->lastmtime + 3 > (UINT64)g_CurrentTime){
				return PASS;
			}
	   }
#endif   
	   //adjust by lqy 20150107
	   //if(thisseq==rcv->first_data_seq) return PASS;
	   //add by lqy 20110507 syn�����ݵ���Ϊ�ǹ�������
	   //if(datalen>0) return PASS;
	   //return PASS;	
	   if(th_flags & TH_RST)
	   {
	   		//MESA_runtime_log(RLOG_LV_FATAL, "[tcp_deal_data_stream]:","syn_rst,curseq:%d\n",curseq);
			return PASS;
	   }
	    pdetail_pr->link_state=STREAM_LINK_REUSE_BYSYN;
		pstream->opstate= OP_STATE_CLOSE;
		
#if 0		//del by lqy 20150107 tcp_reset_stream�����������������
		ret=stream_process_tcp(pstream,raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
#endif		
		tcp_reset_stream(pindex,this_iphdr,this_tcphdr,datalen,raw_pkt);
		return PASS;		
	}
	if(datalen + (th_flags & TH_FIN) +(th_flags & TH_RST)> 0)//����TCP����
	{
		tcpdata=(unsigned char*)(this_tcphdr) + 4 * this_tcphdr->th_off;
		ret=tcp_deal_data(pindex,this_iphdr,raw_pkt,this_tcphdr,tcpdata,datalen);	

/* 2016-05-12 lijia modify, ��������������unorder_list����BUG, ��ǰ������Ѿ���CLOSE״̬, �˴�Ӧ������return, ���ü���ִ�� */			

		
		//���ϲ�ر����ӣ����ߴ������������rst����
		if((pstream->opstate==OP_STATE_CLOSE)&&(pdetail_pr->link_state!=STREAM_LINK_RESET))
		{	
			tcp_change_stream_tonouse(pindex);
			return ret;
        	}

		if(ret==DROP)
			return DROP;
	}
	//add by lqy 20120922 �ϲ���Ҫack����Ϣʱ�ϴ��������ݵı���
	else if(pdetail_pr->needackflag!=0)
	{
		ret=stream_process_tcp(pstream,this_iphdr,this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
		//���ϲ�ر����ӣ����ߴ������������rst����
		/* 2017-08-01 lijia modify, ��Ҫ�ж�TCPALL���״̬, ����ֻ����TCPALL���ʱ, opstate�Ѿ���CLOSE��, ��������NOUSE̬ */
		if((pstream->opstate==OP_STATE_CLOSE)
		 && (OP_STATE_CLOSE == pstream->pktstate)
		 &&(pdetail_pr->link_state!=STREAM_LINK_RESET))
		{	
			tcp_change_stream_tonouse(pindex);
			return ret;
		}
	}
	assert(rcv->count >= 0);
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
	//��������ݵ�rst����Ҫ�ر�	
	if ((th_flags & TH_RST)&&(thisseq==curseq) &&(datalen!=0))
	{
		pdetail_pr->link_state=STREAM_LINK_RESET;
		finclose=1;
	}
	/* 2015-11-12 lijia add, ������RST, FIN���������� */
	if(pdetail_pr->ignore_rst_fin != 0){
		finclose = 0;
	}
	if(finclose)
	{
		pstream->opstate = OP_STATE_CLOSE;
	
		ret=stream_process_tcp(pstream,this_iphdr,this_tcphdr, raw_pkt,&(pdetail_pr->apme),&(pstream->opstate));
		//adjust by lqy �����ȫ�����յĺ�������ʱ
		if(pstream->pktstate!=OP_STATE_CLOSE)
		{
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

/*
	2017-10-16 lijia add,
	�ж�NOUSE״̬��, �յ�SYN, SYN/ACK�������Ԫ������, ���������ش�, �������۵��µ�ʱ�����.
	TODO:
	    ���ӳ�ʱ�ж�, ����ͳ�Ʒ���, ��������Ԫ������ͨ������30������.
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
			is_reuse = 0; /* ��Ԫ����ͬ, ����Ų�ͬ�����������ʱ��̫��, һ��30������, ���ƹ��������� */
		}
	}

	return is_reuse;
}

static int tcp_deal_nouse_stream(struct streamindex *pindex,const void *this_iphdr,const raw_pkt_t *raw_pkt,struct mesa_tcp_hdr *this_tcphdr,int datalen)
{
	struct streaminfo *pstream=(struct streaminfo *)(&(pindex->stream));
	struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)pstream->pdetail;

	//add by lqy 20141213
	//����ǿ�ack���������ӣ�Ӧ�ò�δ������,��ָ������������з���
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


	//fin��rst���п����������ģ�����ڴ˴���̭�����������п��ܻ����ȥ�������ݽ������ӣ���˲���̭
	
	//���Ӹ��� add by lqy 20150210 �������Ӻ��������ʱ�ָܻ���data������
	//add by lqy 20130822 �������а������յĺ�������ʱ������������̭
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
			pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len;
		}else{
			pdetail_pr->flow_stat->C2S_all_pkt++;
			pdetail_pr->flow_stat->C2S_all_byte += tcplen;
			pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len;
		}
	}
	
	//�½����ӱ����ȵ���all����
	ret=tcp_processallpkt(pstream,this_iphdr,this_tcphdr,tcplen,raw_pkt);	

	if(DROP == ret){ 
		/* 2016-06-08 lijia add,
			for HMD, ������й���ǰ����kill, �������ٵ��ú������.
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


/* LiJia comment: pstreamָ��ջ����ڴ� */
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
	int call_tcpall_after_reset = 0; /* 2019-10-18 lijia modify, ��ǰ����reset֮��,��֤�ȵ���tcpall,�ٵ���tcp */
	
	pindex_tcp = findstreamindex (pindex, raw_pkt);
	if(unlikely(!pindex_tcp)){
		if(this_tcphdr->th_flags & TH_SYN)
		{
			//add by yw to detect synflood attack
			//if(g_RunSYNFloodDetect == 1)
			if (unlikely(TCP_SYNFLOOD_DETECT_ON & tcp_flood_detect_model))
			{
				if( synflood_detector(pstream->threadnum) == ATTACKING)
               	{     
                    tcp_creatlink_model = TCP_CTEAT_LINK_BYDATA;
					return PASS;
               	}
                else
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
				ret=tcp_processallpkt(pstream,this_iphdr,this_tcphdr,tcplen,raw_pkt);
			}
			return ret;
		}
//		else if(tcplen>0)
		else
		{
			/*   2017-12-07 lijia add,  
				TCPRFC�涨, �����ӻ�δ�����������, �յ��Զ˵����ݰ�, ��Ӧ��RST�����Ϊ0, 
				���һ�����ĵ�һ����, ���Ǹ�seq=0��RST��, ��ʱ����������, ������.
			*/
			if((this_tcphdr->th_flags & TH_RST) && (0 == this_tcphdr->th_seq)){
				return PASS;
			}
			//add by lqy 20141213ȫ���ӿ��²���tcplen=0�İ�������
			if((tcplen==0)&&(tcp_support_all==TCP_SUPPORT_ENTRYALL_OFF))
				return PASS;		
			if(TCP_CTEAT_LINK_BYDATA  & tcp_creatlink_model )
			{
				//add by yw to detect dataflood attack
				//if(tcplen < g_DataFloodPacketLen && g_RunDataFloodDetect == 1)
				if((tcplen<tcp_dataflood_pktlen) && (1==(TCP_DATAFLOOD_DETECT_ON  & tcp_flood_detect_model)))
				{
					if( dataflood_detector(pstream->threadnum) == ATTACKING)
					{
						tcp_creatlink_model = TCP_CTEAT_LINK_BYSYN;
						return PASS;
					}
				}
				//end of add by yw to detect dataflood attack			
			pindex_tcp=tcp_add_new_stream_bydata(pindex,this_tcphdr,tcplen,CTREAT_LINK, raw_pkt);
			if(likely(pindex_tcp != NULL))
			{
				pstream_pr = &pindex_tcp->stream;
				pstream = &pstream_pr->stream_public;
					pstream_pr->raw_pkt = raw_pkt;  //add by lijia 20171206
				//add by lqy 20150114 �½��������ӱ����ȵ���all����
				return tcp_process_newstreambydata(pindex_tcp,this_iphdr, this_tcphdr,tcplen,raw_pkt);
			}
			}
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
		/* 2015-11-04 lijia add, IP��Ƭ���͸���, pstreamָ�������еĽṹ, pindexΪջ�ﵱǰ���ṹ */	
		pstream->addr.pktipfragtype = pindex->stream.stream_public.addr.pktipfragtype; 
	}

	pdetail_pr =(struct tcpdetail_private*)(pstream->pdetail);
	pdetail =(struct tcpdetail *)(&pdetail_pr->tcpdetail_public);

	/* 2014-10-11 lijia add, Fd������ƽ̨ʵ�� */
	if(unlikely(pstream_pr->stream_killed_flag != 0)){
		if((pdetail_pr->auto_remedy_flag != 0) && (tcplen > 0)){ /* ��ֹflood����, ֻ�д����ݵİ��ŷ�RST */
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
		//return DROP; /* 2019-11-20 lijia modify, kill_tcp��Ĭ����Ϊ����DROP, ȡ����drop_stream_flag */
	}

	if(unlikely(pdetail_pr->drop_stream_flag != 0)){
		sapp_runtime_log(RLOG_LV_DEBUG, "TCP stream: %s, has been set drop flag, curdir:%d, return DROP.", 
						printaddr(&pstream->addr, pstream->threadnum), pstream->curdir);
		return DROP;
	}

	if(pstream->curdir==DIR_S2C)
	{
		if(pdetail->clientpktnum == 0) /* ��ǰ����ĵ�һ����, ���Ը��µײ������ĵ����ַ��Ϣ(��MPLS, GTP) */
		{
			try_to_update_addr_info = 1;
		}
		pdetail->clientbytes+=tcplen;
		pdetail->clientpktnum++;
	}
	else
	{
		if(pdetail->serverpktnum == 0) /* ��ǰ����ĵ�һ����, ���Ը��µײ������ĵ����ַ��Ϣ(��MPLS, GTP) */
		{
			try_to_update_addr_info = 1;
		}
		pdetail->serverbytes+=tcplen;
		pdetail->serverpktnum++;
	}

	if(try_to_update_addr_info == 1)
	{
		update_opposite_addr_info((struct streaminfo_private *)(pstream->pfather),
				(struct streaminfo_private *)(pindex->stream.stream_public.pfather), pstream->curdir);
	}

	/* flow_stat��ȫ����״̬��¼, �������ش����������� */
	if(G_TCP_FLOW_STAT_PROJECT_ID != -1){
		if(DIR_C2S == pstream->curdir){
			pdetail_pr->flow_stat->C2S_all_pkt++;
			pdetail_pr->flow_stat->C2S_all_byte += tcplen;
			pdetail_pr->flow_stat->C2S_all_byte_raw += raw_pkt->raw_pkt_len;
		}else{
			pdetail_pr->flow_stat->S2C_all_pkt++;
			pdetail_pr->flow_stat->S2C_all_byte += tcplen;
			pdetail_pr->flow_stat->S2C_all_byte_raw += raw_pkt->raw_pkt_len;
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

	update_polling_inject_context(pstream_pr, raw_pkt);
	
	/* note: reset�����ü���, ����clientbytes+=, clientpktnum++����֮�� */
	if(1 == lrustream(pindex_tcp)){
		ret = tcp_reset_stream(pindex_tcp, this_iphdr,this_tcphdr, tcplen,raw_pkt);		
		if(0 == ret){
			return PASS;
		}
		ret = tcp_processallpkt(pstream, this_iphdr, this_tcphdr, tcplen, raw_pkt);
		if(DROP == ret){
			return DROP;
		}

		call_tcpall_after_reset = 1;		
	}
	pdetail->lastmtime=g_CurrentTime;

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
			// �������ı��ģ����������к�̴���
			if(DROP==ret)
			{
				   //return PASS;//�����к�̴��������Ǳ��뷵��PASS�������߼�����
				   ret = PASS;
				   goto fun_exit;
			}
			if((tcplen>0) && (checkcreatlinkseq(&(pindex_tcp->stream),htonl(this_tcphdr->th_seq))==1))
			{
				tcp_change_stream_todata(pindex_tcp,this_tcphdr,tcplen);
				 //ret=tcp_deal_data_stream(pindex_tcp,rawippkt,iplen,this_tcphdr,tcplen);
				 ret=tcp_deal_data_stream(pindex_tcp,this_iphdr,raw_pkt,this_tcphdr,tcplen);
			}
			//add by lqy 20150215 �½����Ӹտ�ʼ��������
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
	
	//adjust by lqy 20150107 Ϊ�˷�ֹSYN�ؽ�����ʱSYN�ڵ�һ��������
	if((0 == call_tcpall_after_reset) && pindex_tcp && (pstream->pktstate!=OP_STATE_CLOSE))
	{
		//ȫ���ӿ��õ�������ָ��ǰ����ԭʼ����
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
	�����IP��Ƭ����İ�, ������ʽ�Ĵ���IP��ͷ, ����ֻ��tcp_hdr��raw_hdr, �޷���ȡ������IP��ͷ.
*/
static int dealtcppkt(struct streamindex *pfindex, const void *this_iphdr, struct mesa_tcp_hdr *this_tcphdr, 
	int thread_num,unsigned char routedir, int tcpdatalen, const raw_pkt_t *raw_packet, int offset_to_raw_pkt_hdr)
{
#if 0
	struct layer_addr_tcp tcp_addr;
#else
	//struct layer_addr *tcp_stream_addr;
#endif

	/* IPPORT-union�汾, IP��TCP��ʹ��ͬһ��index�ṹ, ��ֱ��ͨ��IP�㴫�ݵ�pfindex */
	//struct streamindex tmp_tcp_stream;
	//struct streamindex *ptmp=&tmp_tcp_stream;
	struct streaminfo_private *pstream_pr = (struct streaminfo_private *)(&pfindex->stream);
	struct streaminfo *pstream = (struct streaminfo *)(&pstream_pr->stream_public);
	sapp_gval_mthread_sys_stat_t *local_sys_stat = &sapp_global_val->mthread_volatile[thread_num]->sys_stat;
	
	//g_SysInputInfo[thread_num][PKT_TCP]++;
	//g_SysInputInfo[thread_num][PKT_TCPLEN] += tcpdatalen;
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

#if IKNOW_ENABLE
	packet_io_status_tcp_pkt_update(thread_num, this_tcphdr->th_flags, tcpdatalen);
#endif

	set_transport_addr(pstream, this_tcphdr->th_sport, this_tcphdr->th_dport);

	pstream->addr.pkttype = PKT_TYPE_NORMAL;//add by lqy 20151222, init pkttype
	
	pstream_pr->addr_use_as_hash = 1; /* ��Ԫ����Ϣ����IP�� */
//	ptmp->stream.p_layer_header = this_tcphdr;
	//ptmp->stream.offset_to_raw_pkt_hdr = (char *)this_tcphdr - (char *)raw_packet->raw_pkt_data;
	pstream_pr->offset_to_ip_hdr = (char *)this_tcphdr - (char *)this_iphdr;
	pstream_pr->raw_pkt = raw_packet; /* 2014-12-30 lijia add */

	//pstream->pfather=&pfstream_pr->stream_public;
	pstream->type=STREAM_TYPE_TCP;
	pstream->routedir=routedir;
	pstream->threadnum=thread_num;
	
	//return deal_tcp_stream(ptmp,this_tcphdr,tcpdatalen,raw_packet,raw_len);
	return deal_tcp_stream(pfindex,this_iphdr, this_tcphdr,tcpdatalen, raw_packet, offset_to_raw_pkt_hdr);
}

/* lijia comment: this_iphdr��������ʵԭʼ��, Ҳ������malloc��IP�����, ��addr.pkttype���� */
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

	/* lijia 2016-06-15 add, �����Ż�, ������ACK�� */
#if HIGH_PERF /* ������ģʽ���Զ�����ACK */
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
int set_transport_addr(struct streaminfo *this_stream, UINT16 sport, UINT16 dport)
{
	struct streaminfo_private *this_stream_pr = (struct streaminfo_private *)this_stream;
	struct layer_addr *this_addr = &this_stream->addr;
	
	if(__ADDR_TYPE_IP_PAIR_V4 == this_addr->addrtype){
		struct stream_tuple4_v4 *ip4_addr = this_addr->tuple4_v4;
		/* ���ö˿�, ��IP-PORT-union�汾��port˳����Ϊlayer_dir�Ĳ���,
		   ͬʱ����layer_dir, ���ڼ���HASHʱ, ��ַ����˳�� */
		if(ntohs(sport) > ntohs(dport)){
			this_stream_pr->layer_dir = 1; /* ���˿�˳�������Ԫ��layer_dir */
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
		ip4_addr->source = sport;
		ip4_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV4; /* ����pappƽ̨, ��������Ԫ��ʹ��'ADDR_TYPE_IPV4��ʾ' */
		this_addr->addrlen = sizeof(struct stream_tuple4_v4);
	}else if(__ADDR_TYPE_IP_PAIR_V6 == this_addr->addrtype){
		struct stream_tuple4_v6 *ip6_addr = this_addr->tuple4_v6;
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
		
		ip6_addr->source = sport;
		ip6_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV6; /* ����pappƽ̨, ��������Ԫ��ʹ��'ADDR_TYPE_IPV6��ʾ' */
		this_addr->addrlen = sizeof(struct stream_tuple4_v6);
	}else{
		assert(0);
	}
	
	return 0;
}
#endif

int set_stream_addr_transport(struct streaminfo_private *this_stream_pr, UINT16 sport, UINT16 dport)
{
	struct streaminfo *this_stream = &this_stream_pr->stream_public;
	struct layer_addr *this_addr = &this_stream->addr;
	
	if(__ADDR_TYPE_IP_PAIR_V4== this_stream->addr.addrtype){
		struct stream_tuple4_v4 *ip4_addr = this_stream->addr.tuple4_v4;
		if(ntohs(sport) > ntohs(dport)){
			this_stream_pr->layer_dir = 1;
			this_stream->curdir = DIR_C2S;
		}else{
			if(sport == dport){
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
		ip4_addr->source = sport;
		ip4_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV4; /* ����pappƽ̨, TCP�����Ԫ��ʹ��'ADDR_TYPE_IPV4��ʾ' */
		this_stream->addr.addrlen = sizeof(struct stream_tuple4_v4);
	}else if(__ADDR_TYPE_IP_PAIR_V6 == this_stream->addr.addrtype){
		struct stream_tuple4_v6 *ip6_addr = this_stream->addr.tuple4_v6;
		if(ntohs(sport) > ntohs(dport)){
			this_stream_pr->layer_dir = 1;
			this_stream->curdir = DIR_C2S;
		}else{
			if(sport == dport){
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
		ip6_addr->source = sport;
		ip6_addr->dest = dport;
		this_addr->addrtype = ADDR_TYPE_IPV6;/* ����pappƽ̨, TCP-v6�����Ԫ��ʹ��'ADDR_TYPE_IPV6��ʾ' */
		this_stream->addr.addrlen = sizeof(struct stream_tuple4_v6);
	}else{
		//printf("set_stream_addr_transport() error, addr type is not IPv4 or IPv6!\n");
		sapp_runtime_log(RLOG_LV_FATAL, "set_stream_addr_transport() error, addr type is not IPv4 or IPv6!\n");
		abort();
	}

	//this_addr->paddr = pfstream->addr.paddr;
	//this_addr->pktipfragtype = pfstream->addr.pktipfragtype; /* 2015-01-29 lijia add, IP��Ƭ���Ͳ�� */
	return 0;
}

/* 
   2014-04-08 LiJia add,
   ÿ�����ĵ�ַ��Ϣ��ʱ����ջ�ռ�, �������غ�˿��ڴ��ַ����Ч��, 
   ��������ʱ, ��copy��malloc�Ķѿռ���, �����Ժ�ĵ�ַ�ȶ�. 
 */
struct streaminfo_private *copy_stream_info_to_heap(const struct streaminfo_private *stack_stream_pr, int reverse)
{
	struct streaminfo_private *heap_stream_pr = NULL;
	void *heap_addr;
	struct streaminfo *heap_stream;
	const struct streaminfo *stack_stream;

	if(NULL == stack_stream_pr){
		return NULL;
	}

	stack_stream = &(stack_stream_pr->stream_public);

	heap_stream_pr = (struct streaminfo_private *)dictator_malloc(stack_stream->threadnum, sizeof(struct streaminfo_private));
	memcpy(heap_stream_pr, stack_stream_pr, sizeof(struct streaminfo_private));
	heap_stream = &(heap_stream_pr->stream_public);

	heap_stream->pfather = (struct streaminfo *)copy_stream_info_to_heap((const struct streaminfo_private *)stack_stream->pfather, reverse);

	heap_addr = dictator_malloc(stack_stream->threadnum, stack_stream->addr.addrlen);
	memset(heap_addr, 0, stack_stream->addr.addrlen);
		
	if(reverse){
		heap_stream_pr->dirreverse=1;
		heap_stream_pr->stream_dir = 1 ^ heap_stream_pr->layer_dir; /* lijia comment, ��"src>=dst"Ĭ�Ϲ���һ�� */
		//reverse_addr_new(heap_addr, heap_stream->addr.addrtype);
		/* ��ַCOPYʱ, �����Ҫ��ת, ֱ�ӷ���COPY, ��Ҫ��memcpy, �ٽ�����ַԴ��Ŀ�ĵ�˳�� */
		addr_reverse_memcpy(heap_addr, stack_stream->addr.paddr, stack_stream->addr.addrtype, stack_stream->addr.addrlen);
	}else{
		heap_stream_pr->stream_dir = heap_stream_pr->layer_dir;
		memcpy(heap_addr, stack_stream->addr.paddr, stack_stream->addr.addrlen);
	}
	
	heap_stream->addr.paddr = heap_addr;
	heap_stream->addr.addrlen = stack_stream->addr.addrlen;
	heap_stream->addr.addrtype = stack_stream->addr.addrtype;
	
	return (struct streaminfo_private *)heap_stream;
}

/* 2014-12-30 lijia add, ��������Ϊһ������ṹ, ����Ϊ��ȡ��ַ��ʵ�ʽṹ, ����֮ */
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
	
	uo_packet = (struct buf_unorder *)dictator_malloc(a_tcp->threadnum, sizeof(struct buf_unorder));
	memset(uo_packet, 0, sizeof(struct buf_unorder));

	//carry_ip_stream = skip_proxy_phony_stream(a_tcp->pfather);
	carry_ip_stream = skip_proxy_phony_stream(a_tcp);

	/* �洢ԭʼ�� */
	memcpy(&(uo_packet->raw_pkt),  stack_raw_pkt, sizeof(raw_pkt_t));	
	uo_packet->raw_pkt.raw_pkt_data = dictator_malloc(a_tcp->threadnum, stack_raw_pkt->raw_pkt_len);
	memcpy((void *)uo_packet->raw_pkt.raw_pkt_data, stack_raw_pkt->raw_pkt_data, stack_raw_pkt->raw_pkt_len);


	/* 	iphdr���������:
		1)��IP��Ƭ��:
			ֻ��洢������ԭʼ��, �����Ķ���ָ������, ֻ��freeһ��;
		2)IP����İ�:
			�洢������ԭʼ��(���һ����Ƭ), �������malloc��IP��, ����ʹ��ָ������;
	*/
#if 0	 
	if(carry_ip_stream->addr.pktipfragtype & PKT_TYPE_IPREBUILD){
#else
	/* ��ΪIPv4�п��ܶ��Ƕ��, ����: MAC->IPv4->UDP->IPv6->IPv4->TCP->APP,
		���ܽ��жϵ�ǰ����IPv4���Ƿ��Ƿ�Ƭ, ��ײ��IPv4��Ҳ������Դ��IP��Ƭ����İ�.
		����, ʹ��ԭʼ��ָ��͵�ǰIPͷָ��ľ���ֵƫ�����ж�, 
		�����İ�, ��ǰ��ͷ��ԭʼ��ͷ�ĵ�ַƫ�����϶���MTU��Χ��,
		���������MTU, ��ǰIP���϶�����malloc��, ����Ƭ����İ�.
	*/
	if(abs((char *)this_iphdr - (char *)stack_raw_pkt->raw_pkt_data) > MTU_MAX){
#endif
		uo_packet->ip_reassemble_pkt = 1;
		this_ip_tot_len = get_ip_pkt_tot_len(carry_ip_stream, this_iphdr);
		uo_packet->this_ip_hdr = dictator_malloc(a_tcp->threadnum, this_ip_tot_len);
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

	/* IP��Ƭ����ָ���ƶ���pakiet�ṹ��, ��ȫ�ֵ�G_IP_FRAG_LIST[tid]ָ���ÿ�, ���ⱻip_entry���ͷ� */
	uo_packet->ipfrag_list = raw_ip_frag_list_global_move_pkt(a_tcp);

	a_tcp->addr.pkttype = PKT_TYPE_TCPUNORDER;//add by lqy 20151222, mark unorder
	
	return uo_packet;
}

static void tcp_free_unorder_pkt(int threadnum, struct buf_unorder *uo_packet)
{
	if(uo_packet->ip_reassemble_pkt != 0){
		dictator_free(threadnum, uo_packet->this_ip_hdr);
	}

#if (0 == HIGH_PERF)	
	if(uo_packet->ipfrag_list){
		raw_frags_list_free_one(threadnum, uo_packet->ipfrag_list);
		uo_packet->ipfrag_list = NULL;
	}
#endif

	dictator_free(threadnum, (void *)uo_packet->raw_pkt.raw_pkt_data);
	dictator_free(threadnum, uo_packet);

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
	��Ϊkill_xxxϵ�к���ʹ��stream_pr�ṹ�е�raw_pktָ��,
	����������������ĳ����, ����kill_xxxϵ�к���,
	��ʱ��
*/
static inline void update_stream_list_raw_pkt_pointer(struct streaminfo_private *a_tcp_pr, const raw_pkt_t *raw_pkt)
{
	a_tcp_pr->raw_pkt = raw_pkt;

	/* TODO 3: �Ƿ���Ҫ�ݹ�Ľ�a_tcp->pfather->raw_pktҲȫ������?! */

	return;
}

/* TODO 1: ����ÿ������ƽ������, �ֽ���, ƽ����ʱ����ͳ�� */
#if IKNOW_ENABLE
#include "iknow.h"
typedef struct{
	packet_io_status_base_t io_base_status; /* TCP���ܼ��� */
	unsigned long long syn_pkt_num;
	unsigned long long synack_pkt_num;
	unsigned long long rst_pkt_num;
	unsigned long long nodata_pkt_num; /* data length = 0 */
}packet_io_status_tcp_pkt_t;

typedef struct{
	packet_io_status_base_t io_base_status; /* nouse */
	unsigned long long create_by_syn_num;
	unsigned long long create_by_data_num;
	unsigned long long create_nouse_num;
	unsigned long long del_syn_num;
	unsigned long long del_data_num;
	unsigned long long del_nouse_num;	
}packet_io_status_tcp_stream_t;

typedef struct{
	time_t max_live_time; /* ȫ���������ʱ��, ��������������, Ҳ��������ʱ����̭�� */
	time_t min_live_time;
	time_t avg_live_time;
	time_t normal_finish_max_live_time; /* ���������������ʱ��, ����FIN����RST������ */
	time_t normal_finish_avg_live_time; /* ���������������ʱ��, ����FIN����RST������ */	
}packet_io_status_tcp_stream_time_t;

//extern int g_packet_io_thread_num;
extern packet_io_status_t *g_packet_io_status_pool[MAX_THREAD_NUM];
static volatile packet_io_status_tcp_pkt_t g_last_tcp_pkt_status, g_cur_tcp_pkt_status, g_realtime_tcp_pkt_status;
static volatile packet_io_status_tcp_pkt_t g_thread_last_tcp_pkt_status[MAX_THREAD_NUM], g_thread_realtime_tcp_pkt_status[MAX_THREAD_NUM];
static volatile packet_io_status_tcp_stream_t g_last_tcp_stream_status, g_cur_tcp_stream_status, g_realtime_tcp_stream_status;
static volatile packet_io_status_tcp_stream_t g_thread_last_tcp_stream_status[MAX_THREAD_NUM], g_thread_realtime_tcp_stream_status[MAX_THREAD_NUM];

void *packet_io_status_tcp_pkt_mem_init(void)
{
	void *tcp_pkt_mem;
	
	tcp_pkt_mem = malloc(sizeof(packet_io_status_tcp_pkt_t));
	memset(tcp_pkt_mem, 0, sizeof(packet_io_status_tcp_pkt_t));

	return tcp_pkt_mem;
}

void packet_io_status_tcp_pkt_time_cb(void)
{
	int i;
	packet_io_status_tcp_pkt_t *p_tcp_pkt_status;

 	memcpy((void *)&g_last_tcp_pkt_status, (void*)&g_cur_tcp_pkt_status, sizeof(packet_io_status_tcp_pkt_t)); /* ������һ���ֵ */
 	memset((void *)&g_cur_tcp_pkt_status, 0, sizeof(packet_io_status_tcp_pkt_t)); /* ���� */

	for(i = 0; i < g_packet_io_thread_num; i++){
		p_tcp_pkt_status = (packet_io_status_tcp_pkt_t *)(g_packet_io_status_pool[i]->packet_io_status[IO_STATUS_TCP_PKT]);
		/* for summary */
		g_cur_tcp_pkt_status.io_base_status.pkt_num += p_tcp_pkt_status->io_base_status.pkt_num;
		g_cur_tcp_pkt_status.io_base_status.pkt_byte += p_tcp_pkt_status->io_base_status.pkt_byte;
		g_cur_tcp_pkt_status.syn_pkt_num += p_tcp_pkt_status->syn_pkt_num;
		g_cur_tcp_pkt_status.synack_pkt_num += p_tcp_pkt_status->synack_pkt_num;
		g_cur_tcp_pkt_status.rst_pkt_num += p_tcp_pkt_status->rst_pkt_num;
		g_cur_tcp_pkt_status.nodata_pkt_num += p_tcp_pkt_status->nodata_pkt_num;

		/* for detail real time */
		g_thread_realtime_tcp_pkt_status[i].io_base_status.pkt_num = p_tcp_pkt_status->io_base_status.pkt_num - g_thread_last_tcp_pkt_status[i].io_base_status.pkt_num;
		g_thread_realtime_tcp_pkt_status[i].io_base_status.pkt_byte = p_tcp_pkt_status->io_base_status.pkt_byte - g_thread_last_tcp_pkt_status[i].io_base_status.pkt_byte;
		g_thread_realtime_tcp_pkt_status[i].syn_pkt_num = p_tcp_pkt_status->syn_pkt_num - g_thread_last_tcp_pkt_status[i].syn_pkt_num;
		g_thread_realtime_tcp_pkt_status[i].synack_pkt_num = p_tcp_pkt_status->synack_pkt_num - g_thread_last_tcp_pkt_status[i].synack_pkt_num;
		g_thread_realtime_tcp_pkt_status[i].rst_pkt_num = p_tcp_pkt_status->rst_pkt_num - g_thread_last_tcp_pkt_status[i].rst_pkt_num;
		g_thread_realtime_tcp_pkt_status[i].nodata_pkt_num = p_tcp_pkt_status->nodata_pkt_num - g_thread_last_tcp_pkt_status[i].nodata_pkt_num;

		/* save last status */
		g_thread_last_tcp_pkt_status[i].io_base_status.pkt_num = p_tcp_pkt_status->io_base_status.pkt_num;
		g_thread_last_tcp_pkt_status[i].io_base_status.pkt_byte = p_tcp_pkt_status->io_base_status.pkt_byte;
		g_thread_last_tcp_pkt_status[i].syn_pkt_num = p_tcp_pkt_status->syn_pkt_num;
		g_thread_last_tcp_pkt_status[i].synack_pkt_num = p_tcp_pkt_status->synack_pkt_num;
		g_thread_last_tcp_pkt_status[i].rst_pkt_num = p_tcp_pkt_status->rst_pkt_num;
		g_thread_last_tcp_pkt_status[i].nodata_pkt_num = p_tcp_pkt_status->nodata_pkt_num;
	}

	g_realtime_tcp_pkt_status.io_base_status.pkt_num = g_cur_tcp_pkt_status.io_base_status.pkt_num - g_last_tcp_pkt_status.io_base_status.pkt_num;
	g_realtime_tcp_pkt_status.io_base_status.pkt_byte = g_cur_tcp_pkt_status.io_base_status.pkt_byte - g_last_tcp_pkt_status.io_base_status.pkt_byte;
	g_realtime_tcp_pkt_status.syn_pkt_num = g_cur_tcp_pkt_status.syn_pkt_num - g_last_tcp_pkt_status.syn_pkt_num;
	g_realtime_tcp_pkt_status.synack_pkt_num = g_cur_tcp_pkt_status.synack_pkt_num - g_last_tcp_pkt_status.synack_pkt_num;
	g_realtime_tcp_pkt_status.rst_pkt_num = g_cur_tcp_pkt_status.rst_pkt_num - g_last_tcp_pkt_status.rst_pkt_num;
	g_realtime_tcp_pkt_status.nodata_pkt_num = g_cur_tcp_pkt_status.nodata_pkt_num - g_last_tcp_pkt_status.nodata_pkt_num;
}


static void packet_io_status_tcp_pkt_update(int tid, unsigned char th_flags, int payload_len)
{
	packet_io_status_tcp_pkt_t *p_tcp_pkt_status;

	p_tcp_pkt_status = (packet_io_status_tcp_pkt_t *)(g_packet_io_status_pool[tid]->packet_io_status[IO_STATUS_TCP_PKT]);

	p_tcp_pkt_status->io_base_status.pkt_num++;
	p_tcp_pkt_status->io_base_status.pkt_byte += payload_len;
	
	switch(th_flags){
		case TH_SYN:
			p_tcp_pkt_status->syn_pkt_num++;
		break;

		case TH_RST:
			p_tcp_pkt_status->rst_pkt_num++;
		break;

		case 0x12: /* SYN/ACK */
			p_tcp_pkt_status->synack_pkt_num++;
		break;

		default:
		break;
	}

	if(0 == payload_len){
		p_tcp_pkt_status->nodata_pkt_num++;
	}
}


static inline void packet_io_status_tcp_stream_update(int tid, UCHAR stream_state,  int action)
{
	packet_io_status_tcp_stream_t *p_tcp_stream_status;

	p_tcp_stream_status = (packet_io_status_tcp_stream_t *)(g_packet_io_status_pool[tid]->packet_io_status[IO_STATUS_TCP_STREAM]);

	if(action > 0){
		switch(stream_state){
			case TCP_DATA_STATE:
					p_tcp_stream_status->create_by_data_num ++;
					break;
			case TCP_NOUSE_STATE:
					p_tcp_stream_status->create_nouse_num ++;
					break;
			case TCP_SYN_STATE:
					p_tcp_stream_status->create_by_syn_num ++;
					break;					
		}	
	}else{
		switch(stream_state){
			case TCP_DATA_STATE:
					p_tcp_stream_status->del_data_num++;
					break;
			case TCP_NOUSE_STATE:
					p_tcp_stream_status->del_nouse_num++;
					break;
			case TCP_SYN_STATE:
					p_tcp_stream_status->del_syn_num ++;
					break;					
		}	
	}
}


static long ifuncb_show_tcp_pkt_summary(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	/* ȫ���ܰ���, ���ֽ��� */

	iprintf(ihandle, iconn,"NOTE: unit of byte for total is 'byte', for realtime is 'bps, bit per second'!\n");
	iprintf(ihandle, iconn, "%8s %10s %12s %8s %10s %8s %10s %11s\n", " ", "packet", "byte", "SYN-PKT", "SYNACK-PKT", "RST-PKT", "NO-PAYLOAD", "AVG-PKT-LEN"); 
	iprintf(ihandle, iconn, "%8s %10llu %12llu %8llu %10llu %8llu %10llu %.2f\n", "total", 
		  g_cur_tcp_pkt_status.io_base_status.pkt_num, 
		  g_cur_tcp_pkt_status.io_base_status.pkt_byte,
		  g_cur_tcp_pkt_status.syn_pkt_num,
		  g_cur_tcp_pkt_status.synack_pkt_num,
		  g_cur_tcp_pkt_status.rst_pkt_num,
		  g_cur_tcp_pkt_status.nodata_pkt_num,
		  (g_cur_tcp_pkt_status.io_base_status.pkt_num > 0) ? (float)g_cur_tcp_pkt_status.io_base_status.pkt_byte/(float)g_cur_tcp_pkt_status.io_base_status.pkt_num : 0);

	iprintf(ihandle, iconn, "%8s %10llu %12llu %8llu %10llu %8llu %10llu %.2f\n", "realtime", 
		  g_realtime_tcp_pkt_status.io_base_status.pkt_num, 
		  g_realtime_tcp_pkt_status.io_base_status.pkt_byte,
		  g_realtime_tcp_pkt_status.syn_pkt_num,
		  g_realtime_tcp_pkt_status.synack_pkt_num,
		  g_realtime_tcp_pkt_status.rst_pkt_num,
		  g_realtime_tcp_pkt_status.nodata_pkt_num,
		  (g_realtime_tcp_pkt_status.io_base_status.pkt_num > 0) ?(float)g_realtime_tcp_pkt_status.io_base_status.pkt_byte/(float)g_realtime_tcp_pkt_status.io_base_status.pkt_num : 0);
		  
	return 0;
}

static long ifuncb_show_tcp_pkt_detail_total(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	int i;
	packet_io_status_tcp_pkt_t *p_tcp_pkt_status;

	iprintf(ihandle, iconn,"NOTE: unit of byte for total is 'byte', for realtime is 'bps, bit per second'!\n");
	iprintf(ihandle, iconn, "%8s %10s %12s %8s %10s %8s %10s %11s\n", "tid", "packet", "byte", "SYN-PKT", "SYNACK-PKT", "RST-PKT", "NO-PAYLOAD", "AVG-PKT-LEN"); 

	for(i = 0; i < g_packet_io_thread_num; i++){
		p_tcp_pkt_status = (packet_io_status_tcp_pkt_t *)(g_packet_io_status_pool[i]->packet_io_status[IO_STATUS_TCP_PKT]);
		iprintf(ihandle, iconn, "%8d %10llu %12llu %8llu %10llu %8llu %10llu %.2f\n", 
			  i, 
			  p_tcp_pkt_status->io_base_status.pkt_num, 
			  p_tcp_pkt_status->io_base_status.pkt_byte,
			  p_tcp_pkt_status->syn_pkt_num,
			  p_tcp_pkt_status->synack_pkt_num,
			  p_tcp_pkt_status->rst_pkt_num,
			  p_tcp_pkt_status->nodata_pkt_num,
			  (p_tcp_pkt_status->io_base_status.pkt_num > 0) ? (float)p_tcp_pkt_status->io_base_status.pkt_byte/(float)p_tcp_pkt_status->io_base_status.pkt_num : 0);
	}
	
	return 0;
}

static long ifuncb_show_tcp_pkt_detail_realtime(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	int i;
	//packet_io_status_tcp_pkt_t *p_tcp_pkt_status;

	iprintf(ihandle, iconn,"NOTE: unit of byte for total is 'byte', for realtime is 'bps, bit per second'!\n");
	iprintf(ihandle, iconn, "%8s %10s %12s %8s %10s %8s %10s %11s\n", "tid", "packet", "byte", "SYN-PKT", "SYNACK-PKT", "RST-PKT", "NO-PAYLOAD", "AVG-PKT-LEN"); 

	for(i = 0; i < g_packet_io_thread_num; i++){
		iprintf(ihandle, iconn, "%8d %10llu %12llu %8llu %10llu %8llu %10llu %.2f\n", 
			  i, 
			  g_thread_realtime_tcp_pkt_status[i].io_base_status.pkt_num, 
			  g_thread_realtime_tcp_pkt_status[i].io_base_status.pkt_byte,
			  g_thread_realtime_tcp_pkt_status[i].syn_pkt_num,
			  g_thread_realtime_tcp_pkt_status[i].synack_pkt_num,
			  g_thread_realtime_tcp_pkt_status[i].rst_pkt_num,
			  g_thread_realtime_tcp_pkt_status[i].nodata_pkt_num,
			  (g_thread_realtime_tcp_pkt_status[i].io_base_status.pkt_num > 0) ? (float)g_thread_realtime_tcp_pkt_status[i].io_base_status.pkt_byte/(float)g_thread_realtime_tcp_pkt_status[i].io_base_status.pkt_num : 0);
	}
	
	return 0;
}

#if IKNOW_ENABLE
void iknow_register_tcp_pkt_cb(void *ihandle)
{
	int ret;

	ret = iknow_register_cmd(ihandle, "show tcp pkt summary", "display tcp pkt summary", ifuncb_show_tcp_pkt_summary, NULL, 0, NULL);
	assert(0 == ret);
	ret = iknow_register_cmd(ihandle, "show tcp pkt detail total", "display tcp pkt detail total", ifuncb_show_tcp_pkt_detail_total, NULL, 0, NULL);
	assert(0 == ret);	
	ret = iknow_register_cmd(ihandle, "show tcp pkt detail realtime", "display tcp pkt detail realtime", ifuncb_show_tcp_pkt_detail_realtime, NULL, 0, NULL);
	assert(0 == ret);	
}
#endif

void *packet_io_status_tcp_stream_mem_init(void)
{
	void *tcp_stream_mem;
	
	tcp_stream_mem = malloc(sizeof(packet_io_status_tcp_stream_t));
	memset(tcp_stream_mem, 0, sizeof(packet_io_status_tcp_stream_t));

	return tcp_stream_mem;
}

void packet_io_status_stream_update(int tid, UCHAR stream_type, UCHAR stream_state,  int action)
{
	if(STREAM_TYPE_TCP == stream_type){
		packet_io_status_tcp_stream_update(tid, stream_state, action);
	}else if(STREAM_TYPE_UDP == stream_type){
		/*  */
	}
}

static long ifuncb_show_tcp_stream_summary(iknow_handle ihandle, iknow_conn iconn, const void *cb_fun_arg, const char *cmd_args)
{
	iprintf(ihandle, iconn, "%9s %10s\n", " ", "stream-num"); 
	iprintf(ihandle, iconn, "%9s %10llu\n", "current", 
		  (g_cur_tcp_stream_status.create_by_syn_num+g_cur_tcp_stream_status.create_by_data_num+g_cur_tcp_stream_status.create_nouse_num)\
		   - (g_cur_tcp_stream_status.del_syn_num+g_cur_tcp_stream_status.del_data_num+g_cur_tcp_stream_status.del_nouse_num));
	iprintf(ihandle, iconn, "%9s %10llu/s\n", "rt-create", 	   
		  (g_realtime_tcp_stream_status.create_by_syn_num+g_realtime_tcp_stream_status.create_by_data_num+g_realtime_tcp_stream_status.create_nouse_num));
	iprintf(ihandle, iconn, "%9s %10llu\n/s", "rt-delete", 		  
		   (g_realtime_tcp_stream_status.del_syn_num+g_realtime_tcp_stream_status.del_data_num+g_realtime_tcp_stream_status.del_nouse_num));

	return 0;
}

void packet_io_status_tcp_stream_time_cb(void)
{
	int i;
	packet_io_status_tcp_stream_t *p_tcp_stream;

	memcpy((void *)&g_last_tcp_stream_status, (void *)&g_cur_tcp_stream_status, sizeof(packet_io_status_tcp_stream_t));
	memset((void *)&g_cur_tcp_stream_status, 0, sizeof(packet_io_status_tcp_stream_t));

	for(i = 0; i < g_packet_io_thread_num; i++){
		p_tcp_stream = (packet_io_status_tcp_stream_t *)(g_packet_io_status_pool[i]->packet_io_status[IO_STATUS_TCP_STREAM]);
		g_cur_tcp_stream_status.create_by_syn_num += p_tcp_stream->create_by_syn_num;
		g_cur_tcp_stream_status.create_by_data_num += p_tcp_stream->create_by_data_num;
		g_cur_tcp_stream_status.create_nouse_num += p_tcp_stream->create_nouse_num;
		g_cur_tcp_stream_status.del_syn_num += p_tcp_stream->del_syn_num;
		g_cur_tcp_stream_status.del_data_num += p_tcp_stream->del_data_num;
		g_cur_tcp_stream_status.del_nouse_num += p_tcp_stream->del_nouse_num;

		/* calc realtime */
		g_thread_realtime_tcp_stream_status[i].create_by_syn_num = p_tcp_stream->create_by_syn_num - g_thread_last_tcp_stream_status[i].create_by_syn_num;
		g_thread_realtime_tcp_stream_status[i].create_by_data_num = p_tcp_stream->create_by_data_num - g_thread_last_tcp_stream_status[i].create_by_data_num;
		g_thread_realtime_tcp_stream_status[i].create_nouse_num = p_tcp_stream->create_nouse_num - g_thread_last_tcp_stream_status[i].create_nouse_num;
		g_thread_realtime_tcp_stream_status[i].del_syn_num = p_tcp_stream->del_syn_num - g_thread_last_tcp_stream_status[i].del_syn_num;
		g_thread_realtime_tcp_stream_status[i].del_data_num = p_tcp_stream->del_data_num - g_thread_last_tcp_stream_status[i].del_data_num;
		g_thread_realtime_tcp_stream_status[i].del_nouse_num = p_tcp_stream->del_nouse_num - g_thread_last_tcp_stream_status[i].del_nouse_num;

		/* save last */
		g_thread_last_tcp_stream_status[i].create_by_syn_num = p_tcp_stream->create_by_syn_num;
		g_thread_last_tcp_stream_status[i].create_by_data_num = p_tcp_stream->create_by_data_num;
		g_thread_last_tcp_stream_status[i].create_nouse_num = p_tcp_stream->create_nouse_num;
		g_thread_last_tcp_stream_status[i].del_syn_num = p_tcp_stream->del_syn_num;
		g_thread_last_tcp_stream_status[i].del_data_num = p_tcp_stream->del_data_num;
		g_thread_last_tcp_stream_status[i].del_nouse_num = p_tcp_stream->del_nouse_num;
	}

	g_realtime_tcp_stream_status.create_by_syn_num = g_cur_tcp_stream_status.create_by_syn_num -g_last_tcp_stream_status.create_by_syn_num;
	g_realtime_tcp_stream_status.create_by_data_num = g_cur_tcp_stream_status.create_by_data_num -g_last_tcp_stream_status.create_by_data_num;
	g_realtime_tcp_stream_status.create_nouse_num = g_cur_tcp_stream_status.create_nouse_num -g_last_tcp_stream_status.create_nouse_num;
	g_realtime_tcp_stream_status.del_syn_num = g_cur_tcp_stream_status.del_syn_num -g_last_tcp_stream_status.del_syn_num;
	g_realtime_tcp_stream_status.del_data_num = g_cur_tcp_stream_status.del_data_num -g_last_tcp_stream_status.del_data_num;
	g_realtime_tcp_stream_status.del_nouse_num = g_cur_tcp_stream_status.del_nouse_num -g_last_tcp_stream_status.del_nouse_num;
}

#if IKNOW_ENABLE
void iknow_register_tcp_stream_cb(void *ihandle)
{
	int ret;

	ret = iknow_register_cmd(ihandle, "show tcp stream summary", "display tcp stream summary", ifuncb_show_tcp_stream_summary, NULL, 0, NULL);
	assert(0 == ret);
	//ret = iknow_register_cmd(ihandle, "show tcp stream detail total", "display tcp stream detail total", ifuncb_show_tcp_stream_detail, NULL, 0, NULL);
	//assert(0 == ret);	
	//ret = iknow_register_cmd(ihandle, "show tcp stream detail realtime", "display tcp stream detail realtime", ifuncb_show_tcp_stream_detail, NULL, 0, NULL);
	//assert(0 == ret);		
}
#endif
#endif


static void tcp_flow_stat_free(int thread_seq, void *project_req_value)
{
	dictator_free(thread_seq, project_req_value);
	return;
}


/* 2015-12-25 lijia add, for TCP/UDP����ͳ�� */
int tcp_flow_stat_init(void)
{
	int project_req_id;
	
	project_req_id = project_producer_register(PROJECT_REQ_TCP_FLOW, "struct", tcp_flow_stat_free);
	if(project_req_id >= 0){
		G_TCP_FLOW_STAT_PROJECT_ID = project_req_id;
	}else{
		/* �����ļ�û��'tcp_flow_stat'��, �رմ˹��� */
		G_TCP_FLOW_STAT_PROJECT_ID = -1;
	}

	project_req_id = project_producer_register(PROJECT_REQ_TCP_DEDUCE_FLOW, "struct", tcp_flow_stat_free);
	if(project_req_id >= 0){
		G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = project_req_id;
	}else{
		/* �����ļ�û��'tcp_flow_stat'��, �رմ˹��� */
		G_TCP_DEDUCE_FLOW_STAT_PROJECT_ID = -1;
	}
	
	return 0;
}

#ifdef __cplusplus
}
#endif

