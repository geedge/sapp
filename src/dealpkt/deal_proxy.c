/*

*/
#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct streaminfo *skip_proxy_phony_stream(struct streaminfo *a_tcp);
extern int udp_stream_table_size;

/*
20141017 : lqy
1)  �½�deal_proxy_stream ���ô���sock4,5,http�Ĺ�����������
2) ģ��һ��stream �γ����Ƶ�α��pstream->pPrxoy->fstream
20150123 lqy
1) ���´����ĵ�ַ˳����Ƕ����ʱ��ʹ�������ַ��ʵ�ʵ�ַ�Ͷ˿�
    �����п���ΪCONNECT pop.163.com:110 ����ģʽ�£���ַ�����0.0.0.0


*/


/*�ص��ϲ���Ϣ���ͷŴ�������������Ϣ*/
void free_tcp_proxy_stream(struct streaminfo *pstream,struct streaminfo *pProxy)
{
	if (pProxy == NULL)
	{
		return;
	}
	UCHAR saved_opstate;
	struct proxydetail *pProxydetail=(struct proxydetail *)pProxy->pdetail;
	int threadnum=pstream->threadnum;

	


	//�Ȼص����ܴ��ڵ�Ӧ�ò�
	if(pProxydetail->apme!=NULL)
	{
		pProxy->opstate=OP_STATE_CLOSE;
		saved_opstate = pstream->opstate;
		pstream->opstate = OP_STATE_CLOSE;/* 20160928 lijia add, ���ô�����������״̬ */
		//tcp stream �ص�
		stream_process_tcp(pstream,NULL,NULL,NULL,&(pProxydetail->apme),&(pProxy->opstate));  
		pProxydetail->apme=NULL;
		pstream->opstate = saved_opstate; /* 20160928 lijia add, �ָ���ǰ��״̬ */
	}

	
	//�ڶ��� �ͷ�
	
	pProxydetail=(struct proxydetail *)pProxy->pdetail;
	if(pProxydetail->pUser)
	{
		dictator_free(threadnum,pProxydetail->pUser);
		pProxydetail->pUser = NULL;
	}
	
	if(pProxydetail->pPwd)
	{
		dictator_free(threadnum,pProxydetail->pPwd);
		pProxydetail->pPwd = NULL;
	}
	
	if(pProxydetail->pIpv6) 
	{
		dictator_free(threadnum,pProxydetail->pIpv6);
		pProxydetail->pIpv6 = NULL;
	}
	
	if(pProxydetail->append)
	{
		dictator_free(threadnum,pProxydetail->append);
		pProxydetail->append = NULL;
	}	

	 if(pProxy->addr.paddr!=NULL)
	 {
		 dictator_free(threadnum,pProxy->addr.paddr);
		 pProxy->addr.paddr=NULL;
	 }
	 
	 if(pProxy->pdetail != NULL)
	 {
		 dictator_free(threadnum,pProxy->pdetail);
		 pProxy->pdetail=NULL;
	 }
	 
	 dictator_free(threadnum,pProxy);
	 pProxy = NULL;

}


/*��һ����������Ϣ�����һ��fatherstream,���ҹ��ص�stream��*/

void set_proxy_fstream(struct streaminfo *pstream,struct streaminfo *pProxy)
{
		void *paddr=NULL;
		struct proxydetail *pProxydetail=(struct proxydetail *)pProxy->pdetail;
	        struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;		

		//������������ͼ���ַ��Ϣ

		if(pstream->addr.addrtype==ADDR_TYPE_IPV4)
		{
			pProxy->addr.addrtype=ADDR_TYPE_IPV4;
			paddr=dictator_malloc(pstream->threadnum,sizeof(struct tuple4));
			memcpy(paddr,pstream->addr.paddr,sizeof(struct tuple4));
			((struct tuple4 *)paddr)->daddr=pProxydetail->uiIP;
			((struct tuple4 *)paddr)->dest=pProxydetail->uiPort;
		}
		if(pstream->addr.addrtype==ADDR_TYPE_IPV6)
		{
			pProxy->addr.addrtype=ADDR_TYPE_IPV6;
			paddr=dictator_malloc(pstream->threadnum,sizeof(struct tuple6));
			memcpy(paddr,pstream->addr.paddr,sizeof(struct tuple6));
			if(NULL == pProxydetail->pIpv6){ /* 2015-02-02 lijia add, �п��ܻ�ȡ���� */
				//printf("proxy type:%d, not fill addr info!\n", pProxydetail->iType);
				memset(((struct tuple6 *)paddr)->daddr,0,16);
			}else{
				memcpy(((struct tuple6 *)paddr)->daddr,pProxydetail->pIpv6,16);
			}
			((struct tuple6 *)paddr)->dest=pProxydetail->uiPort;
		}

		pProxy->addr.paddr=paddr;
		pProxy->pktstate=OP_STATE_PENDING;	
		pProxy->opstate=OP_STATE_PENDING;
		pProxydetail->serverpktnum=pdetail->serverpktnum;	
		pProxydetail->clientpktnum=pdetail->clientpktnum;
		pProxydetail->serverbytes=pdetail->serverbytes;
		pProxydetail->clientbytes=pdetail->clientbytes;
		pProxy->threadnum = pstream->threadnum;
				
		return;
	
}

/*��������������Ϣ������ɺ󣬽���Ƕ�׵���*/
int deal_tcp_in_proxy_stream(struct streaminfo *stream,void * a_packet,struct streaminfo *pProxy)
{
	int ret=PASS;
	int appstate=APP_STATE_GIVEME;
	struct proxydetail *pProxydetail=(struct proxydetail *)pProxy->pdetail;
	char tmpstate=stream->opstate;
	void *paddr=NULL;
	UCHAR addrtype;
	struct streaminfo_private *stream_pr = (struct streaminfo_private *)stream;
	raw_pkt_t *real_raw_pkt = (raw_pkt_t *)stream_pr->raw_pkt;

	if(STREAM_TYPE_TCP == stream->type){
		struct tcpdetail *pdetail=(struct tcpdetail *)stream->pdetail;
		//struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)stream->pdetail;		
		pdetail->serverpktnum-=pProxydetail->serverpktnum;	
		pdetail->clientpktnum-=pProxydetail->clientpktnum;
		pdetail->serverbytes-=pProxydetail->serverbytes;
		pdetail->clientbytes-=pProxydetail->clientbytes;
	
	}else if(STREAM_TYPE_UDP == stream->type){
		struct udpdetail *pdetail=(struct udpdetail *)stream->pdetail;
		//struct udpdetail_private *pdetail_pr=(struct udpdetail_private *)stream->pdetail;		
		pdetail->serverpktnum-=pProxydetail->serverpktnum;	
		pdetail->clientpktnum-=pProxydetail->clientpktnum;
		pdetail->serverbytes-=pProxydetail->serverbytes;
		pdetail->clientbytes-=pProxydetail->clientbytes;		
	}else{
		assert(0);
	}

#if 0
	struct streaminfo_private *carry_ip_stream = (struct streaminfo_private *)skip_proxy_phony_stream(pProxy->pfather);	
	if(NULL == carry_ip_stream){
		sapp_runtime_log(RLOG_LV_FATAL, "too many proxy layer, maybe recur infinitely!\n");
		return APP_STATE_GIVEME;
	}
#else
	struct streaminfo_private *carry_ip_stream = stream_pr; /* IP-PORT�洢��ͬһ��, ����Ҫͨ��pfather���� */
#endif
	
	//�������Ӷ�Ӧ��ϵ��ʹ����α���������Ч
	pProxy->pfather=stream->pfather;
	stream->pfather=pProxy;    
	

	//add by lqy 2 0150123
	addrtype=stream->addr.addrtype;
	stream->addr.addrtype=pProxy->addr.addrtype;
	pProxy->addr.addrtype=addrtype;
	paddr=stream->addr.paddr;
	stream->addr.paddr=pProxy->addr.paddr;
	pProxy->addr.paddr=paddr;
	//end add
	
	stream->opstate=pProxy->opstate;

	if(NULL == real_raw_pkt){ /* ��ʱ��̭, ��ԭʼ������ */
		ret=stream_process_tcp(stream, NULL, NULL, NULL, 
							&pProxydetail->apme,&(stream->opstate));	

	}else{
		ret=stream_process_tcp(stream,
							(const void *)((char *)real_raw_pkt->raw_pkt_data + carry_ip_stream->offset_to_raw_pkt_hdr),	
							(const void *)((char *)real_raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr),		
							(const raw_pkt_t *)real_raw_pkt, &pProxydetail->apme,&(stream->opstate));	
	}							
	pProxy->opstate=stream->opstate;
	//��ԭ״̬
	stream->opstate=tmpstate;
	
	stream->pfather=pProxy->pfather;
	//add by lqy 2 0150123
	addrtype=stream->addr.addrtype;
        stream->addr.addrtype=pProxy->addr.addrtype;
        pProxy->addr.addrtype=addrtype;
        paddr=stream->addr.paddr;
        stream->addr.paddr=pProxy->addr.paddr;
        pProxy->addr.paddr=paddr;	

	if(STREAM_TYPE_TCP == stream->type){
		struct tcpdetail *pdetail=(struct tcpdetail *)stream->pdetail;
		//struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)stream->pdetail;		
		
		pdetail->serverpktnum+=pProxydetail->serverpktnum;	
		pdetail->clientpktnum+=pProxydetail->clientpktnum;
		pdetail->serverbytes+=pProxydetail->serverbytes;
		pdetail->clientbytes+=pProxydetail->clientbytes;
	}else if(STREAM_TYPE_UDP == stream->type){
		struct tcpdetail *pdetail=(struct tcpdetail *)stream->pdetail;
		//struct tcpdetail_private *pdetail_pr=(struct tcpdetail_private *)stream->pdetail;	
		
		pdetail->serverpktnum+=pProxydetail->serverpktnum;	
		pdetail->clientpktnum+=pProxydetail->clientpktnum;
		pdetail->serverbytes+=pProxydetail->serverbytes;
		pdetail->clientbytes+=pProxydetail->clientbytes;
	}else{
		assert(0);
	}
	
	if(ret==DROP)
	{
		appstate|=APP_STATE_DROPPKT;
	}
	
	if(pProxydetail->apme==NULL)
	{
		appstate|=APP_STATE_DROPME;
	}

	if(OP_STATE_CLOSE == stream->opstate){
		appstate|= APP_STATE_DROPME;
	}
	
	return appstate;
}

#ifdef __cplusplus
}
#endif

