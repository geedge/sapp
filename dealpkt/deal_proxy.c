/*

*/
#include <assert.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "stream_manage.h"
#include "stream_internal.h"
#include "deal_ipv6.h"
#include "dealpkt.h"
#include "project_internal.h"
#include "MESA_handle_logger.h"
#include "sysinfo.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int gdev_keepalive(unsigned char *data, int len, int thread_id, int pro_type);
extern struct streaminfo *skip_proxy_phony_stream(struct streaminfo *a_tcp);
extern int udp_stream_table_size;
extern unsigned short udp_reset_time;

/*
20141017 : lqy
1)  新建deal_proxy_stream 适用处理sock4,5,http的公共处理函数
2) 模拟一层stream 形成类似的伪流pstream->pPrxoy->fstream
20150123 lqy
1) 更新代理的地址顺序，内嵌调用时，使用虚拟地址的实际地址和端口
    由于有可能为CONNECT pop.163.com:110 这种模式下，地址会出现0.0.0.0


*/


/*回调上层信息，释放代理保存的相关信息*/
void free_tcp_proxy_stream(struct streaminfo *pstream,struct streaminfo *pProxy)
{
	UCHAR saved_opstate;
	struct proxydetail *pProxydetail=(struct proxydetail *)pProxy->pdetail;
	int threadnum=pstream->threadnum;

	
	if(pProxy == NULL)
	{
		return;
	}

	//先回调可能存在的应用层
	if(pProxydetail->apme!=NULL)
	{
		pProxy->opstate=OP_STATE_CLOSE;
		saved_opstate = pstream->opstate;
		pstream->opstate = OP_STATE_CLOSE;/* 20160928 lijia add, 设置代理的流结束状态 */
		//tcp stream 回调
		stream_process_tcp(pstream,NULL,NULL,NULL,&(pProxydetail->apme),&(pProxy->opstate));  
		pProxydetail->apme=NULL;
		pstream->opstate = saved_opstate; /* 20160928 lijia add, 恢复当前流状态 */
	}

	
	//第二步 释放
	
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


/*把一个代理的信息虚拟成一个fatherstream,并且挂载到stream上*/

void set_proxy_fstream(struct streaminfo *pstream,struct streaminfo *pProxy)
{
		void *paddr=NULL;
		struct proxydetail *pProxydetail=(struct proxydetail *)pProxy->pdetail;
	        struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;		

		//填充代理层的类型及地址信息

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
			if(NULL == pProxydetail->pIpv6){ /* 2015-02-02 lijia add, 有可能获取不到 */
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

/*当代理自身的信息处理完成后，进行嵌套调用*/
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
	struct streaminfo_private *carry_ip_stream = stream_pr; /* IP-PORT存储于同一层, 不需要通过pfather查找 */
#endif
	
	//更新链接对应关系，使得新伪造的链接生效
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

	if(NULL == real_raw_pkt){ /* 超时淘汰, 无原始包参数 */
		ret=stream_process_tcp(stream, NULL, NULL, NULL, 
							&pProxydetail->apme,&(stream->opstate));	

	}else{
		ret=stream_process_tcp(stream,
							(const void *)((char *)real_raw_pkt->raw_pkt_data + carry_ip_stream->offset_to_raw_pkt_hdr),	
							(const void *)((char *)real_raw_pkt->raw_pkt_data + stream_pr->offset_to_raw_pkt_hdr),		
							(const raw_pkt_t *)real_raw_pkt, &pProxydetail->apme,&(stream->opstate));	
	}							
	pProxy->opstate=stream->opstate;
	//还原状态
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
		appstate=appstate|APP_STATE_DROPPKT;
	}
	
	if(pProxydetail->apme==NULL)
	{
		appstate=appstate|APP_STATE_DROPME;
	}

	if(OP_STATE_CLOSE == stream->opstate){
		appstate |= APP_STATE_DROPME;
	}
	
	return appstate;
}

#ifdef __cplusplus
}
#endif

