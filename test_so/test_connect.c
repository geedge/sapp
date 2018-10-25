#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "stream_base.h"
#include "stream_proxy.h"
#include "stream_entry.h"


char process_http_proxy_stream(struct streaminfo *pstream,struct streaminfo *pProxy,void * a_packet)
{
	int ret=APP_STATE_GIVEME;
	
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
	char *data=pdetail->pdata;	
	struct proxydetail*pProxydetail=NULL;

	pProxydetail=(struct proxydetail *)(pProxy->pdetail);
	//如果是首次进入
	if(pProxydetail==NULL)
	{
		pProxydetail=dictator_malloc(pstream->threadnum,sizeof(struct proxydetail));
		memset(pProxydetail,0,sizeof(struct proxydetail));
		pProxy->pdetail=pProxydetail;
	}
	
	if(pProxydetail->dealstate==PROXY_STATE_SEL)
	{
		//to do
		//获取代理地址信息
		//获取用户名密码
		pProxydetail->pUser=dictator_malloc(pstream->threadnum,10);
		memcpy(pProxydetail->pUser,"testliuqy",10);
		pProxydetail->uiUserLen=10;
	
		//处理完成自身的信息后
		if(memmem(data,pdetail->datalen,"\r\n\r\n",4)!=NULL)
		{
			pProxydetail->dealstate=PROXY_STATE_LINK_IN;
			//创建新流嵌套关系
			/* 2014-12-29 lijia add, 增加流类型标识, TODO:如果是socks怎么识别? 此函数应增加一个类型参数 */
			pProxy->type = STREAM_TYPE_HTTP_PROXY; 
			set_proxy_fstream(pstream,pProxy);
		}
	}
	else if(pProxydetail->dealstate==PROXY_STATE_LINK_IN)
	{
		ret=deal_tcp_in_proxy_stream(pstream,a_packet,pProxy);
	}
	
	return ret;
	
}

char deal_http_proxy_stream(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
		struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;

		struct streaminfo *pProxy=NULL;
		int ret=APP_STATE_GIVEME;
		if(pstream->opstate== OP_STATE_PENDING)
		{
			
			//代理识别，识别命中后，分配空间
			//识别待完善
			if(( pdetail->datalen >=8)&&
				( (memcmp(pdetail->pdata, "connect ", 8) == 0 )
				|| (memcmp(pdetail->pdata, "CONNECT ", 8) == 0 )))
			{
				
				pProxy=dictator_malloc(pstream->threadnum,sizeof(struct streaminfo));
				memset(pProxy,0,sizeof(struct streaminfo));
				(*pme)=pProxy;
				return process_http_proxy_stream(pstream,pProxy,a_packet);
			}
			else
			{
				return APP_STATE_DROPME;
			}
	
		
		}
		else if(pstream->opstate== OP_STATE_DATA)
		{
			
			pProxy=(struct streaminfo *)(*pme);
			ret=process_http_proxy_stream(pstream,pProxy,a_packet);
			if(ret==APP_STATE_DROPME)
			{
				free_tcp_proxy_stream(pstream,pProxy);
				(*pme)=NULL;
			}
		}
		if(pstream->opstate== OP_STATE_CLOSE)
		{	
			if((*pme)!=NULL)
			{
				pProxy=(struct streaminfo *)(*pme);
				pProxy->opstate=OP_STATE_CLOSE;
				ret=process_http_proxy_stream(pstream,pProxy,a_packet);
				free_tcp_proxy_stream(pstream,pProxy);
				(*pme)=NULL;
			}	
		}
		return ret;
	}


char TCP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return deal_http_proxy_stream(a_tcp,pme,thread_seq,a_packet);
}

int CHAR_DESTROY(void)
{
	return 0;
}

int CHAR_INIT()
{
	int demo_plugid = 51;
	printf("test_connect init ok!!!!!!!!!!!!\n");
//  函数实现自定义
//  只要求函数返回值为插件ID；
	
	return demo_plugid;
}
void TEST_GET_PLUGID(unsigned short plugid)
{
	printf("proto id is %d\n",plugid);
}

long long TEST_FLAG_CHANGE(char* flag_str)
{
	return 0;
}
void TEST_PROT_FUNSTAT (long long protflag)
{
	return ;
}

