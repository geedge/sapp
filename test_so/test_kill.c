#include <stdlib.h>
#include "stream.h"
#include <stdio.h>

 typedef struct _stRuleKey
{    unsigned int uiRuleID;      
     unsigned int uiType;        
     int iLx;                    
     int iXz;                    
     unsigned int uiLength;      
     unsigned char* sKey;        
}__attribute__((packed))  tdRuleKey;

#define RTF_SSL   0x2B1   //ssl证书管控
#define LOG_SSL   24
extern int gfn_CScan_SearchMem_Expr(int iRuleType, char *data, int datalen, int begPos, int* pRuleType, tdRuleKey *ptdRuleKey, int *pFoundPostion, void **ppParam,int thread_num) ;
extern int logxjfdinfo(int threadid,struct tuple4 *paddr,int logtype,int ruleid,char *url,int urllen);
extern int logxjfdinfo_from_old(int threadid,struct tuple4 *paddr,int logtype,int ruleid,char *logcont,int contlen);

void kill_tcp_from_old(struct streaminfo *pstream);
 

char testtcpApp_2(struct streaminfo *pstream,void **pme, int thread_seq,void *a_packet)
{
	int iRuleTable=0;
	int iFoundPos=0;
	tdRuleKey rulekey;
	void *pScanMidAgent=NULL;//   用于保留扫描的中间结果	
	struct tcpdetail *pdetail=(struct tcpdetail *)pstream->pdetail;
	if(pstream->opstate== OP_STATE_PENDING)
	{
		//printf("%s ",printaddr(&(pstream->addr),        pstream->threadnum));
		//printf("hash index =%d \n",mkstreamhash(0,&(pstream->addr),250000));
			
	}
	else
	{
		rulekey.uiRuleID=0;
		if(pdetail->datalen>0)
		{
			gfn_CScan_SearchMem_Expr(RTF_SSL, pdetail->pdata, pdetail->datalen, 0,
								 &(iRuleTable), &(rulekey), &iFoundPos,&pScanMidAgent , pstream->threadnum);
		}
		if(rulekey.uiRuleID>0)
		{
			kill_tcp_from_old(pstream);
			logxjfdinfo_from_old(pstream->threadnum,pstream->addr.paddr,LOG_SSL,rulekey.uiRuleID,NULL,0);
		}

	}
	if(pstream->opstate== OP_STATE_CLOSE)
	{	
		printf("%s ",printaddr(&(pstream->addr),	pstream->threadnum));
		printf("opstate=%d,server pkt=%d, count=%d,client pkt=%d,count=%d, datalen=%d",pstream->opstate,pdetail->serverpkt,pdetail->servercount,
		pdetail->clientpkt,pdetail->clientcount,pdetail->datalen);
	
		printf("\n");
	}
        return APP_STATE_GIVEME;
}





char TCP_ENTRY(struct streaminfo *a_tcp,  void **pme, int thread_seq,void *a_packet)
{
	return testtcpApp_2(a_tcp,pme,thread_seq,a_packet);
}
/*
char IP_ENTRY( struct streaminfo *f_stream,unsigned char routedir,int thread_seq,struct ip * a_packet)
{
	return testIPApp_1(f_stream,routedir,thread_seq,a_packet);
}
*/
int CHAR_INIT()
{
	int demo_plugid = 51;

//  函数实现自定义
//  只要求函数返回值为插件ID；
	
	return demo_plugid;
}

