#ifndef __FAKE_INTERFACE_H__
#define __FAKE_INTERFACE_H__
//#include "ace/OS.h"

#ifdef __cplusplus
extern "C" {
#endif	

#define ETH_P_IP 0x0800
#define PROTO_TCP 0x06
#define PROTO_UDP 0x11

#define MAX_QUEUE_COUNT 	16
#define MAX_SKB_QUEUE_LENGTH	10000
#define MAX_FLOW_QUEUE_LENGTH	100000


struct RawShotAddr
{
	
unsigned int srcIp;
	
unsigned int dstIp;
	
unsigned short srcPort;
	
unsigned short dstPort;
	
unsigned char proto;
	
unsigned char srcNation;			//源IP国家码
	
unsigned char dstNation;			//目的IP国家码
	
unsigned char allRecvShotType;		//全收中标类型
	
unsigned short srcShotType;			//原始报文的中标类型，源方向
	
unsigned short dstShotType;			//原始报文的中标类型，目的方向
	
unsigned long jiffies;              //jiffie值

};

//规则过滤的对象：流信息或者原始报文
enum TargetType
{
	TARGET_FLOWINFO = 1,				//过滤流信息
	TARGET_RAWDATA = 2					//过滤原始报文
};

//正向过滤规则优先级
enum RecordPriority
{
	RECORD_PRIORITY_LOW	= 1,			//低优先级
	RECORD_PRIORITY_HIGH = 2			//高优先级
};

/*接口通用返回值：
 * 		0：执行成功
 * 		-1：参数错误
 * 		-2：进程pid不符合调用条件
 * 		-3：资源分配失败
 * 		-4：系统调用失败
 * 		-5：内核未初始化
 * 		其余正值：执行正常，但未完成请求操作，具体原因见接口返回值介绍。
 * 		其余负值：执行异常，具体原因见接口返回值介绍。
 */


/*绑定全收规则
返回值：
*/	
int BindAllRecvRule(enum TargetType targetType, enum RecordPriority recordPriority);

/*解绑定全收规则
返回值：
*/
int UnbindAllRecvRule(enum TargetType targetType, enum RecordPriority recordPriority);


/*创建采集任务
参数：
	queueCount：缓存队列个数
	bufLen：每个收包缓冲的长度（注意：不是队列的长度！）
返回值：
*/
int CreateRawDataTask(unsigned int queueCount, unsigned int bufLen);


/*销毁任务，销毁规则与缓存数据
返回值：
*/
int CloseRawDataTask();

/*从指定的原始报文queue上收取原始包，保存在recvBuf数组中，每个报文的对应信息保存在rawShotAddr中，
  requestCount表示recvBuf的个数，recvCount保存实际收取的报文个数。
返回值：
	1：未获取数据，因为没有数据中标
*/
int RecvRawData(unsigned int queueId, char* recvBuf[], unsigned int recvBufLen[], struct RawShotAddr rawShotAddr[], int requestCount, int* recvCount);

#ifdef __cplusplus
}
#endif	

#endif

