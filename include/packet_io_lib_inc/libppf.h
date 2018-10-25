


#ifndef __LIBPPF2_H__
#define __LIBPPF2_H__

#include <linux/types.h>

#define ZYWK_ACT_DROP 0x80000000
#define ZYWK_ACT_PASS 0


#define ZYWK_TAG_NONE 0
#define ZYWK_TAG_WHITE 1
#define ZYWK_TAG_BLACK 2
#define ZYWK_TAG_BLOCK 3
#define ZYWK_TAG_MONIT 4

//p2p flags for payload filt
#define IPP2P_EDK               (1 << 1)
#define IPP2P_DATA_KAZAA        (1 << 2)
#define IPP2P_DATA_EDK          (1 << 3)
#define IPP2P_DATA_DC           (1 << 4)
#define IPP2P_DC                (1 << 5)
#define IPP2P_DATA_GNU          (1 << 6)
#define IPP2P_GNU               (1 << 7)
#define IPP2P_KAZAA             (1 << 8)
#define IPP2P_BIT               (1 << 9)
#define IPP2P_APPLE             (1 << 10)
#define IPP2P_SOUL              (1 << 11)
#define IPP2P_WINMX             (1 << 12)
#define IPP2P_ARES              (1 << 13)
#define IPP2P_MUTE              (1 << 14)
#define IPP2P_WASTE             (1 << 15)
#define IPP2P_XDCC              (1 << 16)

//action for payload filt
#define ACTION_PASS 0
#define ACTION_DROP 1
#define ACTION_FILT 2

//tag for payload filt
#define ZYWK_TAG_P2P 10

//////use function definations in libppf

#define DEBUG_PPF 0

#define DUM_CONF_FILE "dum.conf"


/////5-tuple rule 
struct zywk_rule
{
    __u32 sip,sip_mask;
    __u32 dip,dip_mask;
    __u16 sport,sport_mask;
    __u16 dport,dport_mask;

   
    __u32 protocol; 
    __u32 drop_tag;   //	drop action bit or tag
                      //	if MSB is set, DROP
                      //	if MSB is not set, deliver the packet upward with this tag;
    __u32 rid;		  //	rule id
    __u32 time_to_live;		//	in seconds
};

//open devices listed in file "dum.conf"
//if failed, return < 0
int ppf_open();

//close device with device id
void ppf_close();

//set user define packet dispathing function 
//without calling it, default hash function will be used
void ppf_setDispatchFunc(int (*DispatchFunc)(__u32 sip, __u32 dip));

//rebalance stream, some connetions in a thread maybe migrated to other threads
void ppf_setStreamBalance(int flag);

//set stream number 
//if failed, return < 0
int ppf_setStreamNum(int sn);

//recieve ad data block from zcp device, return no matter if there are packets
inline void *ppf_getDataBlock_no_Lock(int sid);

//return if there are packets, block otherwise
inline void *ppf_recvDataBlock(int sid);

//free a packet to zcp device
//return 1 if succeed, -1 if failed
inline int ppf_freeDataBlock(const void *pkt);

//retrieve the ip packet
inline void *ppf_getIPPacket(const void *pkt);

//retrieve the interface id of the ip
inline __u32 ppf_getIfId(const void *pkt);

inline __u64 ppf_getTimeStamp(const void *pkt);

inline __u32 ppf_getTag(const void *pkt);

inline __u32 ppf_getRuleID(const void *pkt);

inline __u32 ppf_getPktLength(const void *pkt);	

inline struct tuple5* ppf_getTuple5(const void *pkt);	

///////////filt interface /////////

//return -1 if buffer full, -2 the same rule exists, -3 other errors
inline int ppf_add_one_rule(const struct zywk_rule *prule);

//return -1 if buffer empty, -2 no such rule exists, -3 other errors
inline int ppf_del_one_rule(const struct zywk_rule *prule);

//set payload filt for p2p
//flag specifies what p2p software to filt
//act specifies what action should be taken
//if action is upward, tag will be marked
void set_p2p_filt(int flag, int act, int tag);




//send a packet pointed by ptr, with lenth len
//return 1 if succeed, -1 if failed
inline int ppf_SendPkt(char *pkt_data, uint pkt_len, uint fd);

//get a packet buffer from zcp device, used to fill and send packet
inline void *ppf_AllocTxBuf(uint fd);

//send out the packet get by ppf_AllocSub
//return 1 if succeed, -1 if failed
inline int ppf_SendBuf(void *buf, int len, uint fd);


#endif
