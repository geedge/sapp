/*
 *  Description:
 *		平台公共hash函数, 
 *		基于隧道模式下, 既要处理协议本身的逻辑, 还要考虑是否在隧道内部, 及外层隧道地址.
 *
 *		例:
 *			在两个不同的L2tp隧道内, 有两个IP地址对通信, 1.1.1.1 <--> 1.1.1.2, 且有分片,
 *			在原平台中, 是无法区别这两类数据的, 会混淆在一起!
 *
 *		所以新建此模块, 将地址链表比较步骤封装起来.
 *		可用于基于隧道的IPv4, IPv6分片重组, TCP, UDP流还原等模块.
 *
 *
 *  Author:    Li Jia<lijia@nismail.iie.ac.cn>
 *  Date:      2014-07-17
 *  Version:   0.1
 */
#include <stdio.h> 
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif

