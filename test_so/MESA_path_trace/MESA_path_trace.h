#ifndef _MESA_PATH_TRACE_H_
#define _MESA_PATH_TRACE_H_
/*
    2016-01-20 LiJia create,
        便于排查在线环境CT问题, 终端发送一个带有特定标记的数据包,
        通过xx系统之后, 如果收到此标记包, 则记录一条日志,
        从而可以追踪到此二元组的分流路径.

        为了隐蔽此类包的特殊信息, 添加了随机数、移位、异或操作, 算法是拍脑袋想的, 无相关依据!
*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <netinet/ip.h>
#include <netinet/ip6.h>
#else
#include <QUdpSocket>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define MESA_PATH_TRACE_SRC_PORT		(43690) 		/* 源端口, 即0xAAAA, 主机序和网络序是相同的 */
#define MESA_PATH_TRACE_DST_PORT		(21845) 		/* 目标端口, 即0x5555, 主机序和网络序是相同的 */

#define MESA_PATH_TRACE_MAGIC		(0x4153454D)  /* MESA */

typedef struct{
    unsigned int random_shift; 	/* 用于控制位移 */
    unsigned int trick1; 			/* 垃圾数据1 */
    unsigned int magic1;		/* 正确性验证 */
    unsigned int ip_addr_type;	/* IP地址类型 */
    unsigned int trick2; 			/* 垃圾数据2 */
    unsigned int magic2;		/* 正确性验证 */
#ifdef __linux__
    char dst_ip_net_order[sizeof(struct in6_addr)];	/* 目标IP地址, 正确性验证 */
#else
    char dst_ip_net_order[sizeof(Q_IPV6ADDR)];	/* 目标IP地址, 正确性验证 */
#endif
    char __random_data[0]; 	/* 随机追加的负载, 无意义 */
}MESA_path_trace_t;


enum _ip_addr_type{
    MESA_TRACE_IPV4 = 4,
    MESA_TRACE_IPV6 = 6,
};

typedef struct{
    int ip_addr_type;	/* IP地址类型, 4 or 6 */
    union{
        unsigned int ipv4_dst; 		/* network order */
#ifdef __linux__
        struct in6_addr ipv6_dst; 	/* network order */
#else
        Q_IPV6ADDR ipv6_dst;
#endif
    };
}MESA_path_trace_addr_t;

static inline unsigned int rol32(unsigned int  word, unsigned int shift)
{
    return (word << shift) | (word >> (32 - shift));
}

static inline unsigned int ror32(unsigned int  word, unsigned int shift)
{
    return (word >> shift) | (word << (32 - shift));
}

/*
    参数说明:
        dstip_net_order: 数据包目标IP地址, 网络序;
        dstport_net_order: 数据包目标端口, 网络序;
        payload_buf: 执向udp负载的指针;
        payload_buf_max_len: udp负载最大可用长度;

    返回值:
        < 0: 错误;
        > 0:UDP负载的实际长度, <= payload_buf_max_len;
*/
static inline int MESA_path_trace_build_payload(MESA_path_trace_addr_t *dstip,
                char *payload_buf, int payload_buf_max_len, unsigned int random)
{
    unsigned int random_rl, random_rr;
    MESA_path_trace_t *ptrace_data;
    int i, actual_payload_len, expect_payload_len;
    char *ptr;

    if((NULL == payload_buf) || (payload_buf_max_len < (int)sizeof(MESA_path_trace_t))){
        return -1;
    }

    if((MESA_TRACE_IPV4 != dstip->ip_addr_type) && (MESA_TRACE_IPV6 != dstip->ip_addr_type)){
        return -1;
    }

    ptrace_data = (MESA_path_trace_t *)payload_buf;

    random_rl = rol32(random, (random&0xE) + 1);  /* 靠random_shift左移生成, 用于异或magic1, dst_ip_net_order */
    random_rr = ror32(random, ((random&0xE) >> 4) + 1);  /* 靠random_shift右移生成, 用于异或magic2 */

    ptrace_data->random_shift = random;
    ptrace_data->magic1 = MESA_PATH_TRACE_MAGIC ^ random_rl;
    ptrace_data->ip_addr_type = dstip->ip_addr_type ^ random_rl;

    ptrace_data->magic2 = MESA_PATH_TRACE_MAGIC ^ random_rr;

    ptrace_data->trick1 = rol32(random, (random&0x7) + 1) + 1234567;	/* trick */
    ptrace_data->trick2 = rol32(random, (random&0xF) + 3) + 7654321;	/* trick */

    if(MESA_TRACE_IPV4 == dstip->ip_addr_type){
        memcpy(ptrace_data->dst_ip_net_order, &dstip->ipv4_dst, sizeof(int));
        unsigned int *ipv4 = (unsigned int *)&ptrace_data->dst_ip_net_order[0];
        *ipv4 ^= random_rr;
#ifdef __linux__
        for(i = 4; i < (int)sizeof(struct in6_addr); i++){
            ptrace_data->dst_ip_net_order[i] = (char)((i ^ random_rr) * i); /* trick */
        }
#else
        for(i = 4; i < 16; i++){
            ptrace_data->dst_ip_net_order[i] = (char)((i ^ random_rr) * i); /* trick */
        }
#endif
    }else{
#ifdef __linux__
        memcpy(ptrace_data->dst_ip_net_order, &dstip->ipv6_dst, sizeof(struct in6_addr));
#else
        memcpy(ptrace_data->dst_ip_net_order, &dstip->ipv6_dst, sizeof(Q_IPV6ADDR));
#endif
        unsigned int *ipv6 = (unsigned int *)&ptrace_data->dst_ip_net_order[0];
        for(i = 0; i < 4; i++){
            *ipv6 ^= random_rr;
            ipv6++;
        }
    }

    expect_payload_len = sizeof(MESA_path_trace_t) + random % 256 + 32;

    if(payload_buf_max_len <= expect_payload_len){
        actual_payload_len = payload_buf_max_len;
    }else{
        actual_payload_len = expect_payload_len;
    }

    ptr = payload_buf + (int)sizeof(MESA_path_trace_t);
    for(i = (int)sizeof(MESA_path_trace_t); i < actual_payload_len; i++, ptr++){
        *ptr = (char )((random * (i+1)) ^ random); /* trick */
    }

    return actual_payload_len;
}


#ifdef __cplusplus
}
#endif

#endif
