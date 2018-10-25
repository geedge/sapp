#ifndef _GDEV_H_
#define _GDEV_H_

#ifdef __cplusplus
extern "C" {
#endif

/* 特殊设备保活协议类型 */
#define GDEV_KEEPALIVE_TYPE_ICMP  (1)
#define GDEV_KEEPALIVE_TYPE_ARP   (2)
#define GDEV_KEEPALIVE_TYPE_BFD   (3)

/* 特殊设备使用的保活协议 */
#define BFD_DEFAULT_PORT	(3784) /* 默认端口 */
typedef struct{
    unsigned char version_diag;
    unsigned char flags;
    unsigned char detect_time_multiplier;
    unsigned char length;
    unsigned char my_discriminator[4];
    unsigned char your_discriminator[4];
    unsigned char desired_min_tx_interval[4];
    unsigned char required_min_rx_interval[4];
    unsigned char required_min_echo_interval[4];
}bfd_header_t;

/* return value:
 * 	>0: is gdev keepalive pkt;
 * 	0: not gdev keepalive pkt;
 * 	-1: error; 			
 */
int gdev_keepalive(const raw_pkt_t *raw_pkt, int thread_id, int keepalive_type,unsigned char dir);
int gdev_check_pkt(int addr_type, void *pkt_data);

#ifdef __cplusplus
}
#endif

#endif

