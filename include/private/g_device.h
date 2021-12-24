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

/* State Machine
                             +--+
                             |  | UP, ADMIN DOWN, TIMER
                             |  V
                     DOWN  +------+  INIT
              +------------|      |------------+
              |            | DOWN |            |
              |  +-------->|      |<--------+  |
              |  |         +------+         |  |
              |  |                          |  |
              |  |               ADMIN DOWN,|  |
              |  |ADMIN DOWN,          DOWN,|  |
              |  |TIMER                TIMER|  |
              V  |                          |  V
            +------+                      +------+
       +----|      |                      |      |----+
   DOWN|    | INIT |--------------------->|  UP  |    |INIT, UP
       +--->|      | INIT, UP             |      |<---+
            +------+                      +------+
*/

#define BFD_MSG_FLAGS_ADMIN_DOWN 0x00
#define BFD_MSG_FLAGS_DOWN 0x01
#define BFD_MSG_FLAGS_INIT 0x02
#define BFD_MSG_FLAGS_UP 0x03

typedef struct{
    unsigned char version_diag;
#if __BYTE_ORDER == __LITTLE_ENDIAN    
    unsigned char flags:6;
    unsigned char state:2;
#elif __BYTE_ORDER == __BIG_ENDIAN    
    unsigned char state:2;
    unsigned char flags:6;
#endif

    unsigned char detect_time_multiplier;
    unsigned char length;
    unsigned char my_discriminator[4]; /* 业务号, 猜测? */
    unsigned char your_discriminator[4];
    unsigned char desired_min_tx_interval[4];
    unsigned char required_min_rx_interval[4];
    unsigned char required_min_echo_interval[4];
}bfd_header_t;  /* 9.7.5 */

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

