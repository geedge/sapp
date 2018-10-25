
/*  Header file of new_l2fwd_lib in Load Balance Model.
 *  Autuor   :  Lu Qiuwen
 *  Date     :  2014-03-04
 */


#ifndef __L2FWD_LIB_INCLUDE__
#define __L2FWD_LIB_INCLUDE__

int dpdk_send_packet_dst(unsigned char *data, int datalen, int dst);
int dpdk_send_packet_port(const unsigned char *data, int datalen, int port);
int dpdk_init(int argc, char **argv);
int dpdk_run();
int dpdk_register_callfunc(int (*func)(const unsigned char *data,int datalen,int port_in,int lcore));
int dpdk_register_callfunc_dst(int (*func)(const unsigned char *data,int datalen,int dst,int lcore));


#endif
