#include "sapp_api.h"
#include "sapp_private_api.h"

#ifndef __cplusplus
#error("This file must be compiled with c++ compiler!")
#endif

extern "C" int __MESA_rst_tcp_c(struct streaminfo *stream, unsigned char rst_th_flags, int rst_pkt_num, unsigned char snd_rst_dir, 
							unsigned short signature_seed1, unsigned short signature_seed2);

int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags, int rst_pkt_num, unsigned char dir, 
						unsigned short signature_seed1, unsigned short signature_seed2)

{
	return __MESA_rst_tcp_c(stream, th_flags, rst_pkt_num, dir, signature_seed1, signature_seed2);
}


int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags, int rst_pkt_num, unsigned char dir)
{
	return __MESA_rst_tcp_c(stream, th_flags, rst_pkt_num, dir,
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed1, 
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed2);		

}


int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags, int rst_pkt_num)
{
	return __MESA_rst_tcp_c(stream, th_flags, rst_pkt_num, DIR_DOUBLE,
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed1, 
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed2);		
}


int MESA_rst_tcp(struct streaminfo *stream, unsigned char th_flags)
{
	return __MESA_rst_tcp_c(stream, th_flags, 1, DIR_DOUBLE, 
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed1, 
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed2);	
}


int MESA_rst_tcp(struct streaminfo *stream)
{
	return __MESA_rst_tcp_c(stream, TH_RST|TH_ACK, 1, DIR_DOUBLE, 
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed1, 
							sapp_global_val->config.stream.tcp.inject.rst_signature_seed2);
}


