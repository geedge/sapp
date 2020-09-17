#ifndef _SAPP_STATE_H_
#define _SAPP_STATE_H_ 1
#ifdef __cplusplus
extern "C" {
#endif

#if 0  //move to stream_control.h
enum sapp_state_t{
	SAPP_STATE_JUST_START, /* main() called by shell command */
	SAPP_STATE_CONFIG_PARSE,
	SAPP_STATE_PLATFORM_INITING,
	SAPP_STATE_PLATFORM_INITED,
	SAPP_STATE_PKT_IO_INITING,
	SAPP_STATE_PKT_IO_INITED,		
	SAPP_STATE_PLUG_INITING,
	SAPP_STATE_PLUG_INITED,	
	SAPP_STATE_PROCESSING,
	SAPP_STATE_READY_TO_EXIT, /* only for pcap dumpfile */
};
#endif

#ifdef __cplusplus
}
#endif

#endif

