#ifndef _PLUGIN_PLATFORM_H
#define _PLUGIN_PLATFORM_H


#ifdef __cplusplus
extern "C" {
#endif


int plugin_load_platform(void);
int process_confelem_platform(char* confelem_filename);

#ifdef __cplusplus
}
#endif


#endif
