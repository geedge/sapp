#ifndef _PLUGIN_PLATFORM_H
#define _PLUGIN_PLATFORM_H

#define FILENAME_STEWARD		"./plug/platform/steward.so"

#ifdef __cplusplus
extern "C" {
#endif


int plugin_load_platform(char* filename);
int process_confelem_platform(char* confelem_filename);

#ifdef __cplusplus
}
#endif


#endif
