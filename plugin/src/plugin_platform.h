#ifndef _PLUGIN_PLATFORM_H
#define _PLUGIN_PLATFORM_H

#define FILENAME_STEWARD		"./plug/platform/steward.so"

int plugin_load_platform(char* filename);
int process_confelem_platform(char* confelem_filename);

#endif
