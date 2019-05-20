#ifndef _SAPP_DECLARATION_H_
#define _SAPP_DECLARATION_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "sapp_private_api.h"

int sapp_parse_cmd_args(int argc, char *argv[]);
int sapp_parse_config(void);
void sapp_generate_sample_config(void);
void sapp_cla_override_cfg_file(void);
void sapp_global_val_sanity_check(void);


extern sapp_global_t *sapp_global_val;

#ifdef __cplusplus
}
#endif


#endif

