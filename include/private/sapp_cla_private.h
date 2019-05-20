#ifndef _SAPP_CLA_PRIVATE_H_
#define _SAPP_CLA_PRIVATE_H_ 1

#include "sapp_std.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef int args_legality_check_t(const char *opt_name, const char *opt_arg);

typedef struct{
	const char *long_opt_name;
	args_legality_check_t *check_fun;
	const char *usage;
}sapp_cmd_args_usage_t;


typedef struct{
	const char *long_opt_name;
	sapp_tlv_t arg_val;
}sapp_cmd_args_val_t; 



#ifdef __cplusplus
}
#endif


#endif

