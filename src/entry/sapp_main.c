#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef HASP_ENABLED
#include "hasp_verify.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif



int main(int argc, char *argv[])
{
#ifdef HASP_ENABLED

#ifndef FEATURE_ID
#define FEATURE_ID 100
#endif
	hasp_verify(FEATURE_ID);
#endif
	if(libsapp_setup_env(argc,argv) < 0){
		return -1;
	}
	
	while(1){
		pause();
	}

	return 0;
}


#ifdef __cplusplus
}
#endif

