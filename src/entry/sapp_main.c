#include "sapp_api.h"
#include "sapp_private_api.h"

#ifdef __cplusplus
extern "C" {
#endif



int main(int argc, char *argv[])
{	
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

