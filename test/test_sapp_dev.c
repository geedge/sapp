#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int libsapp_setup_env(int argc, char *argv[]);

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