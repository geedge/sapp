#ifndef _PLUGIN_BUSINESS_H
#define _PLUGIN_BUSINESS_H


typedef struct _plugin_business_plug_info
{
	unsigned short plugid;
	char* plugname;
	void* filepoint;	
	void  (*fun_destroy)();	
	int (*fun_update)(int plugid,int fileflag,char*tablefile_name, char* path);		
	struct _plugin_business_plug_info* pre;
	struct _plugin_business_plug_info* next;

}stBusinessPlugInfo;


void init_pluginfo_elem_bus(stBusinessPlugInfo** business_plug_info);
void destroy_pluginfo_elem_bus(stBusinessPlugInfo* plug_info);
int plugin_load_business(char* filename);
int process_confelem_business(char* confelem_filename);



#endif
