#include "iknow.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

iknow_handle ihandle = NULL;
int print_fd = -1;

void test_immediate_cb(iknow_handle ihandle, int fd)
{
	iknow_print(ihandle, fd, "------------------\n");	
	iknow_print(ihandle, fd, "\t this is a immediate command.\n");
	iknow_print(ihandle, fd, "------------------\n");
	
}

void test_verbose_cb(iknow_handle ihandle, int fd)
{
	int ret;
	
	iknow_print(ihandle, fd, "\t this is a verbose command.\n");

	while(1){
		ret = iknow_print(ihandle, fd, "\t time now: %lu\n", time(NULL));
		if(ret < 0){
			return;
		}

		sleep(1);
	}
}


void test_redirect(iknow_handle ihandle, int fd)
{
	print_fd = fd;
}


void *process_thread(void *arg)
{
	int  ret;
	FILE *fp;
	int times = 0;
	
	while(1){
		/* do something */

#if 0	 /* 传统写日志方式 */
		fprintf(stderr,  "system running, %d!\n", times++);

		fp = fopen("test.log", "w+");
		fprintf(fp,  "system running, %d!\n", times++);
		fclose(fp);
#endif

		/* do something */

		ret = iknow_print(ihandle, print_fd, "%s:%d, xxx log, %d!\n", __FILE__, __LINE__, times++);
		if(ret < 0){
			print_fd = -1;
		}

		/* do something */
		
		ret = iknow_print(ihandle, print_fd, "%s:%d, yyy log, %d!\n", __FILE__, __LINE__, times++);
		if(ret < 0){
			print_fd = -1;
		}

		/* do something */
		
		ret = iknow_print(ihandle, print_fd, "%s:%d, zzz log, %d!\n", __FILE__, __LINE__, times++);
		if(ret < 0){
			print_fd = -1;
		}		

		sleep(1);
	}

	return NULL;
}

int main(void)
{
	pthread_t pid;

	pthread_create(&pid, NULL, process_thread, NULL);

	ihandle = iknow_create(14723); /* Iknow birthday is 14-07-23, ^_^ */
	if(NULL == ihandle){
		return -1;
	}

	iknow_register_immediate_cmd(ihandle, "show immediate", "test immediate cmd", test_immediate_cb);

	iknow_register_verbose_cmd(ihandle, "show verbose", "test verbose cmd", test_verbose_cb);

	iknow_register_global_flush_cmd(ihandle, "show all", "test global redirect", test_redirect);

	iknow_wait(ihandle);

	return 0;
}

