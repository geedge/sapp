#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include "MESA_sleep.h"

#define DEBUG 0
#define THREAD_NUM  (36)

void *mythread(void *param)
{
    int i;
    int no=*(int *)param;
    long timeused;
    struct timeval t1,t2;
    printf("%d\n",no);
    //for (i=0;i<9999;i++)
    while(1)
    {
        //printf("%d-%d\t", no, i);
#if 0
        usleep(1);
        /*pthread_mutex_lock(&mymutex[no]);
        pthread_cond_wait(&mycond[no],&mymutex[no]);
        pthread_mutex_unlock(&mymutex[no]);*/
#else    

#if DEBUG
    gettimeofday(&t1,NULL);
        MESA_sleep();
    gettimeofday(&t2,NULL);
    timeused=1000000*(t2.tv_sec-t1.tv_sec)+t2.tv_usec-t1.tv_usec;
    printf("%d: used time:%d us\n",no, timeused);
#else
        MESA_sleep();
#endif
#endif
    }
    pthread_exit(0);
    return NULL;
}

int main(void)
{
    printf("begin main thread.\n");
    int i;
    pthread_t tid[THREAD_NUM];

    for (i=0;i<THREAD_NUM;i++) 
    {
        pthread_create(&tid[i],NULL,mythread,(void *)&i);
        usleep(100);
    }

	while(1){
		pause();
	}
    void *res;
    for (i=0;i<THREAD_NUM;i++)
        pthread_join(tid[i], &res);
    printf("end main thread.\n");
    return 0;
}
