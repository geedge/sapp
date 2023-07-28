#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include "MESA_sleep.h"

#define MAXN 16
#define NUM_CON 4
pthread_mutex_t mymutex[MAXN]={PTHREAD_MUTEX_INITIALIZER};
pthread_cond_t mycond[MAXN] = {PTHREAD_COND_INITIALIZER};
pthread_mutex_t mod_mutex=PTHREAD_MUTEX_INITIALIZER;
int g_count=0;

void *wakeup_bg_thread(void *param)
{
    int i;
    while(1)
    {
        for (i=0;i<NUM_CON;i++)
        {
            if(pthread_cond_signal(&mycond[i])){
                printf("error\n");
                return NULL;
            }
        }
        usleep(1);
    }
    return NULL;
}

void *watch_bgt_thread(void *param)
{
    pthread_t tid=*(pthread_t *)param;
    while(1)
    {
        if (g_count==0)
        {
            pthread_cancel(tid);
        }
        sleep(10);
    }
    return NULL;
}

void MESA_sleep(void)
{
    static int hasBGT=0;//back ground thread
    pthread_t tid;
    static int no=0;
    int tmpno;
    if (hasBGT)
    {
        pthread_mutex_lock(&mod_mutex);
        g_count++;
        no=(no+1) % MAXN;
        tmpno=no;
        #if debug
        printf("no.:%d \n", no);
            printf("in sleep1: g_count=%d\n", g_count);
        #endif
        pthread_mutex_unlock(&mod_mutex);
    }
    else
    {
        pthread_mutex_lock(&mod_mutex);
        hasBGT=1;
        g_count=1;
        no=0;
        tmpno=0;
        pthread_create(&tid,NULL,wakeup_bg_thread,NULL);
        // pthread_create(&tid_watch,NULL,watch_bgt_thread,(void *)&tid);
        pthread_mutex_unlock(&mod_mutex);
        #if debug
            // puts("BGT watch created...");
            puts("BGT created...");
        #endif
    }

    pthread_mutex_lock(&mymutex[tmpno]);
    pthread_cond_wait(&mycond[tmpno % NUM_CON],&mymutex[tmpno]);
    pthread_mutex_unlock(&mymutex[tmpno]);

    pthread_mutex_lock(&mod_mutex);
    g_count--;
    #if debug
        printf("in sleep2: g_count=%d\n", g_count);
    #endif
    pthread_mutex_unlock(&mod_mutex);
}

