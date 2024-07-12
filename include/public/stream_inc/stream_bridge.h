#ifndef _SAPP_STREAM_BRIDGE_H_
#define _SAPP_STREAM_BRIDGE_H_ 

#ifdef __cplusplus
extern "C" {
#endif


/*****************************************   stream bridge API   *************************************************

            -------------------
            |   streaminfo    |   plug X
            |-----------------| /
   plug A-->|bridge1 -> data1 |/--plug Y
            |-----------------|\
            |bridge2 -> data2 | \ plug Z
            |-----------------|
            |bridge3 -> data3 |
            -------------------

            

        	 -------------------- plug X
             |                  /
    plug A ->|  bridge_id = 1  /--plug Y
             |                 \
             |                  \ plug Z 
             --------------------

*******************************************************************************************************************/


/* 
    bridge_name: unique name
	
        "r": read only; 
        "w": bridge_name is write only; 
        
        >=0 : success
         <0 : error
*/
int stream_bridge_build(const char *bridge_name, const char *rw_mode);

struct streaminfo;
typedef void stream_bridge_free_cb_t(const struct streaminfo *stream, int bridge_id, void *data);
typedef int  stream_bridge_sync_cb_t(const struct streaminfo *stream, int bridge_id, void *data);


/* 
    free cb wille be overwrites by new free cb, if call register more than one time.
*/
int stream_bridge_register_data_free_cb(int bridge_id, stream_bridge_free_cb_t *free_cb_fun);

/* every sync_cb will be trigger when stream_bridge_sync_data_put() being called */
int stream_bridge_register_data_sync_cb(int bridge_id, stream_bridge_sync_cb_t *sync_cb_fun);

/*
        0: without stream_bridge_sync_cb_t;
        -1: error
        N: number of stream_bridge_sync_cb_t being called;
*/
int   stream_bridge_sync_data_put(const struct streaminfo *stream, int bridge_id, void *data);

/* equal to project_req_add_xxx */
int   stream_bridge_async_data_put(const struct streaminfo *stream, int bridge_id, void *data); 

/* 
        Not NULL: put data.
        NULL: if return NULL, need to get errno, if errno == ENODATA (61), means bridge not exist. 
*/
void *stream_bridge_async_data_get(const struct streaminfo *stream, int bridge_id);  


#ifdef __cplusplus
}
#endif

#endif

