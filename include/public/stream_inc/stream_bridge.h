#ifndef _SAPP_STREAM_BRIDGE_H_
#define _SAPP_STREAM_BRIDGE_H_ 

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>


/*****************************************   stream bridge API   *************************************************

   stream_bridge_xxx接口用于在不同插件之间, 创建一个通道, 支持同步和异步两种方式互相通信, 支持多对多的关系.
    
   同步模式采用callback注册方式, 避免直接使用extern声明函数, 动态、灵活、可扩展.
   异步模式是在streaminfo中保留一份数据, 功能同之前的project_req_xxx系列接口.
	
   假设插件plug A,X,Y,Z都注册同一个bridge name:"bridge_demo", bridge_id=1,

   plug A使用异步模式在streaminfo, bridge=1的空间存储了一份数据, receiver X,Y,Z可以在streaminfo生存周期内取数据.
            -------------------
            |   streaminfo    |   plug X
            |-----------------| /
   plug A-->|bridge1 -> data1 |/--plug Y
            |-----------------|\
            |bridge2 -> data2 | \ plug Z
            |-----------------|
            |bridge3 -> data3 |
            -------------------

            
    plugA发送一条同步消息, receiver X,Y,Z都可以依次收到.

        	 -------------------- plug X
             |                  /
    plug A ->|  bridge_id = 1  /--plug Y
             |                 \
             |                  \ plug Z 
             --------------------

*******************************************************************************************************************/


/* 
    bridge_name: 全局唯一, 与之前的project使用不同的命名空间, 可以重名, 
	             但是bridge_id与project_req_id不能通用!!!
	
    rw_mode类似fopen函数的参数, 只支持两个模式:
        "r": 只读,bridge_name不存在则返回错误; 
        "w": bridge_name不存在则创建一个新的bridge, 
             注意, 如果其他插件已经创建了同名bridge, 再次用"w"模式打开, 不能像fopen以截断模式重新打开一个文件, 其实bridge_id是一样的!
             建议先用"r"模式验证是否有无同名bridge; 
        
    返回值是bridge_id, 
        >=0 : success
         <0 : error
*/
int stream_bridge_build(const char *bridge_name, const char *rw_mode);


typedef void stream_bridge_free_cb_t(const struct streaminfo *stream, int bridge_id, void *data);
typedef int  stream_bridge_sync_cb_t(const struct streaminfo *stream, int bridge_id, void *data);


/* 
   注意: free函数最多只能有一个, 后面会覆盖前面的函数指针, 多次重复注册只保留最后一个!
*/
int stream_bridge_register_data_free_cb(int bridge_id, stream_bridge_free_cb_t *free_cb_fun);

/* sync回调函数可以是多个, 调用stream_bridge_sync_data_put()时, 会调用所有注册的callback函数 */
int stream_bridge_register_data_sync_cb(int bridge_id, stream_bridge_sync_cb_t *sync_cb_fun);

/*
    返回值:
        0: 没有stream_bridge_sync_cb_t函数;
        -1: error
        N: 成功调用stream_bridge_sync_cb_t函数的数量;
*/
int   stream_bridge_sync_data_put(const struct streaminfo *stream, int bridge_id, void *data);

/* 等同于之前的project_req_add_xxx, 注意如果data是malloc的内存, 要注册stream_bridge_free_cb_t, streaminfo在close时会自动free */
int   stream_bridge_async_data_put(const struct streaminfo *stream, int bridge_id, void *data); 

/* 
    返回值:
        非NULL: 插件曾经调用stream_bridge_async_data_put()存储的data值.
        NULL  : 此时会产生一种歧义, 如果stream_bridge_async_data_put()就是存了一个空指针, 或者利用C的特性, 存了一个整数0, 
                如何区别是错误还是原始数据就是0？

                如果返回值是NULL的情况下, 插件要再判断一下errno, errno == ENODATA (61), 说明确实没有插件曾经存储过数据, 是个错误. 
*/
void *stream_bridge_async_data_get(const struct streaminfo *stream, int bridge_id);  /* 等同于之前的project_get_xxx */


#ifdef __cplusplus
}
#endif

#endif

