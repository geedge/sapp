#ifndef __CCC_HDR_H
#define __CCC_HDR_H

#include <stdlib.h>
#include <stdint.h>

#define CCC_VERSION 0x24

/*
*  Msg CMD type
*/
#define CCC_CMD_AUTH           0x01
#define CCC_CMD_KEEPALIVE      0x02
#define CCC_CMD_DATA           0x03

/*
* MSG type
*/

#define CCC_CMD_AUTH_REQ      0x0101
#define CCC_CMD_AUTH_REP      0x0102
#define CCC_CMD_KEEPALIVE_REQ 0x0201
#define CCC_CMD_KEEPALIVE_REP 0x0202
#define CCC_CMD_FDATA_REQ     0x0301
#define CCC_CMD_FDATA_REP     0x0302
#define CCC_CMD_SDATA_REQ     0x0401
#define CCC_CMD_SDATA_REP     0x0402

/*
* Route info
*/


#define CCC_ROUTE_G 0x00
#define CCC_ROUTE_D 0x01
#define CCC_ROUTE_S 0x02


typedef struct {
#if __BYTE_ORDER == __BIG_ENDIAN
	union{
		struct{
			uint8_t sip_flag:1;
			uint8_t sipmsk_flag:1;
			uint8_t dip_flag:1;
			uint8_t dipmsk_flag:1;
			uint8_t sport_flag:1;
			uint8_t spmsk_flag:1;
			uint8_t dport_flag:1;
			uint8_t dpmsk_flag:1;
			uint8_t proto_flag:1;
			uint8_t pmsk_flag:1;
			uint8_t action:1;
			uint8_t ipv6:1;
			uint8_t durable:1;
			uint8_t resv:3; // must be zero
		};
		uint16_t rule_info;
	};
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	union{
		struct 
		{
			uint8_t dpmsk_flag:1;
			uint8_t dport_flag:1;
			uint8_t spmsk_flag:1;
			uint8_t sport_flag:1;
			uint8_t dipmsk_flag:1;
			uint8_t dip_flag:1;
			uint8_t sipmsk_flag:1;
			uint8_t sip_flag:1;
			uint8_t resv:3;
			uint8_t durable:1;
			uint8_t ipv6:1;
			uint8_t action:1;
			uint8_t pmsk_flag:1;
			uint8_t proto_flag:1;
		};
		uint16_t  rule_info;
	};
#else
#error "Please fix <bits/endian.h>"
#endif
	uint8_t serv_type;
	uint8_t attr_len; // must be zero;
}ip_rule_hdr_t;



typedef union {

	struct{
	
#if  __BYTE_ORDER == __BIG_ENDIAN
		uint32_t dev_type:8;
		uint32_t chnl_id:24;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
		uint32_t  dev_type:8;
		uint32_t  chnl_id:24;
#else
# error "Please fix <bits/endian.h>"
#endif
	};
	uint32_t route_key;
}channel_hdr_t;



typedef struct{
	uint8_t  version;
	uint8_t  msg_type;
	uint16_t msg_code;
	uint32_t msg_id;
#if  __BYTE_ORDER == __BIG_ENDIAN
	uint16_t more_flag:2;
	uint16_t msg_len:14;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	union{
		struct{
			uint8_t  msg_len1:6;
			uint8_t  more_flag:2;
			uint8_t  msg_len2;		
		};
		uint16_t len_flag;
	};
#else 
#error "Please fix <bits/endian.h>"
#endif
	uint16_t  msg_count;
	uint16_t  resv;
	uint16_t  checksum;
}message_hdr_t;



typedef struct{
	uint8_t *data;
	size_t   size;
}cksum_vec_t;


static inline uint16_t do_checksum_multidata(const cksum_vec_t * vec, size_t count)
{
    uint32_t cksum = 0;
    uint16_t unit;
    size_t i, j;
    size_t data_sum, data_count;

    data_count = 0;
    data_sum   = 0;


    for(i = 0; i < count; ++i){
            data_sum += vec[i].size;
    }

    unit = 0;
    for(i = 0; i < count; ++i){
            for(j = 0; j < vec[i].size; ++j, ++data_count){

                    ((uint8_t*)&unit)[ data_count & 1 ] = vec[i].data[j];
                    if((data_count & 1) == 1){
                            cksum += unit;
                            unit   = 0;
                    }
            }
            //chsum += unit; 
    }

    if(data_sum & 1){
            cksum += unit;
    }

    cksum  = (cksum >> 16) + (cksum & 0xffff);
    cksum += cksum >> 16;

    return (uint16_t)(~cksum);

}

static inline uint16_t do_checksum(const uint8_t * data, size_t size)
{
	uint32_t cksum = 0;
	const uint16_t * _data;

	_data = (uint16_t *)data;
	while(size > 1){
		cksum += *_data++;
		size -= sizeof(uint16_t);
	}

	if(size){
		cksum += *(uint8_t*)_data;
	}

	cksum  = (cksum >> 16) + (cksum & 0xffff);
	cksum += cksum >> 16;
	
	return (uint16_t)(~cksum);
}


#endif



