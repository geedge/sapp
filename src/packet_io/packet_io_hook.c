#include "sapp_api.h"
#include "sapp_private_api.h"
#include "support/MESA_feedback.h"
/*
	2020-09-28 add:
	
	传统意义上的packet_io, 一般是不会修改原始包内容的, 原样收、原样转发,

	但是在inline串联模式下, 如vxlan等, 需要对收到的包进行翻转, 如底层mac, 底层ip等.
	或者某些地址参数根本不在原始包里呈现, 要通过一些接口设置转发参数, 如a设备获取、设置转发vlan, 等等,

	mrtunnat被取代后, 新增此层, 用于完成上述功能.
*/

#ifdef __cplusplus
extern "C" {
#endif


extern unsigned short (*marsio_get_vlan_id_from_mbuff)(void *pkt_reference);
extern int (*marsio_set_vlan_id_to_mbuff)(void *pkt_reference, unsigned short vlan_id_net_order);


static const sapp_vlan_flipping_map_t *vlan_flipping_get_opposite(int cori, unsigned short vlan_id)
{
	const sapp_vlan_flipping_map_t *config_vf, *result_vf = NULL;
	int i, vf_num;
	
	config_vf = sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_map_array;
	vf_num = sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_map_num;

	for(i = 0; i < vf_num; i++){
		if(('C' == cori) && (vlan_id == config_vf[i].c_router_vlan_id)){
			result_vf = &config_vf[i];
			break;
		}else if(('I' == cori) && (vlan_id == config_vf[i].i_router_vlan_id)){
			result_vf = &config_vf[i];
			break;
		}
	}

	return result_vf;
}


static int packet_io_hook_output_vlan_flipping_adev(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	struct mesa_ethernet_hdr *ehdr;
	unsigned char tmp_mac_addr[ETHER_ADDR_LEN];
	unsigned short vlan_id;

	if(sapp_global_val->config.packet_io.packet_io_tunnel.mac_flipping_enabled){
		ehdr = (struct mesa_ethernet_hdr *)raw_pkt->raw_pkt_data;
		memcpy(tmp_mac_addr, ehdr->ether_shost, ETHER_ADDR_LEN);
		memcpy(ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
		memcpy(ehdr->ether_dhost, tmp_mac_addr, ETHER_ADDR_LEN);
	}

	/* 对端的vlan_id已经在收包input_hook阶段查询到, 此处直接set即可 */
	marsio_set_vlan_id_to_mbuff((void *)raw_pkt->io_lib_pkt_reference, raw_pkt->vlan_flipping_couple[1]);

	return 0;
}


static int packet_io_hook_output_vxlan(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	//to do, 翻转最外层mac, 外层ip
	return 0;
}


static int packet_io_hook_input_vlan_flipping_adev(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	unsigned short vlan_id;
	const sapp_vlan_flipping_map_t *vf;

	vlan_id = marsio_get_vlan_id_from_mbuff((void *)raw_pkt->io_lib_pkt_reference);
	raw_pkt->vlan_flipping_couple[0] = vlan_id;

	vf = vlan_flipping_get_opposite('C', vlan_id);
	if(NULL == vf){
		vf = vlan_flipping_get_opposite('I', vlan_id);
		if(NULL == vf){
			sapp_runtime_log(20, "packet_io_hook_input() error, not found vlan_id:%u\n", vlan_id);
			return -1;
		}else{
			/* 数据包来自I路由器端, 即I2C(E2I)方向, 更新route_dir的值 */
			raw_pkt->route_dir = sapp_global_val->config.packet_io.inbound_route_dir;
			raw_pkt->vlan_flipping_couple[1] = vf->c_router_vlan_id;
		}
	}else{
		/* 数据包来自C路由器端, 即C2I(I2E)方向, 更新route_dir的值 */
		raw_pkt->route_dir = sapp_global_val->config.packet_io.inbound_route_dir ^ 1;
		raw_pkt->vlan_flipping_couple[1] = vf->i_router_vlan_id;
	}

	return 0;
}

static int packet_io_hook_input_vxlan(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	//to do,
	return 0;
}



int packet_io_hook_input(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	int ret = 0;

	if(OVERLAY_MODE_VLAN_FLIP_ADEV == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = packet_io_hook_input_vlan_flipping_adev(raw_pkt, dir, thread_num);
	}else if(OVERLAY_MODE_VXLAN == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = packet_io_hook_input_vxlan(raw_pkt, dir, thread_num);
	}else{
		sapp_runtime_log(20, "packet_io_hook_output() error, unsupport overlay_mode:%d\n", sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin);
		assert(0);
	}
	
	return ret;
}


int packet_io_hook_output(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	int ret;

	if(OVERLAY_MODE_VLAN_FLIP_ADEV == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = packet_io_hook_output_vlan_flipping_adev(raw_pkt, dir, thread_num);
	}else if(OVERLAY_MODE_VXLAN == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = packet_io_hook_output_vxlan(raw_pkt, dir, thread_num);
	}else{
		sapp_runtime_log(20, "packet_io_hook_output() error, unsupport overlay_mode:%d\n", sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin);
		assert(0);
	}
	
	return ret;
}


#ifdef __cplusplus
}
#endif


