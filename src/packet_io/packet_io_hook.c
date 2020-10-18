#include "sapp_api.h"
#include "sapp_private_api.h"
#include "support/MESA_feedback.h"
/*
	2020-09-28 add:
	
	传统意义上的packet_io, 一般不会修改原始包内容的, 原样收、原样转发,

	但是在inline串联模式下, 如vxlan等, 需要对收到的包进行翻转, 如底层mac, 底层ip等.
	或者某些地址参数根本不在原始包里呈现, 要通过一些tes接口设置转发参数, 如A设备获取vlan、设置转发vlan, 等等,

	原来都由mrtunnat完成, 对sapp透明, mrtunnat被取代后, 新增此层, 用于完成上述功能.
*/

#ifdef __cplusplus
extern "C" {
#endif


extern unsigned int marsio_get_vlan_id_from_mbuff(void *pkt_reference);
extern int marsio_set_vlan_id_to_mbuff(void *pkt_reference, unsigned int vlan_id_host_order);

#if 0
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
#endif


static int packet_io_hook_output_vlan_flipping(raw_pkt_t *raw_pkt, unsigned char route_dir, void *raw_pkt_data, void *io_lib_pkt_reference, const char *action)
{
	struct mesa_ethernet_hdr *ehdr;
	unsigned char tmp_mac_addr[ETHER_ADDR_LEN];
	unsigned short vlan_id;

	if(raw_pkt->mac_flipping_enable != 0){
		ehdr = (struct mesa_ethernet_hdr *)raw_pkt_data;
		memcpy(tmp_mac_addr, ehdr->ether_shost, ETHER_ADDR_LEN);
		memcpy(ehdr->ether_shost, ehdr->ether_dhost, ETHER_ADDR_LEN);
		memcpy(ehdr->ether_dhost, tmp_mac_addr, ETHER_ADDR_LEN);
	}

	if(raw_pkt->route_dir == route_dir){
		/* 原始包同向发送, 需要设置发送vlan为couple vlan id */
		marsio_set_vlan_id_to_mbuff((void *)io_lib_pkt_reference, raw_pkt->vlan_flipping_couple[1]);
		sapp_runtime_log(RLOG_LV_DEBUG, "%s: input_vlan_id:%u, output_vlan_id:%u, mac_flapping:%d", 
						action, raw_pkt->vlan_flipping_couple[0], raw_pkt->vlan_flipping_couple[1], raw_pkt->mac_flipping_enable);
	}else{
		/* 反向注入, 需要设置发送vlan为收包时的vlan id */
		marsio_set_vlan_id_to_mbuff((void *)io_lib_pkt_reference, raw_pkt->vlan_flipping_couple[0]);
		sapp_runtime_log(RLOG_LV_DEBUG, "%s: input_vlan_id:%u, output_vlan_id:%u, mac_flapping:%d", 
						action, raw_pkt->vlan_flipping_couple[0], raw_pkt->vlan_flipping_couple[0], raw_pkt->mac_flipping_enable);
	}

	return 0;
}


static int packet_io_hook_output_vxlan(raw_pkt_t *raw_pkt, void *raw_pkt_data, unsigned char route_dir)
{
	//to do, 翻转最外层mac, 外层ip, 
	//看情况是否需要设置route_dir标志, 同向不变, 反向异或
	return 0;
}


static int packet_io_hook_update_vlan_couple(raw_pkt_t *raw_pkt, unsigned short vlan_id)
{
	const sapp_vlan_flipping_map_t *vlan_map = sapp_global_val->config.packet_io.packet_io_tunnel.vlan_flipping_map_array;

	raw_pkt->vlan_flipping_couple[0] = vlan_id;
	raw_pkt->vlan_flipping_couple[1] = vlan_map[vlan_id].couple_vlan_id;
	raw_pkt->mac_flipping_enable = vlan_map[vlan_id].mac_flipping_enable;

	if('C' == vlan_map[vlan_id].this_vlan_route_location){
		/* 数据包来自C路由器端, 即C2I(I2E)方向, 根据inbound_route_dir的值, 更新当前包route_dir的值 */
		raw_pkt->route_dir = sapp_global_val->config.packet_io.inbound_route_dir ^ 1;
	}else{
		/* 数据包来自I路由器端, 即I2C(E2I)方向, 根据inbound_route_dir的值, 更新当前包route_dir的值 */
		raw_pkt->route_dir = sapp_global_val->config.packet_io.inbound_route_dir;
	}

	return 0;
}

/*
	如果从metadata里获取不到, 从原始包里解析vlan头部获取.
*/
static unsigned short get_vlan_id_from_rawpkt(raw_pkt_t *raw_pkt)
{
	//todo!!!
	return 0;
}

static int packet_io_hook_input_vlan_flipping(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	unsigned short vlan_id = 1;
	
	int ret;

	vlan_id = marsio_get_vlan_id_from_mbuff((void *)raw_pkt->io_lib_pkt_reference);
	if(vlan_id > 1){
		packet_io_hook_update_vlan_couple(raw_pkt, vlan_id);
		ret=  0;
	}else{
		vlan_id = get_vlan_id_from_rawpkt(raw_pkt);
		if(vlan_id > 1){
			packet_io_hook_update_vlan_couple(raw_pkt, vlan_id);
		}else{
			sapp_runtime_log(RLOG_LV_DEBUG, "warning: packet_io_hook_input(), not found vlan_id:%u\n", vlan_id);
			ret = -1;
		}
	}

	return ret;
}

static int packet_io_hook_input_vxlan(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	//to do, 根据vxlan dir方向设置route_dir
	
	return 0;
}



int packet_io_hook_input(raw_pkt_t *raw_pkt, unsigned char dir, int thread_num)
{
	int ret = 0;

	/* vlan flipping与overlay可共存, 如果metadata或原始包里有vlan且命中flip规则, 则进行翻转,可能是本机自检流量; */
	ret = packet_io_hook_input_vlan_flipping(raw_pkt, dir, thread_num);
	if(ret >= 0){
		return 0;
	}
	
	if(OVERLAY_MODE_VXLAN == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = packet_io_hook_input_vxlan(raw_pkt, dir, thread_num);
	}else if(OVERLAY_MODE_NONE == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = 0;
	}else{
		sapp_runtime_log(RLOG_LV_INFO, "packet_io_hook_input() error, unsupport overlay_mode:%d\n", 
						sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin);
	}
	
	return ret;
}


int packet_io_hook_forward(raw_pkt_t *raw_pkt, unsigned char route_dir, int thread_num)
{
	int ret;

	if(raw_pkt->vlan_flipping_couple[0] > 1){
		ret = packet_io_hook_output_vlan_flipping(raw_pkt, route_dir, (void *)raw_pkt->raw_pkt_data, (void *)raw_pkt->io_lib_pkt_reference, "forward pkt");
		return ret;
	}

	if(OVERLAY_MODE_VXLAN == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = packet_io_hook_output_vxlan(raw_pkt, (void *)raw_pkt->raw_pkt_data, route_dir);
	}else if(OVERLAY_MODE_NONE == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = 0;
	}else{
		sapp_runtime_log(20, "packet_io_hook_forward() error, unsupport overlay_mode:%d\n", sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin);
	}
	
	return ret;
}

int packet_io_hook_sendto(const raw_pkt_t *raw_pkt, unsigned char route_dir, char *send_pkt_data, void *send_pkt_io_reference)
{
	int ret;

	if(raw_pkt->vlan_flipping_couple[0] > 1){
		ret = packet_io_hook_output_vlan_flipping((raw_pkt_t *)raw_pkt, route_dir, (void *)send_pkt_data, send_pkt_io_reference, "send pkt");
		return ret;
	}

	if(OVERLAY_MODE_VXLAN == sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin){
		ret = packet_io_hook_output_vxlan((raw_pkt_t *)raw_pkt, (void *)send_pkt_data, route_dir);
	}else{
		sapp_runtime_log(20, "packet_io_hook_sendto() error, unsupport overlay_mode:%d\n", sapp_global_val->config.packet_io.packet_io_tunnel.overlay_mode_bin);
	}
	
	return ret;

}


#ifdef __cplusplus
}
#endif


