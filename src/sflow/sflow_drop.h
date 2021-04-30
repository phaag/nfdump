SFL_DROP(net_unreachable,0)
SFL_DROP(host_unreachable,1)
SFL_DROP(protocol_unreachable,2)
SFL_DROP(port_unreachable,3)
SFL_DROP(frag_needed,4)
SFL_DROP(src_route_failed,5)
SFL_DROP(dst_net_unknown,6) /* ipv4_lpm_miss, ipv6_lpm_miss */
SFL_DROP(dst_host_unknown,7)
SFL_DROP(src_host_isolated,8)
SFL_DROP(dst_net_prohibited,9) /* reject_route */
SFL_DROP(dst_host_prohibited,10)
SFL_DROP(dst_net_tos_unreachable,11)
SFL_DROP(dst_host_tos_unreacheable,12)
SFL_DROP(comm_admin_prohibited,13)
SFL_DROP(host_precedence_violation,14)
SFL_DROP(precedence_cutoff,15)
SFL_DROP(unknown,256)
SFL_DROP(ttl_exceeded,257) /* ttl_value_is_too_small */
SFL_DROP(acl,258) /* ingress_flow_action_drop, egress_flow_action_drop, group acl_drops */
SFL_DROP(no_buffer_space,259) /* tail_drop */
SFL_DROP(red,260)
SFL_DROP(traffic_shaping,261)
SFL_DROP(pkt_too_big,262) /* mtu_value_is_too_small */
SFL_DROP(src_mac_is_multicast,263)
SFL_DROP(vlan_tag_mismatch,264)
SFL_DROP(ingress_vlan_filter,265)
SFL_DROP(ingress_spanning_tree_filter,266)
SFL_DROP(port_list_is_empty,267)
SFL_DROP(port_loopback_filter,268)
SFL_DROP(blackhole_route,269)
SFL_DROP(non_ip,270)
SFL_DROP(uc_dip_over_mc_dmac,271)
SFL_DROP(dip_is_loopback_address,272)
SFL_DROP(sip_is_mc,273)
SFL_DROP(sip_is_loopback_address,274)
SFL_DROP(ip_header_corrupted,275)
SFL_DROP(ipv4_sip_is_limited_bc,276)
SFL_DROP(ipv6_mc_dip_reserved_scope,277)
SFL_DROP(ipv6_mc_dip_interface_local_scope,278)
SFL_DROP(unresolved_neigh,279)
SFL_DROP(mc_reverse_path_forwarding,280)
SFL_DROP(non_routable_packet,281)
SFL_DROP(decap_error,282)
SFL_DROP(overlay_smac_is_mc,283)
SFL_DROP(unknown_l2,284) /* group l2_drops */
SFL_DROP(unknown_l3,285) /* group l3_drops */
SFL_DROP(unknown_l3_exception,286) /* group l3_exceptions */
SFL_DROP(unknown_buffer,287) /* group buffer_drops */
SFL_DROP(unknown_tunnel,288) /* group tunnel_drops */
SFL_DROP(unknown_l4,289)
  
 

