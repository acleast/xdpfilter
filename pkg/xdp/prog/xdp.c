#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
//#include <bpf/bpf_helpers.h>
#include "maps.h"

// struct vlan_hdr {
// 	__be16 h_vlan_TCI;
// 	__be16 h_vlan_encapsulated_proto;
// };

/* helper functions called from eBPF programs */
// static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
// 	        (void *) BPF_FUNC_trace_printk;

/* macro for printing debug info to the tracing pipe, useful just for
 debugging purposes and not recommended to use in production systems.

 use `sudo cat /sys/kernel/debug/tracing/trace_pipe` to read debug info.
 */
// #define printt(fmt, ...)                                                   \
//             ({                                                             \
//                 char ____fmt[] = fmt;                                      \
//                 bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
//             })

SEC("xdp/xdp_ip_filter")
int xdp_ip_filter(struct xdp_md *ctx) {	
    void *end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
	
    __u32 ip_src = 0, ip_dst = 0;
    __u64 offset;
    __u16 eth_type;

    struct ethhdr *eth = data;
    offset = sizeof(struct ethhdr);

    if ((void *)(eth + 1) > end) {
        return XDP_PASS;
    }
    //eth_type = eth->h_proto;

    /* handle VLAN tagged packet */
//     if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
// 	struct vlan_hdr *vlan_hdr;

// 	vlan_hdr = (void *)eth + offset;
// 	offset += sizeof(*vlan_hdr);
// 	if ((void *)eth + offset > end)
// 		return 0;
// 	eth_type = vlan_hdr->h_vlan_encapsulated_proto; 
//    }

//     /* let's only handle IPv4 addresses */
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *iph;
	iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > end) {
		return XDP_PASS;
	}
    // offset += sizeof(struct iphdr);
    /* make sure the bytes you want to read are within the packet's range before reading them */
    // if (iph + 1 > end) {
    //     return XDP_ABORTED;
    // }
    ip_src = iph->saddr;
    ip_dst = iph->daddr;
    __u8 proto = iph->protocol;

    if (proto == 1 || proto == 6 || proto == 17) {
        __u64 *srcMap_value, *dstMap_value, *protoMap_value, bitmap = 1;
		
        srcMap_value = bpf_map_lookup_elem(&srcMap, &ip_src);		
        dstMap_value = bpf_map_lookup_elem(&dstMap, &ip_dst);
		__u8 tmp = proto;
        protoMap_value = bpf_map_lookup_elem(&protoMap, &tmp);

        if (srcMap_value == 0) {
            __u32 default_sip = 0;
            srcMap_value = bpf_map_lookup_elem(&srcMap, &default_sip);
        }
        if (dstMap_value == 0) {
            __u32 default_dip = 0;
            dstMap_value = bpf_map_lookup_elem(&dstMap, &default_dip);
        }
        if (protoMap_value == 0) {
            __u8 default_prot = 0;
            protoMap_value = bpf_map_lookup_elem(&protoMap, &default_prot);
        }

        if (proto == 1) {
		    if (srcMap_value && dstMap_value && protoMap_value) {
				bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value);
			}
            __u64 temp = (~bitmap) + 1;
            bitmap = bitmap & temp;
        } else if (proto == 6) {
            struct tcphdr *tcph;
			tcph = (struct tcphdr *)(iph + 1);
			if ((void *)(tcph + 1) > end) {
				return XDP_PASS;
			}
			
            __u64 *sportMap_value, *dportMap_value;
            __u16 sport = tcph->source;
            __u16 dport = tcph->dest;
			
            sportMap_value = bpf_map_lookup_elem(&sportMap, &sport);			
            dportMap_value = bpf_map_lookup_elem(&dportMap, &dport);

            if (sportMap_value == 0) {
                __u16 default_sport = 0;
                sportMap_value = bpf_map_lookup_elem(&sportMap, &default_sport);
            }
            if (dportMap_value == 0) {
                __u16 default_dport = 0;
                dportMap_value = bpf_map_lookup_elem(&dportMap, &default_dport);
            }

            if (srcMap_value && dstMap_value && protoMap_value && sportMap_value && dportMap_value) {
				bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value) & (*sportMap_value) & (*dportMap_value);
			}
            __u64 temp = (~bitmap) + 1;
            bitmap = bitmap & temp; 
        } else if (proto == 17) {
            struct udphdr *udph;
			udph = (struct udphdr *)(iph + 1);
			if ((void *)(udph + 1) > end) {
				return XDP_PASS;
			}
			
            __u64 *sportMap_value, *dportMap_value;
            __u16 sport = udph->source;
            __u16 dport = udph->dest;
            sportMap_value = bpf_map_lookup_elem(&sportMap, &sport);
            dportMap_value = bpf_map_lookup_elem(&dportMap, &dport);

            if (sportMap_value == 0) {
                __u16 default_sport = 0;
                sportMap_value = bpf_map_lookup_elem(&sportMap, &default_sport);
            }
            if (dportMap_value == 0) {
                __u16 default_dport = 0;
                dportMap_value = bpf_map_lookup_elem(&dportMap, &default_dport);
            }

            if (srcMap_value && dstMap_value && protoMap_value && sportMap_value && dportMap_value) {
				bitmap = (*srcMap_value) & (*dstMap_value) & (*protoMap_value) & (*sportMap_value) & (*dportMap_value);
			}
            __u64 temp = (~bitmap) + 1;
            bitmap = bitmap & temp; 
        }
		
        __u64 *actionMap_value;
        actionMap_value = bpf_map_lookup_elem(&actionMap, &bitmap);		
        if (actionMap_value) {
            (*actionMap_value) = (*actionMap_value) + 1;			
            bpf_map_update_elem(&actionMap, &bitmap, actionMap_value, BPF_EXIST);
            return XDP_DROP;
        }

		return XDP_PASS;
    }
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
