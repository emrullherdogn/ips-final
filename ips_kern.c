#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

#define MAX_CONN_ATTEMPTS 10
#define MAX_BYTES 1048576 // 1 MB

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));   // IP adresi
    __uint(value_size, sizeof(__u64)); // Bağlantı denemesi sayısı
    __uint(max_entries, 1024);
} conn_attempts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));   // IP adresi
    __uint(value_size, sizeof(__u64)); // Trafik miktarı (byte)
    __uint(max_entries, 1024);
} ip_traffic SEC(".maps");

struct event_t {
    char rule_name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12); // 4 KB
} events SEC(".maps");

SEC("xdp")
int ips_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    __u32 src_ip = iph->saddr;

    __u64 *traffic = bpf_map_lookup_elem(&ip_traffic, &src_ip);
    __u64 pkt_len = data_end - data;
    if (traffic) {
        *traffic += pkt_len;
        if (*traffic > MAX_BYTES) {
            return XDP_DROP;
        }
    } else {
        __u64 init_bytes = pkt_len;
        bpf_map_update_elem(&ip_traffic, &src_ip, &init_bytes, BPF_ANY);
    }

    void *l4hdr = (void *)iph + (iph->ihl * 4);
    if (l4hdr >= data_end) return XDP_PASS;

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4hdr;
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;

        __u64 *count = bpf_map_lookup_elem(&conn_attempts, &src_ip);
        if (count) {
            (*count)++;
            if (*count >= MAX_CONN_ATTEMPTS) {
                return XDP_DROP;
            }
        } else {
            __u64 init_count = 1;
            bpf_map_update_elem(&conn_attempts, &src_ip, &init_count, BPF_ANY);
        }

        void *payload = (void *)(tcph + 1);
        if (payload >= data_end) return XDP_PASS;

        const char *dangerous_payloads[] = {
            "DROP TABLE", "<script>", "../../", "eval(", "wget ", "rm -rf /"
        };
        int payload_lengths[] = {10, 8, 6, 5, 5, 8};
        int num_payloads = sizeof(dangerous_payloads) / sizeof(dangerous_payloads[0]);

        for (int j = 0; j < num_payloads; j++) {
            const char *dangerous_payload = dangerous_payloads[j];
            int payload_len = payload_lengths[j];

            if ((void *)(payload + payload_len) <= data_end) {
                int match = 1;
                for (int i = 0; i < payload_len; i++) {
                    if (((char *)payload)[i] != dangerous_payload[i]) {
                        match = 0;
                        break;
                    }
                }
                if (match) {
                    // Event bildirimi (memset/memcpy yerine döngüyle)
                    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
                    if (e) {
                        #pragma clang loop unroll(disable)
                        for (int i = 0; i < sizeof(e->rule_name); i++) {
                            e->rule_name[i] = 0;
                        }

                        #pragma clang loop unroll(disable)
                        for (int i = 0; i < payload_len && i < sizeof(e->rule_name); i++) {
                            e->rule_name[i] = dangerous_payload[i];
                        }

                        bpf_ringbuf_submit(e, 0);
                    }

                    return XDP_DROP;
                }
            }
        }

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4hdr;
        if ((void *)(udph + 1) > data_end) return XDP_PASS;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
