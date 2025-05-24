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

SEC("xdp")
int ips_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet başlığı
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    // IP başlığı
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;
    __u32 src_ip = iph->saddr;

    // --- Trafik hacmi kontrolü (DoS tespiti) ---
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

    // --- TCP veya UDP başlığına geçiş ---
    void *l4hdr = (void *)iph + (iph->ihl * 4);
    if (l4hdr >= data_end) return XDP_PASS;

    // --- Bağlantı denemesi kontrolü (Port tarama tespiti) ---
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
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = l4hdr;
        if ((void *)(udph + 1) > data_end) return XDP_PASS;
    } else {
        return XDP_PASS;
    }

    // --- Paketin içeriğini kontrol et ---
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = l4hdr;
        if ((void *)(tcph + 1) > data_end) return XDP_PASS;

        // TCP payload başlangıcı
        void *payload = (void *)(tcph + 1);
        if (payload >= data_end) return XDP_PASS;

        // Tehlikeli ifadeler listesi ve uzunlukları
        const char *dangerous_payloads[] = {
            "DROP TABLE",    // SQL enjeksiyonu
            "<script>",      // XSS saldırısı
            "../../",        // Path traversal
            "eval(",         // Kötü amaçlı kod çalıştırma
            "wget ",         // Zararlı dosya indirme
            "rm -rf /"       // Sistem dosyalarını silme
        
        };
        int payload_lengths[] = {
            10, // "DROP TABLE"
            8,  // "<script>"
            6,  // "../../"
            5,  // "eval("
            5,  // "wget "
            8   // "rm -rf /"
        };
        int num_payloads = sizeof(dangerous_payloads) / sizeof(dangerous_payloads[0]);

        // Payload kontrolü
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
                    return XDP_DROP; // Tehlikeli ifade bulundu, paketi düşür
                }
            }
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";