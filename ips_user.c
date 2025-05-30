#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <net/if.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <bpf/bpf_core_read.h>

static int ifindex_global = -1;
static __u32 xdp_flags_global = 0;

struct event_t {
    char rule_name[32];
};

void handle_sigint(int sig) {
    printf("\nCtrl+C algılandı, XDP programı kaldırılıyor...\n");
    if (ifindex_global > 0) {
        int err = bpf_set_link_xdp_fd(ifindex_global, -1, xdp_flags_global);
        if (err < 0) {
            fprintf(stderr, "Uyarı: XDP programı kaldırılamadı: %s\n", strerror(-err));
        } else {
            printf("XDP programı başarıyla kaldırıldı.\n");
        }
    }
    exit(0);
}

static int increase_rlimit(int resource, rlim_t rlim) {
    struct rlimit r;
    int err;

    err = getrlimit(resource, &r);
    if (err) return err;

    r.rlim_cur = r.rlim_max = rlim;
    return setrlimit(resource, &r);
}

int handle_event(void *ctx, void *data, size_t data_sz) {
    struct event_t *e = data;
    printf("IPS: Sahte Paket Algılandı! (%s Paketi)\n", e->rule_name);
    return 0;
}

int attach_xdp(const char *ifname) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd = -1, ifindex = -1;
    int err = 0;
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;

    err = increase_rlimit(RLIMIT_MEMLOCK, RLIM_INFINITY);
    if (err) {
        fprintf(stderr, "Uyarı: Memory limit artırılamadı: %s\n", strerror(errno));
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Hata: '%s' arayüzü bulunamadı: %s\n", ifname, strerror(errno));
        return -1;
    }

    ifindex_global = ifindex;
    xdp_flags_global = xdp_flags;

    signal(SIGINT, handle_sigint);

    printf("Arayüz '%s' bulundu (index: %d)\n", ifname, ifindex);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj = bpf_object__open_file("ips_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Hata: BPF programı 'ips_kern.o' açılamadı: %s\n",
                strerror(-libbpf_get_error(obj)));
        return -1;
    }

    bpf_object__for_each_program(prog, obj) {
        bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Hata: BPF programı yüklenemedi: %s\n", strerror(-err));
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, "ips_kern");
    if (!prog) {
        fprintf(stderr, "Hata: BPF programı 'ips_kern' bulunamadı.\n");
        err = -1;
        goto cleanup;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Hata: BPF program dosya tanıtıcısı alınamadı.\n");
        err = -1;
        goto cleanup;
    }

    printf("BPF programı başarıyla yüklendi (fd: %d)\n", prog_fd);

    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err < 0) {
        fprintf(stderr,
                "Hata: XDP programı '%s' arayüzüne bağlanamadı: %s (ret: %d)\n",
                ifname, strerror(-err), err);
        goto cleanup;
    }

    printf("XDP programı '%s' arayüzüne başarıyla bağlandı.\n", ifname);
    printf("Program çalışıyor. Durdurmak için Ctrl+C basın.\n");

    // Ring buffer setup
    int ringbuf_map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (ringbuf_map_fd < 0) {
        fprintf(stderr, "Ring buffer map bulunamadı.\n");
        goto cleanup;
    }

    struct ring_buffer *rb = ring_buffer__new(ringbuf_map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Ring buffer oluşturulamadı.\n");
        goto cleanup;
    }

    while (1) {
        ring_buffer__poll(rb, 100); // 100 ms
    }

cleanup:
    if (obj) {
        bpf_object__close(obj);
    }
    return err;
}

void print_usage(const char *prog_name) {
    printf("Kullanım: %s <arayüz_adı>\n", prog_name);
    printf("Örnek: %s eth0\n", prog_name);
    printf("       %s lo\n", prog_name);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *ifname = argv[1];

    printf("Linux Çekirdeği IPS - XDP Programı\n");
    printf("Arayüz: %s\n", ifname);

    if (geteuid() != 0) {
        fprintf(stderr, "Hata: Bu program root yetkisi ile çalıştırılmalıdır.\n");
        return 1;
    }

    if (attach_xdp(ifname) < 0) {
        fprintf(stderr, "XDP programı bağlanırken hata oluştu.\n");
        return 1;
    }

    return 0;
}
