#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h> // bpf_set_link_xdp_fd fonksiyonu için gerekli başlık dosyası

int attach_xdp(const char *ifname) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, ifindex;
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE; // Generic mod etkin

    // Ağ arayüzü indeksini al
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Hata: '%s' arayüzü bulunamadı: %s\n", ifname, strerror(errno));
        return -1;
    }

    // eBPF programını yükle
    obj = bpf_object__open_file("ips_kern.o", NULL);
    if (!obj) {
        fprintf(stderr, "Hata: BPF programı 'ips_kern.o' açılamadı: %s\n", strerror(errno));
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Hata: BPF programı yüklenemedi: %s\n", strerror(errno));
        bpf_object__close(obj);
        return -1;
    }

    // XDP programını bul ve dosya tanıtıcısını al
    prog = bpf_object__find_program_by_name(obj, "ips_prog");
    if (!prog) {
        fprintf(stderr, "Hata: BPF programı 'ips_prog' bulunamadı.\n");
        bpf_object__close(obj);
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Hata: BPF program dosya tanıtıcısı alınamadı.\n");
        bpf_object__close(obj);
        return -1;
    }

    // XDP programını ağ arayüzüne bağla
    int err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL);
    if (err < 0) {
        fprintf(stderr,
            "Hata: XDP programı '%s' arayüzüne bağlanamadı: %s (errno: %d, ret: %d)\n",
            ifname, strerror(errno), errno, err);
        bpf_object__close(obj);
        return -1;
    }

    printf("XDP programı '%s' arayüzüne başarıyla bağlandı.\n", ifname);
    bpf_object__close(obj);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Kullanım: %s <arayüz_adı>\n", argv[0]);
        return 1;
    }

    const char *ifname = argv[1];

    if (attach_xdp(ifname) < 0) {
        fprintf(stderr, "XDP programı bağlanırken hata oluştu.\n");
        return 1;
    }

    return 0;
}
