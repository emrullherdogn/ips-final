#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/resource.h>
#include <net/if.h>

// BPF header'ları
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

// Eski sistemlerde linux/if_link.h gerekebilir
#ifndef __has_include
#define __has_include(x) 0
#endif

#if __has_include(<linux/if_link.h>)
#include <linux/if_link.h>
#endif

// XDP flags - eski çekirdeklerde olmayabilir
#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE (1U << 1)
#endif

#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE (1U << 2)
#endif

#ifndef XDP_FLAGS_HW_MODE
#define XDP_FLAGS_HW_MODE (1U << 3)
#endif

// Çekirdek versiyonuna göre uyumluluk fonksiyonları
static int xdp_attach_fallback(int ifindex, int prog_fd, __u32 flags) {
    // Eski libbpf versiyonları için fallback
    #ifdef HAVE_BPF_SET_LINK_XDP_FD
    return bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
    #else
    // Manuel netlink implementasyonu gerekebilir
    return -ENOTSUP;
    #endif
}

static int increase_rlimit(int resource, rlim_t rlim) {
    struct rlimit r;
    int err;

    err = getrlimit(resource, &r);
    if (err) {
        return err;
    }

    r.rlim_cur = r.rlim_max = rlim;
    return setrlimit(resource, &r);
}

int attach_xdp(const char *ifname) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd = -1, ifindex = -1;
    int err = 0;
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;

    // Memory limit'i artır (BPF programları için gerekli)
    err = increase_rlimit(RLIMIT_MEMLOCK, RLIM_INFINITY);
    if (err) {
        fprintf(stderr, "Uyarı: Memory limit artırılamadı: %s\n", strerror(errno));
        // Devam et, bazı sistemlerde sorun olmayabilir
    }

    // Ağ arayüzü indeksini al
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Hata: '%s' arayüzü bulunamadı: %s\n", ifname, strerror(errno));
        return -1;
    }

    printf("Arayüz '%s' bulundu (index: %d)\n", ifname, ifindex);

    // libbpf debug seviyesini ayarla
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // eBPF programını yükle
    obj = bpf_object__open_file("ips_kern.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Hata: BPF programı 'ips_kern.o' açılamadı: %s\n", 
                strerror(-libbpf_get_error(obj)));
        return -1;
    }

    // Program tipini ayarla (gerekirse)
    bpf_object__for_each_program(prog, obj) {
        bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
    }

    // BPF programını yükle
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Hata: BPF programı yüklenemedi: %s\n", strerror(-err));
        goto cleanup;
    }

    // XDP programını bul
    prog = bpf_object__find_program_by_name(obj, "ips_prog");
    if (!prog) {
        fprintf(stderr, "Hata: BPF programı 'ips_prog' bulunamadı.\n");
        // Alternatif program isimlerini dene
        prog = bpf_object__next_program(obj, NULL);
        if (!prog) {
            fprintf(stderr, "Hata: Hiçbir BPF programı bulunamadı.\n");
            err = -1;
            goto cleanup;
        }
        printf("Program bulundu: %s\n", bpf_program__name(prog));
    }

    // Program dosya tanıtıcısını al
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Hata: BPF program dosya tanıtıcısı alınamadı.\n");
        err = -1;
        goto cleanup;
    }

    printf("BPF programı başarıyla yüklendi (fd: %d)\n", prog_fd);

    // XDP programını arayüze bağla - yeni API önce dene
    struct bpf_xdp_attach_opts opts = {
        .sz = sizeof(opts),
    };

    err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &opts);
    if (err < 0) {
        // Yeni API başarısız olursa eski API'yi dene
        printf("Yeni API başarısız, eski API deneniyor...\n");
        err = xdp_attach_fallback(ifindex, prog_fd, xdp_flags);
        
        if (err < 0) {
            // SKB mode'u olmadan dene
            printf("SKB mode olmadan deneniyor...\n");
            xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
            err = bpf_xdp_attach(ifindex, prog_fd, xdp_flags, &opts);
            
            if (err < 0) {
                fprintf(stderr,
                    "Hata: XDP programı '%s' arayüzüne bağlanamadı: %s (ret: %d)\n",
                    ifname, strerror(-err), err);
                goto cleanup;
            }
        }
    }

    printf("XDP programı '%s' arayüzüne başarıyla bağlandı.\n", ifname);
    printf("Program çalışıyor. Durdurmak için Ctrl+C basın.\n");
    
    // Program çalışırken bekle
    while (1) {
        sleep(1);
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

    // Root yetkisi kontrolü
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
