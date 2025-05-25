# 🛡️ XDP Generic Tabanlı IPS Projesi

Bu proje, **XDP (eXpress Data Path)** teknolojisini kullanarak ağ trafiğini gerçek zamanlı analiz eden ve şüpheli paketleri belirlenen kurallara göre engelleyen bir **IPS (Intrusion Prevention System)** çözümüdür.

---

## ⚙️ Sistem Gereksinimleri

Projenin derlenip çalıştırılabilmesi için aşağıdaki paketlerin sisteminizde kurulu olması gerekir:

```bash
sudo apt update -y
sudo apt install clang llvm -y          
sudo apt install gcc -y
sudo apt install bpftool -y
sudo apt install linux-headers-$(uname -r) -y
sudo apt install gcc-multilib -y
```

| Paket            | Açıklama |
|------------------|----------|
| `clang`          | eBPF programlarını BPF bytecode'a çeviren C derleyicisidir. |
| `llvm`           | Clang ile birlikte çalışan derleyici altyapısıdır. |
| `libbpf`         | eBPF programlarının kullanıcı alanı üzerinden yönetilmesini sağlayan kütüphanedir. |
| `gcc`            | Kullanıcı alanı (user-space) uygulamalarını derlemek için kullanılır. |
| `bpftool`        | XDP/BPF programlarını görüntülemek, yüklemek ve kaldırmak için kullanılır. |
| `linux-headers`  | Kernel API'sine erişim sağlar, XDP programlarının çekirdeğe yüklenebilmesi için gereklidir. |
| `gcc-multilib`   | 32-bit destekli programların derlenmesini sağlar. |

---

## 🧩 Kernel-space (XDP) Kodunun Derlenmesi

```bash
clang -O2 -target bpf -g -D__BPF_NO_BTF__ -c ips_kern.c -o ips_kern.o
```

---

## 🖥️ User-space Uygulamasının Derlenmesi

Eğer sisteminizde libbpf sistem genelinde kurulu değilse ve proje dizininde özel olarak derlenmişse:

### Adım 1: `libbpf.pc` dosyasının yolu `PKG_CONFIG_PATH`'e eklenir:
```bash
export PKG_CONFIG_PATH=$(pwd)/libbpf/src:$PKG_CONFIG_PATH
```

### Adım 2: `libbpf.so` dosyası için `LD_LIBRARY_PATH` ayarlanır:
```bash
export LD_LIBRARY_PATH=$(pwd)/libbpf/src:$LD_LIBRARY_PATH
```

### Adım 3: Derleme işlemi:
```bash
gcc -o ips_user ips_user.c -lpbf
```
---

## 🚀 Kullanım

IPS sistemini başlatmak için:

```bash
sudo ./ips_user <interface>
```

Örnek:

```bash
sudo ./ips_user eth0
```

⚠️ **Not:** `sudo` yetkisi gereklidir çünkü XDP programları çekirdek seviyesinde çalışır.

---

## 📊 XDP Programını Kontrol Etme ve Kaldırma

### Yüklü XDP programını görme:

```bash
sudo ip link show dev <interface>
```

> Çıktıda `xdp` ifadesi varsa, XDP programı arayüze bağlıdır.

### XDP programını kaldırma:

```bash
sudo ip link set dev <interface> xdp off
```

Örnek:

```bash
sudo ip link set dev eth0 xdp off
```
