# 🛡️ XDP Generic Tabanlı IPS Projesi

Bu proje, **XDP (eXpress Data Path)** teknolojisini kullanarak ağ trafiğini gerçek zamanlı analiz eden ve şüpheli paketleri belirlenen kurallara göre engelleyen bir **IPS (Intrusion Prevention System)** çözümüdür.

---

## ⚙️ Sistem Gereksinimleri

Projenin derlenip çalıştırılabilmesi için aşağıdaki paketlerin sisteminizde kurulu olması gerekir:

### 🔧 Gerekli Paketlerin Kurulumu (Tek Satırda)

```bash
sudo apt update -y && sudo apt install -y clang llvm gcc gcc-multilib bpftool linux-headers-$(uname -r) pkg-config make git libelf-dev
```

| Paket            | Açıklama |
|------------------|----------|
| `clang`          | eBPF programlarını BPF bytecode'a çeviren C derleyicisidir. |
| `llvm`           | Clang ile birlikte çalışan derleyici altyapısıdır. |
| `gcc`            | Kullanıcı alanı (user-space) uygulamalarını derlemek için kullanılır. |
| `gcc-multilib`   | 32-bit destekli programların derlenmesini sağlar. |
| `bpftool`        | XDP/BPF programlarını görüntülemek, yüklemek ve kaldırmak için kullanılır. |
| `linux-headers`  | Kernel API'sine erişim sağlar, XDP programlarının çekirdeğe yüklenebilmesi için gereklidir. |
| `pkg-config`     | Derleme sırasında kütüphane ve header dosyalarının yolunu bulmak için kullanılır. |
| `libelf-dev`     | ELF biçimindeki dosyalarla çalışmak için gerekli kütüphane (libbpf için gereklidir). |
| `make`, `git`    | libbpf'i derlemek için gereklidir. |

---

## 📦 `libbpf` 0.8.0 Kurulumu

```bash
git clone --branch v0.8.0 https://github.com/libbpf/libbpf.git
cd libbpf/src
sudo make
sudo make install
```

> Bu işlem `libbpf.a` ve `libbpf.so` kütüphanelerini oluşturacaktır.

---

## 🧩 Kernel-space (XDP) Kodunun Derlenmesi

```bash
clang -O2 -target bpf -g -D__BPF_NO_BTF__ -c ips_kern.c -o ips_kern.o
```

---

## 🖥️ User-space Uygulamasının Derlenmesi

Eğer sisteminizde `libbpf` sistem genelinde kurulu değilse ve proje dizininde özel olarak derlenmişse:

### Adım 1: `libbpf.pc` dosyasının yolu `PKG_CONFIG_PATH`'e eklenir:

```bash
export PKG_CONFIG_PATH=$(pwd)/libbpf/src:$PKG_CONFIG_PATH
```

### Adım 2: `libbpf.so` dosyası için `LD_LIBRARY_PATH` ayarlanır:

```bash
export LD_LIBRARY_PATH=$(pwd)/libbpf/src:$LD_LIBRARY_PATH
```

> Bu ortam değişkenlerini kullanmadan önce, user-space programı olan `ips_user.c` dosyasının bulunduğu dizine geçmeniz gerekir.

### Adım 3: `libbpf`'in kurulup kurulmadığını test edin:

```bash
pkg-config --modversion libbpf
```

> Bu komut, `libbpf` versiyonunu gösterir. Eğer bir çıktı alamıyorsanız, `PKG_CONFIG_PATH` doğru ayarlanmamış veya `libbpf.pc` dosyası bulunmamış olabilir.

### Adım 4: Derleme işlemi:

```bash
gcc -o ips_user ips_user.c -lbpf $(pkg-config --cflags --libs libbpf)
```
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
sudo ip a | grep xdp <interface>
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
