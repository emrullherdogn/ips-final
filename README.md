# 🛡️ XDP Tabanlı IPS Projesi

Bu proje, **XDP (eXpress Data Path)** teknolojisini kullanarak ağ trafiğini gerçek zamanlı analiz eden ve şüpheli paketleri belirlenen kurallara göre engelleyen bir **IPS (Intrusion Prevention System)** çözümüdür.

---

## ⚙️ Sistem Gereksinimleri

Projenin derlenip çalıştırılabilmesi için aşağıdaki paketlerin sisteminizde kurulu olması gerekir:

```bash
sudo apt update -y
sudo apt install clang llvm -y          
sudo apt install libbpf-dev -y
sudo apt install gcc -y
sudo apt install bpftool -y
sudo apt install linux-headers-$(uname -r) -y
sudo apt install gcc-multilib -y
```

🧩 Kernel-space (XDP) Kodunun Derlenmesi
```bash
clang -O2 -target bpf -g -D__BPF_NO_BTF__ -c ips_kern.c -o ips_kern.o
```

🖥️ User-space Uygulamasının Derlenmesi
```bash
gcc -o ips_user ips_user.c -lbpf
```

🚀 Kullanım
IPS sistemini başlatmak için aşağıdaki komutu kullanabilirsiniz
```bash
sudo ./ips_user <interface>
```
⚠️ Not: sudo yetkisi gereklidir çünkü XDP programları çekirdek seviyesinde çalışır.

