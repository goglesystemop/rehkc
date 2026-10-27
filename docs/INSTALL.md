# Linux masaüstü kurulumu

Bu sürümün hedefi x86_64 Linux ve glibc >= 2.28'dir. Cinnamon/X11 ve
Ubuntu 26.04.1/Plasma 6.6.6 Wayland/XWayland test kapsamı docs/KDE-NEXT.md
içinde açıklanır. Paket CPython
3.12 ve Qt5/PyQt5 içerir; kullanıcının Python ortamına pip kurulumu yapılmaz.
Sistem OpenGL/X11/font/D-Bus kitaplıkları ve çalışan bir masaüstü oturumu gerekir.
`run --doctor`, eksik XCB kitaplıklarını ve bulunan isteğe bağlı araçları raporlar.

## Kurucu davranışı

- Uygulama: `${XDG_DATA_HOME:-~/.local/share}/rehkc/releases/0.2.2`.
- Sabit sürüm bağlantısı: aynı dizinde `current`.
- Komut: `~/.local/bin/rehkc`; menü: kullanıcı uygulama dizininde
  `io.github.goglesystemop.rehkc.desktop`.
- Ayarlar: `${XDG_CONFIG_HOME:-~/.config}/rehkc`.
- Oturumlar: `${XDG_DATA_HOME:-~/.local/share}/rehkc/sessions`.
- Mevcut `~/.config/rea` ve `rea-local-models` verileri değiştirilmez. Aynı makinede
  eski REA kullanımı devam eder; yeni REHKC, kendi hesap/oturum kaydını kullanır.
- Özel konumlar için `--data-dir`, `--bin-dir`, `--desktop-dir`, `--no-desktop`.
- Mevcut farklı başlatıcıyı değiştirmek açık `--replace-existing` gerektirir;
  önceki içerik özel izinli kurulum kaydında geri dönüş için tutulur.

Arşivden yalnız uygulama kurulumu (`--without-tools`) ağ gerektirmez. Varsayılan kurulum analiz motorları ve JDK için resmî kaynaklara bağlanır. İlk kaynak depo kurulumunda arşiv GitHub'dan
indirilir; ağ ve sistem Python'unun güncel tarfile güvenli açma desteği gerekir.

## Analiz araçları

Kurucu varsayılan olarak Ghidra, RetDec, Radare2 ve uyumlu JDK kurar. Haftalık
güncelleme kontrolü, sürüm/bağımlılık politikası ve geri dönüş için
[Yönetilen analiz motorları](ANALYSIS-TOOLS.md) belgesini okuyun.


Sunucular varsayılan olarak LM Studio `127.0.0.1:1234`, Ollama `127.0.0.1:11434`.
Başka port veya anahtar kullanılıyorsa Rea ayarlarından mevcut sunucuyu seçin.
Yerel sunucular ve model dosyaları bu pakete dahil değildir.

Ghidra kurulumunuzda `support/analyzeHeadless` bulunmalı. Önceden ayarlı
`GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `RETDEC_INSTALL_DIR` değerleri korunur.
Yoksa PATH, `~/.local/opt/`, `/opt/` ve standart Ghidra konumları taranır. Ghidra
12.1.4/JDK 21 önceki sürümde doğrulanmıştır. Yeni yönetilen grup Ghidra 12.1.4
ve JDK 21 kullanır; başka sürümün
uygunluğunu gerçek doctor raporu belirler. Paketli köprü, bu paketin kendi
`app/bridge/ghidra` dizininden kullanılır; `/bridge` yazma veya sudo gerekmez.

Radare2 için `radare2`/`r2` ve `rabin2`; RetDec için `retdec-decompiler` gerekir.
Bunlar bulunmuyorsa araç durum ekranı eksik gösterir; sohbet yine kullanılabilir.
GNU binutils karşılaştırma/strings/ELF audit işlemleri için gereklidir.

Kullanıcıya özel araç komutları `~/.local/bin` altında tutulabilir. Masaüstü
oturumunun PATH'i bu dizini henüz içermiyorsa REHKC onu mevcut PATH'in sonuna
ekleyerek keşif yapar; mevcut PATH ve açık JAVA_HOME/GHIDRA_INSTALL_DIR/
RETDEC_INSTALL_DIR tercihleri önceliğini korur. Ghidra ve RetDec için
`~/.local/opt/ghidra*` ve `~/.local/opt/retdec*` dizinleri de taranır. JDK'nın
`javac` komutuna verilen bir sembolik bağlantı gerçek JDK konumuna çözülür.
Harici araç keşfi indirme yapmaz. Kurucu artık varsayılan olarak yönetilen motor grubunu ayrıca kurar; ayrıntılar aşağıdadır.

## ChatGPT planı

Bulut seçeneği seçildiğinde Continue with ChatGPT, sistem varsayılan tarayıcısını
açar. Uygun hesapla giriş yapıp REHKC/REA için plan kullanım izni verin. Aktif
hesap arayüzde görünür; Kullanımı yönet, ChatGPT izin/kota sayfasını açar.
Kotalar ve hesap tercihlerine bağlı kredi kullanımı ChatGPT ayarlarından yönetilir.
Uygulama API anahtarlı faturalandırmaya geçmez veya kredi satın almaz.

OAuth kayıtları ayar dizinindeki `chatgpt/` altında 0700/0600 izinleriyle korunur.
Bu dizini GitHub'a, hata raporuna veya herkese açık arşive eklemeyin. Resmî akış:
https://developers.openai.com/siwc/token-sharing-open-source/sign-in

## Kaldırma

Kurulu paketin bütünlük ve masaüstü bağımlılıklarını yazmadan tekrar denetlemek için:

```sh
~/.local/share/rehkc/current/install.sh --check
```

Özel konumda kurulduysa aynı `--data-dir` kullanılır. Bu kontrol kurulu paketten
çalışabilir; aynı dizinden kendi üzerine yeniden kurulum koruması devam eder.

Kurulu sürümün kendi kurucusu, kurulum kaydını kullanarak kaldırılabilir:

```sh
~/.local/share/rehkc/current/install.sh --uninstall
```

Özel konumda kurulduysa aynı `--data-dir` kullanılır. Önceden var olan
başlatıcı/menü dosyaları geri konur; kullanıcı sonradan değiştirdiyse korunur.
Ayarlar, hesaplar, sohbetler ve model dosyaları silinmez. Değişmiş/eklenmiş
uygulama dosyaları da korunup raporlanır.

## Kapsam

Cinnamon/X11 ve belirtilen Ubuntu/Plasma ortamı test edilmiştir. ARM,
Alpine/musl, çalıştırma izni olmayan diskler ve tüm Linux dağıtımları için
uyumluluk iddiası yoktur. Ayrıntılı sınırlar docs/KDE-NEXT.md içindedir.

## Debian ve Arch sistem bağımlılıkları

0.2.1'den itibaren `./install.sh --install-system-deps`, `os-release` içindeki
`ID` / `ID_LIKE` değerlerinden Debian/Ubuntu/Kubuntu/Mint ve Arch/CachyOS/Manjaro
ailesini ayırt eder. Debian ailesinde apt-get, Arch ailesinde pacman kullanır;
PATH'te her iki paket yöneticisinin olması seçimi değiştirmez.

Arch komutu `sudo pacman -Syu --needed ...` olduğundan tam sistem güncellemesi
de yapabilir. Pacman'ın onay istemi korunur; ürün kurucusu `--noconfirm`
kullanmaz. Bilinmeyen/çelişkili dağıtım, eksik paket yöneticisi veya paket
kurulumu hatası uygulama kurulumu başlamadan durdurulur. `--check` ile
`--install-system-deps` birlikte kullanılamaz; `--check` salt okunur kalır.

Temiz kurulum komutlarının iki aile için ayrı açıklaması [README](../README.md#kurulum)
içindedir. Motorlar ve JDK, pacman/apt veritabanına eklenmez; kullanıcıya özel,
resmî arşivlerden aynı kurucu ile kurulur. Bu kapsam Debian ve Arch aileleridir.
