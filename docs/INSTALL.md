# Cinnamon kurulumu

Bu sürümün hedefi x86_64 Linux/Cinnamon/X11 ve glibc >= 2.28'dir. Paket CPython
3.12 ve Qt5/PyQt5 içerir; kullanıcının Python ortamına pip kurulumu yapılmaz.
Sistem OpenGL/X11/font/D-Bus kitaplıkları ve çalışan bir Cinnamon oturumu gerekir.
`run --doctor`, eksik XCB kitaplıklarını ve bulunan isteğe bağlı araçları raporlar.

## Kurucu davranışı

- Uygulama: `${XDG_DATA_HOME:-~/.local/share}/rehkc/releases/0.1.1`.
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

Arşivden kurulum ağ gerektirmez. İlk kaynak depo kurulumunda arşiv GitHub'dan
indirilir; ağ ve sistem Python'unun güncel tarfile güvenli açma desteği gerekir.

## Analiz araçları

Sunucular varsayılan olarak LM Studio `127.0.0.1:1234`, Ollama `127.0.0.1:11434`.
Başka port veya anahtar kullanılıyorsa Rea ayarlarından mevcut sunucuyu seçin.
Yerel sunucular ve model dosyaları bu pakete dahil değildir.

Ghidra kurulumunuzda `support/analyzeHeadless` bulunmalı. Önceden ayarlı
`GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `RETDEC_INSTALL_DIR` değerleri korunur.
Yoksa PATH, `~/.local/opt/`, `/opt/` ve standart Ghidra konumları taranır. Ghidra
12.1.4 ve tam 64-bit JDK 21 doğrulanmış mevcut entegrasyondur; başka sürümün
uygunluğunu gerçek doctor raporu belirler. Paketli köprü, bu paketin kendi
`app/bridge/ghidra` dizininden kullanılır; `/bridge` yazma veya sudo gerekmez.

Radare2 için `radare2`/`r2` ve `rabin2`; RetDec için `retdec-decompiler` gerekir.
Bunlar bulunmuyorsa araç durum ekranı eksik gösterir; sohbet yine kullanılabilir.
GNU binutils karşılaştırma/strings/ELF audit işlemleri için gereklidir.

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

Kurulu sürümün kendi kurucusu, kurulum kaydını kullanarak kaldırılabilir:

```sh
~/.local/share/rehkc/current/install.sh --uninstall
```

Özel konumda kurulduysa aynı `--data-dir` kullanılır. Önceden var olan
başlatıcı/menü dosyaları geri konur; kullanıcı sonradan değiştirdiyse korunur.
Ayarlar, hesaplar, sohbetler ve model dosyaları silinmez. Değişmiş/eklenmiş
uygulama dosyaları da korunup raporlanır.

## Kapsam

Cinnamon X11 bu ilk sürümün test hedefidir. Wayland/KDE, ARM, Alpine/musl ve
çalıştırma izni olmayan diskler için uyumluluk iddiası yoktur. KDE için sonraki
makinede yapılacak işler docs/KDE-NEXT.md içindedir.
