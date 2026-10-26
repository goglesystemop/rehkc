# REHKC — REA Linux Desktop

Cinnamon üzerinde geliştirilmiş bağımsız REA masaüstü dağıtımı. Makulu üzerinde birlikte
geliştirilen arayüzü, kullanıcı adına bağlı kurulum yollarından ayırır.

**Paket hedefi:** Linux x86_64; uygulama için glibc >= 2.28, otomatik motor
kurulumu için glibc >= 2.34. Cinnamon/X11 yanında
Ubuntu 26.04.1 / Plasma 6.6.6 Wayland ve XWayland üzerinde de test edildi.
Bu tek KDE ortamının sonucudur; ARM ve her Linux dağıtımı doğrulanmış sayılmaz.
[KDE test kapsamı](docs/KDE-NEXT.md).

## Kurulum

### Debian / Ubuntu / Kubuntu / Linux Mint: GitHub’dan temiz kurulum

64-bit x86_64 Linux ve internet bağlantısı gerekir. Motorlu kurulum glibc >= 2.34
ister. İlk kurulum yaklaşık 1,2 GB uygulama/motor/JDK arşivi indirir; açma ve
kurulum işlemleri için rahat pay bırakmak üzere 8 GB boş alan ayırın.

**1. Git, Python ve sertifikaları kurun:**

```sh
sudo apt update
sudo apt install -y git python3 ca-certificates
```

**2. Depoyu indirin ve kurucuyu çalıştırın:**

```sh
git clone https://github.com/goglesystemop/rehkc.git
cd rehkc
./install.sh --install-system-deps
```

Kurucuyu `sudo ./install.sh` şeklinde çalıştırmayın. Gereken sistem kitaplıkları
ve binutils için kurucu kendisi sudo parolası ister. Uygulama ve motorlar
kullanıcınıza özel kurulur; Ghidra, uyumlu tam Java JDK, RetDec ve Radare2 otomatik
indirilir, hash ve gerçek analiz kontrollerinden sonra etkinleştirilir.
Sistemdeki Python/pip ortamı değiştirilmez.

Kaynak kurucu, yayımlanan sürüm arşivini GitHub’dan SHA-256 doğrulayarak kullanır.
Sistem Python’unun güncel `tarfile` güvenli açma desteği gerekir; eski bir
Python’da bu destek yoksa aşağıdaki sürüm arşivi yöntemi kullanılabilir.

**3. Sürümü ve motorları kontrol edin, ardından uygulamayı açın:**

```sh
~/.local/bin/rehkc --version
~/.local/bin/rehkc --tools status
~/.local/bin/rehkc
```

0.2.0 sürümü için ilk komut `REHKC 0.2.0 / REA 6.7.0` yazmalı;
motor durumunda `"managed": true` ve sağlık bölümünde `"ok": true` görünmelidir.
Sonraki açılışlarda uygulama menüsündeki **REHKC** simgesini kullanabilirsiniz.
Haftalık güncelleme kontrolü uygulama açıkken otomatik yapılır; elle kontrol için:

```sh
~/.local/bin/rehkc --tools check-updates
```

LM Studio/Ollama ve model dosyaları ayrıca kurulur. Ayrıntılar:
[Kurulum](docs/INSTALL.md), [Motor kurulumu ve güncellemeler](docs/ANALYSIS-TOOLS.md).

**Arch / CachyOS / Manjaro:** Yukarıdaki `apt` komutları bu dağıtımlar için
değildir. 0.2.0’daki `--install-system-deps` yalnız `apt-get` destekler;
`pacman` ile otomatik sistem bağımlılığı kurulumu henüz yoktur. Bu dağıtımlarda
REHKC’nin çalışması henüz gerçek kurulum testiyle doğrulanmadı.

### Sürüm arşivinden kurulum

[Releases](https://github.com/goglesystemop/rehkc/releases) sayfasından
`rehkc-0.2.0-linux-x86_64.tar.gz` ve `SHA256SUMS` dosyalarını indirin:

```sh
sha256sum -c SHA256SUMS
tar -xzf rehkc-0.2.0-linux-x86_64.tar.gz
cd rehkc-0.2.0-linux-x86_64
./install.sh --check
./install.sh
```

Menüden **REHKC** açılır; terminal komutu `~/.local/bin/rehkc` olur. Sistemdeki
Python/Qt sürümlerini değiştirmez; çalışma ortamı paketin içindedir. Mevcut `rea-app`
ve onun ayar/oturumları üzerine yazılmaz.

Sistem kitaplığı eksikse:

```sh
./install.sh --print-system-deps
# Debian/Ubuntu/Mint'te yalnız listelenen gerekli kitaplıkları kurmak için:
./install.sh --install-system-deps
```

## Özellikler

- LM Studio ve Ollama: model listesi, bellek durumu, seçili modeli yükle/boşalt,
  akışlı yanıt, bağlam sınırı, gerçek yanıt modeli ve süre.
- ChatGPT planı: resmî tarayıcı girişi, hesap seçimi/çıkış, hesaba ait model listesi.
  API anahtarı gerektirmez; hesabın plan uygunluğu, izinleri ve kotaları geçerlidir.
- Copilot: seçili dosyada sınırlandırılmış, gerçek MCP analiz araçlarını kullanır.
  Araç günlüğü, oturum kaydetme ve dışa aktarım korunur.
- Ghidra: gerçek fonksiyon listesi ve decompile; global `/bridge` kurulumu gerekmez.
- Mevcut Radare2/RetDec adaptörleri, Strings/Security Audit, seçili kod eylemleri,
  analizde arama, notlar/yer imleri ve iki dosya karşılaştırması.

Kurucu Ghidra, uyumlu JDK, Radare2 ve RetDec'i kullanıcıya özel kurar. Haftalık
sürüm ve bağımlılık kontrolü yapar; doğrulanmış motor grupları menüden
güncellenebilir. [Motor kurulumu ve güncellemeler](docs/ANALYSIS-TOOLS.md).
Model sunucuları ve model dosyaları ayrıca kurulur.
Küçük yerel modeller gerçek araç çıktısını yanlış yorumlayabilir; yorum ile
Ghidra/MCP kanıtını aynı şey saymayın.

## Tanılama

```sh
./run --doctor
./run --smoke-test
./run --engine mcp doctor --json
```

[Test kapsamı ve sonuçları](docs/TESTING.md). Başka bir masaüstünün veya her Linux
dağıtımının denenmiş olduğu iddia edilmez.

## Geliştirme

`app/` masaüstü kaynaklarıdır; `packaging/` sabitlenmiş girdileri ve yapım betiğini
içerir. [Derleme](docs/BUILD.md). Kullanıcı ayarları, OAuth token'ları, sohbetler,
kişisel hedef dosyaları ve büyük motor/runtime ikilileri Git'e eklenmez.

GPLv3 masaüstü dağıtımı; orijinal bileşenlerin lisansları korunur.
[Bileşenler ve kaynak bağlantıları](THIRD_PARTY_NOTICES.md).
