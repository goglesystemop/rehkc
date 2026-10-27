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

0.2.2 sürümü için ilk komut `REHKC 0.2.2 / REA 6.7.0` yazmalı;
motor durumunda `"managed": true` ve sağlık bölümünde `"ok": true` görünmelidir.
Sonraki açılışlarda uygulama menüsündeki **REHKC** simgesini kullanabilirsiniz.
Haftalık güncelleme kontrolü uygulama açıkken otomatik yapılır; elle kontrol için:

```sh
~/.local/bin/rehkc --tools check-updates
```

LM Studio/Ollama ve model dosyaları ayrıca kurulur. Ayrıntılar:
[Kurulum](docs/INSTALL.md), [Motor kurulumu ve güncellemeler](docs/ANALYSIS-TOOLS.md).

### Arch / CachyOS / Manjaro: GitHub’dan temiz kurulum

Pacman desteği **0.2.1** sürümünde bulunur; eski 0.2.0 arşivinde yoktur.
64-bit x86_64, glibc >= 2.34, internet ve yukarıdaki boş alan koşulları geçerlidir.

**1. Sistemi güncelleyin ve indirme araçlarını kurun:**

```sh
sudo pacman -Syu --needed git python ca-certificates
```

**2. Aynı depoyu indirin ve kurucuyu çalıştırın:**

```sh
git clone https://github.com/goglesystemop/rehkc.git
cd rehkc
./install.sh --install-system-deps
```

Kurucu `/etc/os-release` bilgisinden Arch ailesini tanır; sistem kitaplıklarını,
X11/Wayland bağımlılıklarını, yazı tiplerini ve binutils araçlarını
`sudo pacman -Syu --needed ...` ile kurar. `-Syu` sistemin tamamı için güncelleme
yapabilir; pacman işlem listesini ve onayını gösterir. Paket kurulumu başarısız
olursa uygulama kurulumu devam etmez. Kurucuyu ayrıca sudo ile çalıştırmayın.

Ghidra, JDK, RetDec ve Radare2 için ayrı Arch/AUR paketi kurmanız gerekmez;
aynı kurucu resmî, hash ile sabitlenmiş motor grubunu kullanıcıya özel kurar.

**3. Kontrol edin ve açın:**

```sh
~/.local/bin/rehkc --version
~/.local/bin/rehkc --tools status
~/.local/bin/rehkc
```

Sürüm `REHKC 0.2.2 / REA 6.7.0`, motor sağlığı `"ok": true` olmalıdır.
Sonrasında menüdeki **REHKC** simgesini kullanabilirsiniz. İki dağıtım ailesi de
aynı kurucuyu, motorları ve haftalık güncelleme kontrolünü kullanır.

Dağıtım seçimini ve paket listesini kurulum yapmadan görmek için her iki ailede:

```sh
./install.sh --print-system-deps
```

GitHub kontrolü Arch kapsayıcısında gerçek pacman bağımlılık kurulumu ve analiz
motoru testlerini çalıştırır. Bu, CachyOS/Manjaro üzerinde gerçek KDE/Wayland
masaüstü testinin yapıldığı anlamına gelmez.

### Sürüm arşivinden kurulum

[Releases](https://github.com/goglesystemop/rehkc/releases) sayfasından
`rehkc-0.2.2-linux-x86_64.tar.gz` ve `SHA256SUMS` dosyalarını indirin:

```sh
sha256sum -c SHA256SUMS
tar -xzf rehkc-0.2.2-linux-x86_64.tar.gz
cd rehkc-0.2.2-linux-x86_64
./install.sh --check
./install.sh
```

Menüden **REHKC** açılır; terminal komutu `~/.local/bin/rehkc` olur. Sistemdeki
Python/Qt sürümlerini değiştirmez; çalışma ortamı paketin içindedir. Mevcut `rea-app`
ve onun ayar/oturumları üzerine yazılmaz.

Sistem kitaplığı eksikse:

```sh
./install.sh --print-system-deps
# Debian/Arch ailesinde uygun paket yöneticisiyle kurmak için:
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
MCP/Ghidra ilk analiz süreleri, durdurma ve hata ayrıntıları:
[MCP analiz süreleri](docs/MCP-ANALYSIS.md).
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
