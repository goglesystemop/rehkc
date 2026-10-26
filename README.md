# REHKC — REA Linux Desktop

Cinnamon üzerinde geliştirilmiş bağımsız REA masaüstü dağıtımı. Makulu üzerinde birlikte
geliştirilen arayüzü, kullanıcı adına bağlı kurulum yollarından ayırır.

**Paket hedefi:** Linux x86_64, glibc 2.28 veya üzeri. Cinnamon/X11 yanında
Ubuntu 26.04.1 / Plasma 6.6.6 Wayland ve XWayland üzerinde de test edildi.
Bu tek KDE ortamının sonucudur; ARM ve her Linux dağıtımı doğrulanmış sayılmaz.
[KDE test kapsamı](docs/KDE-NEXT.md).

## Kurulum

[Releases](https://github.com/goglesystemop/rehkc/releases) sayfasından
`rehkc-0.1.2-linux-x86_64.tar.gz` ve `SHA256SUMS` dosyalarını indirin:

```sh
sha256sum -c SHA256SUMS
tar -xzf rehkc-0.1.2-linux-x86_64.tar.gz
cd rehkc-0.1.2-linux-x86_64
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

Kaynak depodan aynı sürümü kurmak için:

```sh
git clone https://github.com/goglesystemop/rehkc.git
cd rehkc
./install.sh
```

Kaynak kurucu, bu deponun sürüm arşivini SHA-256 ile doğrulayıp kullanır; anahtar,
oturum veya model dosyası istemez. Ayrıntılar: [Kurulum](docs/INSTALL.md).

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

Ghidra/Java/Radare2/RetDec ve model sunucuları isteğe bağlı harici araçlardır;
kurucu bunları indirmez, yükseltmez veya yeniden kurmaz. [Entegrasyonlar](docs/INSTALL.md#analiz-araçları).
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
