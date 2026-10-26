# REHKC 0.2.0

Temiz kurulum artık Ghidra, RetDec, Radare2 ve uyumlu tam JDK'yı resmî
kaynaklardan SHA-256 doğrulayarak kullanıcıya özel kurar. Varsayılan motor
grubu Ghidra 12.1.4 / Temurin JDK 21.0.13+9 / Radare2 6.2.4 / RetDec 5.0'dır.
Bu grup glibc >= 2.34 ve ilk kurulumda internet ister. Uygulama için önceki
glibc 2.28 tabanı `--without-tools` ile korunur.

- Motorlar normal menü başlatıcısından otomatik bulunur; sistem araçları,
  Python/pip ortamı ve elle kurulmuş motorlar değiştirilmez.
- Yeni grup etkinleşmeden önce yerel kitaplıklar, Java/Python sürüm sınırları,
  gerçek Radare2/RetDec/Ghidra analizleri doğrulanır; hata halinde önceki grup korunur.
- Arayüzde **Analiz motorları** menüsü: durum, güncelleme kontrolü, motor kurulumu,
  doğrulanmış motor grubuna güncelleme ve önceki gruba dönüş.
- Kontrol haftalıktır; ağ hatasında ertesi gün denenir. Uygulama kapalıyken
  arka plan servisi çalışmaz; açıkken de arayüz ağ yanıtını beklemez.
- Yeni motor sürümleri, Ghidra'nın Java sınırları, paketli Python yama sürümleri
  ve Python kitaplıklarının `Requires-Python` bilgileri raporlanır.
- Yeni upstream sürümler otomatik kurulmaz. Uyumlu motor kataloğu bakımcı
  doğrulamasıyla güncellenir; Python/Qt değişiklikleri yeni REHKC paketiyle gelir.

Önceki kurucu ve KDE araç keşfi düzeltmeleri korunur. Yerel model sunucuları,
model dosyaları ve isteğe bağlı Ghidra Debugger/PyGhidra bileşenleri dahil değildir.
Ayrıntılar: [Motor kurulumu ve güncellemeler](ANALYSIS-TOOLS.md).
