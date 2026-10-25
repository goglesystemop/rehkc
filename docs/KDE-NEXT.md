# KDE doğrulaması — 26 Ekim 2026

Ubuntu 26.04.1 LTS x86_64, glibc 2.43, Plasma/KWin 6.6.6 ve Wayland üzerinde
0.1.1 paketi gerçek pencereyle denendi. Aynı paketin XWayland/XCB açılışı ve
%150 Qt ölçeğinde açılışı da geçti. Bu tek KDE makinesinin sonucudur; diğer
dağıtımların, masaüstlerinin veya her ölçeklendirme durumunun doğrulaması değildir.

İlk KDE testinde bulunan kurulu `current/install.sh --check` hatası düzeltildi.
Salt kontrol kurulu paketten çalışabilir; kendi kaynak dizinine tekrar kurma
koruması devam eder. Dağıtım testi bu iki davranışı ve kurulum kaydının
değişmediğini birlikte denetler. Altı dağıtım testi geçti.

Masaüstü oturumunun PATH'i `~/.local/bin` içermediğinde kullanıcı araçlarının
bulunabilmesi için bu dizin mevcut PATH'in sonuna eklenir. Açık ortam değişkenleri
ve mevcut PATH önceliği korunur; iki ayrı keşif testi geçti.

## Gerçek işlev testleri

- 155 motor komutu ve üç sağlayıcı seçeneği yüklendi.
- Başlık okuma/disassembly, Strings, ELF güvenlik özellikleri, hex görünümü,
  arama, yer imi, Türkçe notlar, oturum kaydetme/açma, Markdown dışa aktarım
  ve küçük ELF dosyalarının karşılaştırması geçti.
- Radare2 6.2.4, RetDec 5.0 ve Ghidra 12.1.4/JDK 21 arayüzden çalıştı.
  Bilinen `weighted_total` fonksiyonu gerçek decompiler çıktısında bulundu.
- Global `/bridge` olmadan Ghidra fonksiyon/string listesi ve decompile MCP
  üzerinden de çalıştı. MCP doctor 207 araç ve 6 istemi doğruladı; alt süreç
  kapatılıp toplandı.
- Motorlar kalıcı kullanıcı dizinlerine alındıktan sonra, ek test PATH'i veya
  Ghidra/Java/RetDec ortam değişkeni olmadan GUI/MCP testleri tekrar geçti.
  Menü PATH'i yalnız `/usr/bin:/bin` olduğunda da keşif ve pencere açılışı geçti.
- Ollama'da gerçek Gemma4 12B ile model yükleme, akışlı sohbet, modelin seçili
  dosyada objdump MCP aracını çağırması ve model boşaltma geçti.
- REHKC'ye giriş yapılmış ChatGPT hesabında gerçek model kataloğu, sohbet ve
  seçili test dosyasında objdump MCP araç kullanımı geçti. API anahtarı eklenmedi.

Hedef dosyalar çalıştırılmadı. Gerçek sohbet testleri bağlantı ve araç akışı
kanıtıdır; tüm model yanıtlarının doğruluğunu veya her analiz komutunu doğrulamaz.

LM Studio'nun Gemma modelini içe aldıktan sonraki katalog yenilemesi ve gerçek
sohbeti ayrıca tamamlanmalıdır. KDE portal dosya seçicisi, Dolphin'den elle
sürükleme ve görev çubuğu gruplaması tam doğrulanmış sayılmaz. Testler için
masaüstü ayarları değiştirilmedi veya mevcut oturum üzerine KWin başlatılmadı.
