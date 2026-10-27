# REHKC 0.3.0

Büyük veya paketlenmiş dosyalarda her sorunun tam analiz beklemesini azaltan
hızlı ön inceleme, işlem sonucu önbelleği ve alternatif motor akışı eklendi.

- MCP sohbeti ve menüden decompile hızlı PE/boyut/entropi ön incelemesi gösterir.
- Giriş/sembol keşfi global Radare2 analizi gerektirmez; derin sorgu seçilen
  fonksiyona yönlendirilir. Ghidra'nın ilk otomatik analizi hâlâ global olabilir.
- Başarılı sonuçlar dosya SHA256'sı ve motor/ayar kimliğiyle saklanır. Bozuk,
  değişmiş veya eski kayıt kullanılmaz; menüden temizlenebilir.
- Ghidra hatasında seçici RetDec ve uygun Radare2 işlemleri denenir. Çıktı motoru,
  hata nedeni ve kısmi kapsam açıkça görünür; iptal motor geçişini durdurur.
- Kaynak bütçeleri RAM/cgroup durumuna göre ayarlanır; kullanıcı ayarları korunur.
- Aynı pencerede farklı sorgular açık Ghidra analizini yeniden kullanır; 5 dakika
  boş kalınca, hedef değişince veya pencere kapanınca oturum bırakılır.
- String incelemesi büyük çıktıyı ofset ve taranan kapsamıyla kısmi olarak korur.
  PE güvenlik başlıkları ve ELF güvenlik gözlemleri yeniden kullanılabilir.
- Çalışan işlem, geçen süre ve son araç verisinin yaşı gösterilir. Ghidra için
  tahminî ilerleme yüzdesi verilmez.
- Seçili kod Markdown, metin veya JSON olarak dışa aktarılır (sağ tık veya
  Ctrl+Shift+E). Motor, hedef SHA256, fonksiyon/adres, zaman, önbellek durumu,
  sınırlamalar ve alternatif motor hataları raporda korunur.
- Seçili dosyanın önbelleği temizlenebilir; seçili fonksiyonun zorunlu yeniden
  analizi hem sonuç önbelleğini atlar hem de açık Ghidra analizini yeniler.

Süre sınırları ve seçili dosya statik analiz sınırı korunur. Her korumanın
çözüleceği veya özgün kaynağın geri geleceği iddia edilmez. Ayrıntılar:
[Aşamalı analiz](STAGED-ANALYSIS.md).

Doğrulama: üretilmiş 32 MiB PE ve resmî UPX 5.2.1 ile paketlenmiş kopyası,
Ghidra seçili fonksiyon çözümü ve sonraki oturumdan önbellek kullanımıyla sınandı.
Kontrollü Ghidra hatasında gerçek RetDec/Radare2 akışı çalıştı. UPX örneğinde
RetDec komut çözemedi; Radare2'nin yaklaşık sözde kodu kısmi olarak raporlandı.
Bu test ticari VMProtect/Themida korumalarının çözüldüğü anlamına gelmez.

Yerel son doğrulama: 119 davranış/GUI testi ve 6 dağıtım/kurulum testi geçti.
Normal başlatıcıdan Ghidra, RetDec ve Radare2 sonuçları üç dışa aktarma biçiminde
ve yalnız metin seçimiyle doğrulandı. Orijinal dosya ve kullanıcı durumu korundu.
Gerçek sohbette ikinci farklı sorgu açık Ghidra oturumunu yeniden kullandı.
Motor sonucu sürüm bildirmiyorsa dışa aktarılan sürüm `bilinmiyor` olur;
sertifika tablosu bildirimi imza doğrulaması değildir.
