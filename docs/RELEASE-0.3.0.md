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

Süre sınırları ve seçili dosya statik analiz sınırı korunur. Her korumanın
çözüleceği veya özgün kaynağın geri geleceği iddia edilmez. Ayrıntılar:
[Aşamalı analiz](STAGED-ANALYSIS.md).

Doğrulama: üretilmiş 32 MiB PE ve resmî UPX 5.2.1 ile paketlenmiş kopyası,
Ghidra seçili fonksiyon çözümü ve sonraki oturumdan önbellek kullanımıyla sınandı.
Kontrollü Ghidra hatasında gerçek RetDec/Radare2 akışı çalıştı. UPX örneğinde
RetDec komut çözemedi; Radare2'nin yaklaşık sözde kodu kısmi olarak raporlandı.
Bu test ticari VMProtect/Themida korumalarının çözüldüğü anlamına gelmez.
