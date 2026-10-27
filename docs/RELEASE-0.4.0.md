# REHKC 0.4.0

Analiz sohbeti, kaydedilmiş kodun geri açılması ve fonksiyon seçimi için üç
geliştirme tek sürümde toplandı.

- Aynı soru içinde aynı araç ve JSON parametreleri tekrar istenirse önceki gerçek
  sonuç veya hata kullanılır; motor ve araç bütçesi yeniden tüketilmez. Tamamı
  tekrar olan turdan sonra araçlar kapatılıp mevcut kanıtla son yanıt beklenir.
  Yeni soru yeniden deneyebilir; iptal ve hedef değişimi kontrolleri korunur.
- Yeni kaydedilen oturumlar kodun motor bilgilerini, analiz zamanını,
  sınırlamalarını ve görünüm özetini korur. Açılışta hedef SHA256'sı arka planda
  doğrulanmadan dışa aktarma açılmaz. Eşleşen kod motor yeniden çalıştırılmadan
  Markdown, metin veya JSON olarak aktarılır. Eski oturumlar açılmaya devam eder;
  motor bilgisi olmayan eski kayıtlar için yeniden analiz gerekir.
- **Fonksiyonlar…** düğmesiyle giriş/sembol listesini ad veya adresle filtreleyip
  seçilen tam adresi Ghidra → RetDec → Radare2 akışında analiz edebilirsiniz.
  Aynı adresteki takma adlar birleştirilir; hedef değişirse eski seçim kullanılmaz.

Hızlı giriş/sembol listesi tam fonksiyon envanteri değildir; sembolleri silinmiş
veya korumalı dosyada yalnız giriş noktası bulunabilir. Kayıtlı motor bilgisi,
sonradan düzenlenmiş bir oturumun geçmişini kriptografik olarak doğrulamaz.
Analizler statiktir; özgün kaynak kurtarma veya tüm korumaları çözme garantisi yoktur.

Yerel doğrulamada 148 davranış/GUI ve 6 dağıtım/kurulum testi geçti. Normal
başlatıcıdan gerçek Ghidra ile fonksiyon seçimi, önbellek kapalı kontrollü tekrar
senaryosunda iki aynı isteğin tek motor çağrısına dönüşmesi ve kayıtlı kodun
motor yeniden çalıştırılmadan dışa aktarılması doğrulandı. Gerçek ChatGPT sohbeti
de tamamlandı. Değişmiş içerik (aynı boyut/mtime dahil), eksik hedef, bozuk kayıt,
iptal ve hedef/görünüm değişimi sınandı. Hedef örnekleri çalıştırılmadı.

Ghidra, JDK, RetDec ve Radare2'nin sabitlenmiş motor grubu korunur. Kurulum ve
haftalık motor güncelleme kontrolü önceki sürümle aynı akışı kullanır.
