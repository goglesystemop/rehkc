# 0.3.0 için tamamlanan geliştirme grubu

Öncelikler ve kapsam:

1. Temel string/güvenlik araçlarının ortak motor düzenlemesinden kalan
   uyumsuzluğunu düzeltmek. String çıktısı büyürse bütün sonucu kaybetmek yerine
   ofsetleri ve taranan kapsamı belirten sınırlı parçaları göstermek.
2. Aynı dosyada önbellekte olmayan farklı sorgular için açık Ghidra Program'ını
   yeniden kullanmak. Pencere başına tek, özel, salt okunur MCP oturumu; tek
   eşzamanlı kullanım; 5 dakika boş kalınca otomatik kapatma. Dosya veya motor
   kimliği değişince tekrar kullanılmaz. İptal, hatalı/yarım protokol veya pencere
   kapanışı oturumu bırakır. Menüde elle bırakma ve zorunlu yeniden analiz var.
3. EXE'lerde PE güvenlik başlıkları: DYNAMIC_BASE, NX_COMPAT, GUARD_CF,
   HIGH_ENTROPY_VA, relocation ve sertifika tablosu bildirimleri. Bunlar çalışma
   zamanı koruması veya güvenilir imza kanıtı değildir. Sertifika tablosunun dosya
   içinde olması imzayı doğrulamaz. [Microsoft PE biçimi](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
4. Araç çalışırken işlem, geçen süre ve son gelen araç verisinin yaşı. Byte
   taramasında gerçekten okunan kapsam gösterilir; Ghidra için tahminî yüzde veya
   “kesin takıldı” sonucu üretilmez. Veri gelmemesi uzun otomatik analizde normal
   olabilir. Çıktı verisi faaliyeti anlamlı analiz ilerlemesini kanıtlamaz.

String incelemesi 8-bit/UTF-8 ve ASCII aralığındaki UTF-16LE/BE adaylarını
bulur; en fazla 512 bayt/kod birimlik parçalar gösterir. Ofsetler dosya içindedir.
10.000 kayıt veya 2 MiB metin sınırında sonuç kısmi olarak korunur. Sonuçta taranan
ve toplam baytlar açıkça bulunur; görülmeyen metinlerin bulunmadığı söylenmez.
Dosya değişimi, çıktı ve iptal kontrolleri korunur. Hedefler çalıştırılmaz.

Açık analiz oturumu RAM kullanabilir. **Açık analiz oturumunu bırak** bunu kapatır;
kalıcı işlem sonucu önbelleği korunur. **Seçili fonksiyonu yeniden analiz et**
hem sonuç önbelleğini atlar hem de açık analiz Program'ını yeniden açar.
Önbellek temizleme ve hedef değiştirme de ilgili pencerenin açık oturumunu bırakır.
Uygulamayı kapatmak oturumu siler; sonraki program açılışında farklı bir derin
sorgu yeniden Ghidra analizi gerektirebilir. Oturum kaydetmek çalışan süreç veya
Ghidra projesini dosyaya kaydetmez. Anotasyon/çalıştırma araçları açılmaz.

5. Seçili kod motor bilgisi ve sınırlamalarıyla Markdown, metin veya JSON olarak
   dışa aktarılır. Sağ tık menüsü ve Ctrl+Shift+E kullanılabilir. Hedef SHA256,
   fonksiyon/adres, zaman, önbellek ve alternatif motor bilgileri korunur.
   Hedef/görünüm değişirse eski sonuç yeni hedefe aitmiş gibi aktarılmaz.

Bu grup önce yerel geliştirme paketleriyle doğrulandı; 0.3.0 yayını için
birleştiriliyor. Mevcut tüm oturum Markdown/metin dışa aktarımı korunur.
Sonraki geliştirmeler yine gruplar hâlinde doğrulanır ve yayımlanır.
