# 0.4.0 analiz iş akışı geliştirme grubu

Bu üç geliştirme yerelde doğrulandı ve kullanıcının talimatıyla 0.4.0
yayınında birleştiriliyor. Yayın arşivi metadatası doğrulanmış GitHub Actions
paketinden sonra otomatik güncellenir.

Önem sırası ve uygulanan kapsam:

1. **Sohbette yinelenen araç istekleri.** Aynı soru içinde aynı araç ve JSON
   parametreleri tekrar gelirse önceki gerçek sonuç veya hata aynen kullanılır;
   motor ve araç bütçesi yeniden tüketilmez. Parametre sırası eşdeğerdir; farklı
   parametre yeni istektir. Tamamı tekrar olan bir turdan sonraki model isteğinde
   araçlar kapatılır, mevcut kanıtla yanıt beklenir. Yeni soru eski geçici listeyi
   kullanmaz; dosya değişimi/iptal kontrolü tekrar sonuçlarında da korunur.
   Bu, modelin ilk seferde doğru araç seçmesini garanti etmez. Tekrarların özgün
   çağrı kimliği oturum kaydındaki `reused_tool_requests` alanında bulunur.
2. **Kaydedilmiş kodun motor bilgisini geri getirme.** Oturum kaydı görünüm
   SHA256'sını, kodu ve dışa aktarma provenansını taşır. Açılışta alanlar doğrulanır;
   hedefin SHA256'sı arka planda hesaplanıp eşleşmeden kod dışa aktarma açılmaz.
   Hedef yoksa/değişmişse görünüm ve sohbet korunur; yeniden analiz gerekir.
   Kod görünümü değişirse veya doğrulama iptal edilirse eski motor bilgisi yeni
   görünüme bağlanmaz. Motor yeniden çalıştırılmaz; eski analiz zamanı/sürümü
   korunur. Bu kontrol kullanıcı tarafından düzenlenmiş bir oturumun motor
   geçmişinin kriptografik doğrulaması değildir. Eski oturumlar açılır; motor
   bilgisi olmayan eski kayıtlar için yeniden analiz gerekir. Hedef 512 MiB
   sınırı ve kayıt 64 MiB sınırı korunur.
3. **Aranabilir fonksiyon seçici.** Analiz arama çubuğundaki **Fonksiyonlar…**
   veya More Tools → Decompilation Engines → **Fonksiyon bul ve analiz et…**.
   Rabin2 giriş/sembollerini hızlı okur; global aa/aaa veya otomatik Ghidra tam
   envanteri başlatmaz. Ad veya adresle filtrelenir; seçim tam gözlenen adresle
   mevcut Ghidra → RetDec → Radare2 akışını başlatır. Takma adlar aynı adreste
   birleştirilir. Liste en çok 1032 girişten oluşur ve tam envanter değildir;
   sembolü silinmiş/korumalı dosyalarda yalnız giriş noktası görülebilir.
   Hedef değişirse açık listeden gelen eski seçim kullanılmaz.

Yerel paket normal kullanıcı kurucusuyla yüklenir. Bir sonraki resmî sürüm,
kullanıcının toplu GitHub yayını talimatından sonra hazırlanır.
