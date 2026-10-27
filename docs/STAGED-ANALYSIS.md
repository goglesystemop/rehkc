# Aşamalı statik analiz (0.3.0)

MCP sohbeti ve Decompile menüsü hızlı ön incelemeyle başlar. Dosya boyutu,
PE mimarisi/giriş noktası, bölümler, bölüm başına ilk 64 KiB entropi örneği ve
ilk 1 MiB içinden sınırlı string örneği alınır. Sonuç Ghidra beklenmeden görünür.
512 MiB üzeri dosya açık hata verir; dosya boyut sınırı kaldırılmamıştır.

`quick_functions`, rabin2 ile giriş noktalarını ve en fazla 1000 fonksiyon
sembolünü alır. Bu, tam fonksiyon keşfi değildir. MCP politikası önce bu hızlı
kanıtı, sonra gereken tek fonksiyon/adres için `procedure_pseudo_code` kullanır.
Tam keşif istenirse `list_procedures` hâlâ vardır. Ghidra'nın kendi ilk otomatik
analizi global olabilir; bu değişiklik Ghidra'yı artımlı bir motora dönüştürmez.
Radare2'nin hızlı yolu global `-A`/`aaa` çalıştırmaz.

## Önbellek

Başarılı işlem sonuçları kullanıcı veri dizininin `analysis-cache/` klasöründe
saklanır. Hızlı ön inceleme güncel kaynak durumunu göstermek için yeniden alınır. Anahtar: dosyanın SHA256'sı, mutlak yolu, işlem/parametreler, motor
binarileri, analiz modülü/adapter revizyonu, motor kataloğu ve Ghidra/Java ayarları.
Aynı içerikteki dosya başka yola taşınırsa yeniden analiz edilir. Dosya veya motor
kimliği değişirse eski sonuç kullanılmaz. Kullanımdan önce hedefin stat kimliği
tekrar doğrulanır; devam eden analizde dosya değişirse sonuç reddedilir.

Önbellek **tam Ghidra projesi değildir**. Aynı sorgu yeniden JVM analizi başlatmaz;
önbellekte olmayan başka sorgu için aynı pencerenin açık analiz oturumu
kullanılabilir. Oturum kapanmışsa yeniden içe aktarma gerekebilir.
Ham hedef EXE kopyası saklanmaz; analiz çıktısında hassas string/kod bulunabilir.
Dosyalar kullanıcıya özel 0600, klasör 0700 izinleriyle oluşturulur. Bozuk veya
30 günden eski kayıt kullanılmaz. Yazma sırasında yaklaşık 256 MiB/1024 kayıt
kotası korunur; en eski kayıtlar silinir. Tek sonuç en fazla 8 MiB'dir. Kota veya
izin hatası analizi engellemez. Hatalar başarılı Ghidra sonucu diye saklanmaz;
alternatif motor çıktıları kendi kaydı ve sınırlamalarıyla tutulur.

Decompile menüsündeki **Analiz önbelleğini temizle** kayıtları siler.
**Seçili dosyanın önbelleğini temizle** yalnız o dosyanın kayıtlarını siler;
diğer dosyaların sonuçları korunur. **Seçili fonksiyonu yeniden analiz et**
önbelleği okumadan motorları tekrar çalıştırır ve başarılı yeni sonucu saklar.
Ghidra hatası sonrası alternatif motorla alınan sonuç 5 dakika geçerlidir;
sonrasında ana motor yeniden denenir. Açıkça seçilmiş RetDec/Radare2 sonuçları
ve başarılı Ghidra sonuçları normal 30 günlük kurala tabidir.
`REHKC_DISABLE_ANALYSIS_CACHE=1 rehkc` önbellek okuma/yazmasını kapatır.
Araç günlüğünde `cache_hit` görülür. Sohbet oturumunu açmak kayıtlı araçları çalıştırmaz.

## Alternatif motorlar

Ghidra araç çağrısı başarısız olduğunda aynı statik işlem için:

- Fonksiyon envanteri → rabin2 giriş/sembol listesi (kısmi).
- String sorguları → ilk 1 MiB içindeki sınırlı string örneği (kısmi).
- Assembly → Radare2, yalnız seçili adreste en fazla 256 komut.
- C benzeri kod → RetDec seçici çözümleme; hata verirse Radare2 `pdc`.

RetDec adres seçimi en fazla 4096 bayttır ve PE bölümünün sonunda kesilir.
Sembol seçimi tek fonksiyon adı kullanır. `pdc` yaklaşık sözde koddur; gerçek bir
C decompiler ile aynı doğruluk iddia edilmez. Çıktı hangi motordan geldiğini,
önceki motorun hatasını, kısmi kapsamı ve sınırlamaları açıkça taşır. Alternatif
motor da başarısız olursa hata korunur; sonsuz tekrar yapılmaz. Durdur veya toplam
analiz süresi dolduktan sonra başka motor başlatılmaz.

Ghidra heap bütçesi kullanılabilir RAM/cgroup payının yaklaşık üçte biri,
256–4096 MiB aralığıdır. Açık `GHIDRA_HEADLESS_MAXMEM`/`GHIDRA_MAXMEM` korunur.
768 MiB altında yeni Ghidra JVM'si başlatılmaz; RetDec 512 MiB altında atlanır.
RetDec kendi süre sınırıyla, belleği ise dış süreçten uygulanan sert sınırla çalışır.
İç bellek sınırlayıcısının miras alınan sert sınırı yükseltmeye çalışmaması için
RetDec `--no-memory-limit` alır; bu dış bellek sınırını kaldırmaz. Native yardımcılar ayrıca ayrı
çocuk süreçte adres alanı/CPU sınırıyla başlatılır; Qt iş parçacığında preexec_fn
kullanılmaz. Çekirdek dökümleri kapalıdır. Bu ölçümler diğer süreçlerin
sonradan bellek tüketmesini engellemez. Ghidra süreleri önceki politikadaki gibi
ilk çağrıda 930 saniye; MCP toplamı 3600 saniyedir. Menüde tek fonksiyon akışının
toplamı 1800 saniye; bağımsız araç çağrıları da sınırlıdır.

## Paketlenmiş ve korumalı dosyalar

UPX/VMProtect/Themida/ASPack bölüm adları ve yüksek entropili executable bölüm
birer **işaret**tir; korumayı kesin tanımlamaz. Analiz yükleyici kodunu döndürebilir;
bu, asıl payload'ın kaynaklarına ulaşıldığı anlamına gelmez. REHKC hedefi çalıştırmaz,
korumayı otomatik kaldırmaz veya orijinal dosyayı değiştirmez. Motorlar kendi geçici
statik içe aktarma/normalleştirme işlemlerini yapabilir.

Test kapsamı ve sınırlamaları [sürüm notlarında](RELEASE-0.3.0.md) yer alır.
UPX test aracı uygulama bağımlılığı değildir; test için [resmî UPX sürümü](https://github.com/upx/upx/releases/tag/v5.2.1)
kullanılır. Ticari VMProtect/Themida sürümleriyle başarı garantisi yoktur.

İkinci yerel grupta aynı pencere içinde açık analiz oturumunun farklı sorgulara
paylaşılması, PE güvenlik başlıkları ve ilerleme görünümü eklendi. Ayrıntılar:
[İkinci yerel grup](NEXT-LOCAL-BATCH.md).

## Seçili kodu dışa aktarma

Güncel otomatik decompile, RetDec veya Radare2 kod sonucunda `Decompiled C`
veya `Disassembly` sekmesine geçin. Sağ tık → **Seçili kodu dışa aktar…**,
More Tools → Decompilation Engines → aynı seçenek veya **Ctrl+Shift+E** kullanın.
Metin seçiliyse yalnız seçim; seçim yoksa motorun tam kod sonucu aktarılır.
Markdown (`.md`), düz metin (`.txt`) ve yapılandırılmış JSON (`.json`) desteklenir.

Dosya; hedef yolunu, hedef SHA256'sını, fonksiyon/adresi, motoru, bildirilen motor
sürümünü, varsa motor kimliğini ve analiz zamanını, önbellek/oturum durumunu,
paketleyici işaretlerini, sınırlamaları ve alternatif motora geçişte önceki hataları
içerir. Motor sürümü veya eski önbellekte analiz zamanı yoksa `bilinmiyor` yazılır;
kurulu motorun bugünkü sürümü eski sonuca atanmaz. Dışa aktarma zamanı ayrıca UTC
olarak yazılır. Hedef yolu raporda bulunur; paylaşmadan önce gözden geçirin.
Sohbet geçmişi ve hesap ayarları bu dosyaya eklenmez.

Sonuç özgün kaynak kod değildir. Seçimin fonksiyonun tamamını kapsadığı garanti
edilmez; korumalı dosyanın sonucu yalnız yükleyiciye ait olabilir. Hedef değişirse,
çıktı yenilenirse veya kayıtlı oturumdan motor kanıtı olmayan eski metin açılırsa
önce yeniden analiz gerekir. Kod görünümü yeni analiz için değiştiğinde önceki
sonucun dışa aktarma bilgisi kaldırılır.
Hedef dosyanın üzerine yazma engellenir; rapor atomik ve özel izinle kaydedilir.
