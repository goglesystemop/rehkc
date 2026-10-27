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
önbellekte olmayan başka sorgu yeni oturumda yeniden içe aktarma gerektirebilir.
Ham hedef EXE kopyası saklanmaz; analiz çıktısında hassas string/kod bulunabilir.
Dosyalar kullanıcıya özel 0600, klasör 0700 izinleriyle oluşturulur. Bozuk veya
30 günden eski kayıt kullanılmaz. Yazma sırasında yaklaşık 256 MiB/1024 kayıt
kotası korunur; en eski kayıtlar silinir. Tek sonuç en fazla 8 MiB'dir. Kota veya
izin hatası analizi engellemez. Hatalar başarılı Ghidra sonucu diye saklanmaz;
alternatif motor çıktıları kendi kaydı ve sınırlamalarıyla tutulur.

Decompile menüsündeki **Analiz önbelleğini temizle** kayıtları siler.
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
RetDec kendi bellek ve süre sınırlarıyla çalışır. Native yardımcılar ayrıca ayrı
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
