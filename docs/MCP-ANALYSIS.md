# MCP / otonom analiz süreleri

0.2.2, Ghidra'nın uzun ilk analizini normal araç sorgularından ayırır. Önceki
istemci her MCP aracını 90 saniyede kesiyordu. Büyük/karmaşık PE dosyalarında
ilk fonksiyon sorgusu Ghidra'nın içe aktarma ve otomatik analizini de bekler;
aynı dosyada 89 saniyede geçen işlem biraz yavaşlayınca kesilebiliyordu.

## Varsayılan bütçeler

| Aşama | Süre |
| --- | --- |
| MCP başlangıcı / araç envanteri | Çağrı başına 30 saniye |
| Ghidra içe aktarma ve ilk otomatik analiz | 900 saniye (15 dakika) |
| İlk Ghidra `open_binary` ve ilk gerçek sorgu | Çağrı başına 930 saniye; Ghidra süresine 30 saniye yanıt payı |
| Sonraki MCP araç çağrıları | 300 saniye (5 dakika) |
| Toplam otonom analiz | 3600 saniye (1 saat) |

`open_binary` bazen hızlıca bir oturum tanımlayıcısı döndürür ve gerçek Ghidra
hazırlığı ilk `list_procedures`/decompile çağrısında olur. Bu nedenle yalnız
`open_binary` başarılı oldu diye uzun ilk analiz bütçesi kaldırılmaz. İlk gerçek
Ghidra sorgusu başarıyla tamamlanınca sonraki sorgular normal bütçeye geçer.
Hatalı bir ilk sonuç bu geçişi tetiklemez. Her yeni sohbet MCP isteği hâlâ özel,
yeni bir analiz oturumu açar; oturumlar arasında analiz önbelleği eklendiği iddia edilmez.

REA'nın kendi `REA_GHIDRA_STARTUP_TIMEOUT_MS` değeri MCP alt süreci için
varsayılan 900000 olarak ayarlanır. Kullanıcının önceden verdiği pozitif değer
korunur ve istemcinin ilk sorgu bütçesi bu değere 30 saniye eklenerek hesaplanır.
Geçersiz değer alt süreç başlatılmadan açık hata verir. Vendor motoru veya
Ghidra betiklerinin analiz kuralları değiştirilmez.

Model bağlantısı ve ağdan veri bekleme sınırları ayrı kalır; Ghidra'nın uzun
sürmesi model ağ zaman aşımı diye gösterilmez. ChatGPT token doğrulaması,
bağlantısı ve akış beklemesi kendi işlem adıyla raporlanır. Normal, MCP'siz
sohbetin süre davranışı değiştirilmez.

## Ekran ve araç günlüğü

İlk sorguda durum alanı **Ghidra ilk analiz** gösterir. Günlükte araç adı ve
bekleme payı yazılır; yanıt süresi sayacı çalışır. Durdur düğmesi kullanılabilir.

Süre gerçekten dolarsa örnek ileti şöyledir (bu bir örnektir):

> Ghidra ilk analiz / list_procedures: araç çağrısı zaman sınırı doldu
> (sınır 930 sn, geçen 930.1 sn).

Hata; işlem adını, dolan bütçenin türünü (araç çağrısı, toplam analiz veya ağ
bekleme), sınırı ve geçen süreyi içerir. Araç/oturum günlüğünde yapılandırılmış
`timeout` alanı tutulur; başarılı önceki araç kayıtları korunur. Oturum dosyaları
eski kayıtlarla uyumlu kalır.

Süre sınırları takılmış süreçlere karşı son güvence olarak korunur; her dosyanın
her koşulda tamamlanacağı garantisi verilmez. Kullanıcı Durdur'a basınca okuma
ve yazma beklemesi kesilir, yalnız ilgili MCP/Ghidra süreçleri temizlenir. Dosya
çalıştırılmaz; aynı seçili-dosya statik araç sınırı korunur.
