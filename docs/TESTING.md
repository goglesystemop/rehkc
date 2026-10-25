# 0.1.1 test sonuçları — 25 Ekim 2026

## Doğrulanan ortamlar

- Makulu AI-OS / Debian trixie, Cinnamon 6.6.9, X11, x86_64, glibc 2.41:
  paketli CPython 3.12.15, PyQt5 5.15.11 / Qt 5.15.19 ile gerçek pencere açıldı.
- Resmî Ubuntu Base 22.04.5 x86_64 dosya sistemi, glibc 2.35: yalnız listelenen
  sistem kitaplıklarıyla izole bubblewrap ortamında aynı paket açıldı. Bu test
  ana makinenin X11/Cinnamon ekran bağlantısını kullandı; ayrı bir Ubuntu Cinnamon
  masaüstü kurulumu veya başka fiziksel makine testi değildir.
- Her iki ortamda XCB pencere platformu, 155 motor komutu ve LM Studio/Ollama/
  ChatGPT sağlayıcıları doğrulandı. Geçici ayarlar ve oturumlar kullanıldı.

## Kurulum ve koruma

`python3 tests/test_distribution.py --package /path/to/unpacked-release`
ile altı test geçti: yazmadan kontrol, bozuk içerik reddi, mevcut başlatıcıyı
koruma/açık yedekleyerek değiştirme/geri yükleme, temiz ve tekrar kurulum,
kaldırırken kullanıcı verisini koruma, değiştirilmiş başlatıcıyı koruma ve ev
dizinine kurulumun reddi (bazıları aynı test içinde).

Boşluk/Türkçe/özel karakter içeren kurulum yolları denendi. Masaüstü girdisi gerçek
GLib/Gio ile başlatıldı; yalnız metin karşılaştırması yapılmadı. Makinedeki eski
REA başlatıcısı, GUI ayarları ve sohbet dosyalarının hash'leri aynı kaldı.

## Entegrasyonlar

Paketli Python ve uygulama modülleri üzerinde 16 kontrol grubu geçti:
ChatGPT protokol regresyonları; Ghidra fonksiyon envanteri; Copilot/MCP;
model yükle/boşalt; doctor/MCP bağlantısı; araç durumu; Strings/Security Audit;
komut envanteri; analiz işçisi yaşam döngüsü ve gecikmiş hedef sonucu; akış hataları;
arama; notlar; karşılaştırma; Radare2/RetDec; gerçek Ghidra GUI decompile;
LM Studio/Ollama üzerinden gerçek GUI sohbeti.

Ghidra 12.1.4 / JDK 21 ile `weighted_total` gerçek fonksiyon listesinde bulundu
ve C çıktısı üretildi. Bağımsız MCP istemcisi fonksiyon listesi, pseudo-code ve
string araçlarını kullandı. Global `/bridge` dizini gizlenmiş ayrı kontrolde de
paketin kendi köprüsüyle gerçek decompile başarılı oldu. RetDec 5.0 ve kurulu
Radare2 menü eylemleri gerçek hedefte çalıştı. Hedef dosya çalıştırılmadı.

LM Studio'da OpenHermes 2.5 Mistral 7B ve Ollama'da kurulu Gemma modeliyle boş
olmayan yanıt alındı. Bu bir bağlantı/akış testidir; yanıtın talimata uyumu veya
analiz doğruluğu ölçümü değildir. Test için yüklenen modeller sonrasında boşaltıldı.

ChatGPT hesabının gerçek model kataloğu paketli çalışma ortamından alındı.
Yeni sohbet isteği `subscription_sharing_usage_limit_exceeded` ile sınırlandı;
**bu sürüm testinde yeni bir başarılı bulut yanıtı elde edildiği iddia edilmez**.
Önceki geliştirme ortamında başarılı bulut sohbeti/MCP kanıtı vardı. Yeni pakette
OAuth/protokol regresyonları geçti; gerçek sohbet kota yenilendikten sonra yeniden
sınanabilir. Kurucu hesap kotalarını veya ödeme ayarlarını değiştirmez.

## Testte bulunan ve giderilenler

İlk 0.1.0 yayımından yapılan temiz klon/indirme/kurulum/açılış testi geçti;
kurulu `current/install.sh --uninstall` komutu ise kaynak/kurulum dizini çakışma
korumasına takıldı. 0.1.1 bu kontrolü kaldırma işlemi için düzeltir; tehlikeli
kök/ev dizini kontrolü korunur. Dağıtım testi artık kaldırıcıyı kurulu sürümün
kendi dizininden çağırır. Önceki 0.1.0 sürümü yerine 0.1.1 kullanılmalıdır.


Temiz Ubuntu ortamında eksik GLib ve XCB Shape kitaplıkları kurulum listesine
eklendi. Doctor kontrolü yalnız XCB eklentisini değil QtCore/QtGui/QtWidgets
uzantılarını da denetleyecek şekilde genişletildi. Test düzeneklerindeki farklı
filesystem üzerinde hardlink, GLib'in executable metni ayrıştırması, geçici dizin
izinleri ve boş rootfs machine-id sorunları giderilerek kontroller tekrarlandı.

## Sınırlar

KDE/Plasma, Wayland, ARM, Alpine/musl ve her Cinnamon dağıtımı test edilmiş değildir.
Ubuntu Base testi donanım sürücüleri ve tam masaüstü entegrasyonunun yerini tutmaz.
İlk sürüm x86_64/glibc için hazırlanmıştır; KDE kontrol listesi ayrı tutulur.
