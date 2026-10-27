# Yönetilen analiz motorları

Kurucu varsayılan olarak Ghidra, RetDec, Radare2 ve Ghidra için tam JDK indirir.
İndirme kaynakları ve SHA-256 değerleri `app/analysis-tools.json` içinde sabittir.
Motorlar sistem paketlerinin veya elle kurduğunuz araçların üzerine yazılmaz;
uygulamanın kurulum dizinindeki `tools/releases/` altında birlikte tutulur.

Bu değişiklikte doğrulanan grup: Ghidra 12.1.4, Temurin JDK 21.0.13+9,
Radare2 6.2.4, RetDec 5.0 ve REHKC'nin paketli CPython 3.12 ortamı.
REA 6.7.0 yalnız Ghidra 12.1.x hattını kabul eder. Ghidra 12.2 kendi
başına Java 25 ile çalışsa bile bu REA sürümüyle kullanılamaz. Bu yüzden yeni
upstream sürüm bildirilir ama onaylı katalogda 12.1.4 ve Java 21 tutulur.
Kaynak: [Ghidra 12.2 gereksinimleri](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.2_build/GhidraDocs/GettingStarted.md).

## Kurulum

```sh
./install.sh
# Sistem masaüstü kitaplıkları/binutils eksikse Debian/Ubuntu/Mint veya Arch/CachyOS/Manjaro üzerinde:
./install.sh --install-system-deps
```

Motorlar için ilk kurulumda internet ve en az 5 GiB boş alan gerekir.
İndirilecek motor/JDK arşivlerinin toplamı yaklaşık 975 MB'dir (ondalık).
Uygulama arşivi buna dahil değildir. Motorlu kurulum x86_64 glibc >= 2.34 ister;
uygulamanın kendisinin tabanı glibc 2.28 olarak kalır. 0.2.1 kurucusu Debian ailesinde apt-get, Arch ailesinde pacman ile gereken
paylaşılan masaüstü/Java kitaplıklarını kurabilir. Destek kapsamı bu iki ailedir.
Java'nın GUI kitaplıkları, native Ghidra decompiler ve RetDec bağımlılıkları
kurulum sırasında `ldd` ile, Java derleyicisi/motor sürümleri gerçek komutlarla
kontrol edilir. Uyumsuzlukta yeni grup etkinleştirilmez.

Yalnız uygulamayı çevrimdışı kurmak veya harici motor kullanmak için:

```sh
./install.sh --without-tools
# Sonradan paketin sabitlenmiş motor grubunu kur:
rehkc --tools install
rehkc --tools status
```

Kaynak depodan kurucu yayımlanmış paketi indirir. Bu nedenle kaynak değişikliğinin
kullanıcılara ulaşması için yeni sürüm arşivi de yayımlanmalıdır.

`--check` ağ bağlantısı veya motor kurulumu yapmaz. Dağıtım testleri bu nedenle
uygulama kurulumu için `--without-tools` kullanır; motor kurulumunun ağdan/boş
hedefte gerçek testi ayrı yapılır. `REHKC_TOOLS_DIR` özel motor hedefi ve test
izolasyonu için kullanılabilir; varsayılan hedef `REHKC_INSTALL_ROOT/tools`, o
ayarlı değilse XDG kullanıcı uygulama dizinidir.

Normal başlatıcı yönetilen grubu otomatik kullanır. Açık `JAVA_HOME`,
`GHIDRA_INSTALL_DIR`, `RETDEC_INSTALL_DIR` tercihleri önceliklidir. Yönetilen
Radare2 komutları yalnız REHKC'nin alt süreç PATH'ine eklenir; kendi kitaplık
arama yollarını yalnız kendi süreçleri için ayarlar. Global `LD_LIBRARY_PATH`,
sistem Python'u veya kullanıcı pip ortamı değiştirilmez. Sistem Python'una
bağlı kalmamak için motor yardımcılarının Python komutu paketli yorumlayıcıya
gider. Ana RetDec decompiler native bir programdır; Ghidra köprüsü Java
betikleri kullanır. İsteğe bağlı Ghidra Debugger/PyGhidra kurulumları bu özelliğin
kurduğu bileşenler arasında değildir.

## Güncelleme sıklığı ve uyumluluk

REHKC açıldıktan sonra kontrol arka planda yapılır; arayüzün açılması ağı beklemez.
Başarılı kontrolden sonra **7 gün** beklenir. Uygulama uzun süre açık kaldığında
saatlik zamanlayıcı bu süreyi yoklar; uygulama kapalıyken servis çalışmaz.
İnternet/API hatasında **1 gün** sonra yeniden deneme yapılır. Aynı kullanıcı
kurulumundaki pencereler kontrol kilidi ve ortak önbellek kullanır.

Kontrol edilenler:

- Ghidra, RetDec, Radare2 ve kullanılan Temurin JDK ana sürüm hattındaki resmî
  kararlı GitHub yayımları; ön sürümler kurulmaz.
- Yeni Ghidra sürümünün resmî `application.properties` dosyasındaki Java sınırları
  ve sürüme ait gereksinim belgesi bağlantısı.
- Paketli CPython'un aynı minor sürüm hattındaki kararlı yamaları.
- Paketli Python kitaplıklarının PyPI sürümleri ve yeni sürümlerin bildirdiği
  `Requires-Python` koşulları.
- Mevcut motor grubunun yerel başlatma/bağımlılık sağlığı.
- REHKC deposunda daha yeni, uyumluluğu onaylanmış motor kataloğu olup olmadığı.

Yeni bir Python/JDK/Qt ana sürümü otomatik olarak çalışan pakete takılmaz.
Upstream sürüm ve `Requires-Python` bilgisi tek başına entegrasyonun çalıştığını
kanıtlamaz. Yeni Ghidra sürümünün Java sınırı programatik okunur; tüm gelecekteki
motorların bağımlılıklarını serbest metinden eksiksiz çıkarma iddiası yoktur.
Yeni motor gruplarının sürüm/bağımlılık sınırları ve arşiv hash'leri bakımcı
incelemesi ile katalogda güncellenir ve gerçek analizle doğrulanır. Python/Qt ve
wheel kilidi değişiklikleri yeni bir REHKC paketi gerektirir.

Sonuçlar **Analiz motorları** menüsünden görülebilir; yeni sürümler günlükte de
bildirilir. Ayrıntılı rapor `tools/updates.json` altındadır. Terminal karşılıkları:

```sh
rehkc --tools check-updates
rehkc --tools check-updates --if-due
# Yalnız REHKC kataloğunda onaylı motor grubunu kurar; upstream latest'i kurmaz:
rehkc --tools update
rehkc --tools rollback
```

Kontrol hiçbir indirmeyi çalıştırmaz veya motorları sessizce yükseltmez. Güncelleme
kullanıcı menüden ya da komutla seçince başlar. Bütün yeni grup doğrulandıktan
sonra `active.json` atomik olarak değiştirilir; eski grup devam eden analizler
ve geri dönüş için saklanır. Yeni grubu kullanmak için REHKC yeniden açılır.
Başarısız indirme/sağlık kontrolü çalışan grubu değiştirmez. Katalog sürüm numarası
gerideyse otomatik geri sürüme geçiş reddedilir; `rollback` açık bir işlemdir.

Kaldırıcı motorları/önbelleği otomatik silmez; ayarlar, oturumlar ve elle kurulan
araçlar da korunur. Tam alan temizliği istenirse yalnız bu kurulumun
`tools/` dizini ve `~/.cache/rehkc/engines/` arşiv önbelleği ayrıca kaldırılabilir.
