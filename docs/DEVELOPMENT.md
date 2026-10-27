# Yerel geliştirme ve toplu yayın

Geliştirmeler yerelde uygulanır ve test edilir. Normal yerel kurulum test edilen
geliştirme paketiyle güncellenebilir. GitHub'a birleştirme ve resmî sürüm yayını
her küçük düzeltmede yapılmaz: yaklaşık 3–5 anlamlı geliştirme bir grupta
toplanır; grubun sonunda yayın yapılır. Yerel bir paket oluşturmak GitHub'a
yükleme, birleştirme veya yayın başlatmaz.

## Yerel paket

Resmî sürümle aynı değişmez kurulum dizinini paylaşmamak için benzersiz bir
yerel etiket kullanılır. Örnek:

```bash
python3 packaging/build_release.py \
  --engine "$HOME/.local/share/rehkc/current/app/rea.bin" \
  --assets "$HOME/.local/share/rehkc/current/app" \
  --stage work/local-package --output work/local-dist \
  --local-build dev.20261027.1
```

Bu paket `0.3.0-dev.20261027.1` gibi ayrı bir sürüm taşır. Kaynak sürümü,
`packaging/release.json` ve GitHub sürümleri değiştirilmez. Kaynak kod değişince
etiket de artırılır (`dev.20261027.2` gibi). Yerel paket de aynı pinned motor,
Python ve dosya manifesti doğrulamalarından geçer. Uygulama dizinine hesap,
ayar veya kullanıcı oturumu eklenmez.

Kurulumdan önce ilgili testler ve paketin kurulum/motor/GUI kontrolleri yapılır.
Ardından aynı kullanıcı kurucusu kullanılır:

```bash
./work/local-package/install.sh
rehkc --version
```

Hesaplar, modeller ve mevcut oturumlar korunur. Sonraki resmî `0.3.0` paketi,
yerel `0.3.0-dev...` diziniyle çakışmadan normal kurucuyla yüklenebilir.
Çalışmakta olan eski pencere yüklenmiş eski kodu kullanır; güncel sürüm yeni
başlatılan pencerede çalışır.
