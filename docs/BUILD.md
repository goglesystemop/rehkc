# Sürüm arşivini hazırlama

Gerekenler: yapım makinesinde Python 3.12+ (tarfile data filter), tar/gzip, ağ veya
önceden indirilmiş sabit girdiler ve paket metadata'sındaki SHA-256 ile eşleşen
REA 6.7.0 vendor motoru. Çalışan motor veya ajan skill'leri değiştirilmez.

```sh
python3 packaging/build_release.py \
  --engine /path/to/verified/rea.bin \
  --stage /tmp/rehkc-build/rehkc-0.2.0-linux-x86_64 \
  --output dist
```

Python standalone artifact'i ve pip wheel'leri hash ile sabitlenmiştir.
Companion dosyalar pinlenmiş upstream commit/blob/hash'lerinden alınır. Yapım
betiği motorun değişmemiş gömülü JavaScript'ini ayırır ve kaynak dosyalarla arşivler.
Motoru bu depodan yeniden derlediğini veya byte-byte tekrarlanabilir bir tam
vendor build'i ürettiğini iddia etmez; tedarik edilen motor bir girdidir.

Çıktı MANIFEST.json ile dosya hash'leri, build-info.json ile bileşen sürümleri,
arşiv için SHA256SUMS içerir. GUI kaynakları arşivde düzenlenebilir durumdadır.
Yayımdan önce tests/ dağıtım kontrolleri ve gerçek Cinnamon/Ghidra/model testleri
çalıştırılmalı; test raporu kapsamadığı platformu başarılı saymamalıdır.

## GitHub Actions yayını

`packaging/version.json` paket sürümünü ve doğrulanmış masaüstü kapsamını tutar.
Yeni sürüm için bu dosya ile `app/rehkc_boot.py` içindeki sürüm birlikte artırılır;
`docs/RELEASE-<sürüm>.md` sürüm notları hazırlanır. Ana daldaki sürüm dosyası
değişikliği `.github/workflows/release.yml` işini başlatır.

İş, mevcut `packaging/release.json` ile hash'i sabitlenmiş önceki yayımdan vendor
motorunu alır; Python ve wheel girdilerini ayrıca sabitlenmiş hash'lerle doğrular.
Yeni paketi derler, dağıtım/araç keşfi testlerini, offscreen GUI başlangıcını ve
MCP doctor kontrolünü çalıştırır. Offscreen CI testi gerçek masaüstü testi yerine
geçmez. Başarıdan sonra yeni arşivin hash'ini ana dala kaydeder, arşiv ve
SHA256SUMS eklerini taslak sürüme yükler ve sürümü yayımlar. İş yalnız depo
içeriği yazma izni kullanır; kişisel anahtar veya model gerektirmez.

Aynı sürüm yeniden yayımlanmaz veya mevcut eklerin üzerine yazılmaz. Yerel,
yayımsız ön kontrol için:

```sh
python3 packaging/ci_release.py --work-dir /tmp/rehkc-release-check --build-only
```

## Yönetilen motor kabul testi

`verify.yml` pull request üzerinde salt okuma izniyle aynı derleme ve test akışını
`--build-only` olarak çalıştırır; sürüm yayımlamaz. `test_managed_tools.py` hata,
önbellek, sürüm/bağımlılık sınırları ve geri dönüş politikasını sınar.
`test_managed_engines_live.py` ise ağdan hash kontrollü motor kurulumu yapar;
boş hedefte kurucunun varsayılan akışını, kısıtlı PATH ile normal başlatıcıyı,
gerçek Ghidra/REA decompile akışını ve tekrar kurulumu doğrular. Kurucunun kendi
probu da üç motorla gerçek analiz ve paketli REA/Ghidra köprüsünü çalıştırır.
Analiz edilen küçük test ELF'i oluşturulur, hiçbir zaman hedef olarak çalıştırılmaz.

Motor kataloğunda yeni grup yayımlamak için monoton `revision` değeri artırılır;
resmî arşivlerin URL/boyut/SHA-256 değerleri, Java/Python sınırları ve REA'nın
kabul ettiği Ghidra sürüm hattı birlikte değerlendirilir. `requires_review`
güncelleme bildirimi kendi başına katalogya alma veya uyumluluk kanıtı değildir.
