# Sürüm arşivini hazırlama

Gerekenler: yapım makinesinde Python 3.12+ (tarfile data filter), tar/gzip, ağ veya
önceden indirilmiş sabit girdiler ve paket metadata'sındaki SHA-256 ile eşleşen
REA 6.7.0 vendor motoru. Çalışan motor veya ajan skill'leri değiştirilmez.

```sh
python3 packaging/build_release.py \
  --engine /path/to/verified/rea.bin \
  --stage /tmp/rehkc-build/rehkc-0.1.0-cinnamon-x86_64 \
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
