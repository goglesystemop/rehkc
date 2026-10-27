# REHKC 0.2.2

MCP analizinde Ghidra'nın ilk fonksiyon sorgusunun 90 saniyede kesilmesi düzeltildi.

- Ghidra ilk analizine 15 dakika, ilk MCP yanıtına ek 30 saniye pay tanınır.
  REA'nın Ghidra başlangıç süresi de aynı politikaya ayarlanır.
- Hızlı `open_binary` yanıtı, gerçek ilk analiz tamamlandı diye değerlendirilmez.
  Sonraki araçlar için 5 dakika, toplam analiz için 1 saat bütçe vardır.
- Hata iletisinde işlem, sınır türü, sınır değeri ve geçen süre açıkça görünür;
  araç günlüğünde aynı bilgiler korunur. Model/ağ beklemesi ayrıca tanımlanır.
- Arayüz ilk Ghidra analizi aşamasını ve bekleme payını gösterir. Durdur ve
  yalnız ilgili alt süreçlerin temizlenmesi korunur.
- Gecikmiş sunucu, toplam/araç ayrımı, backend ayarı, iptal ve ağ hataları için
  regresyon testleri eklendi. Gerçek PE dosyasında listeleme/decompile ve
  ChatGPT MCP akışıyla doğrulandı; hedef dosya çalıştırılmadı.

Debian/Arch kurucusu, motor grubu ve normal sohbet davranışı korunur. Ayrıntılar:
[MCP analiz süreleri](MCP-ANALYSIS.md).
