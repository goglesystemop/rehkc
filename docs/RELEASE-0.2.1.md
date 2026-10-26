# REHKC 0.2.1

Aynı kurucu Debian ve Arch ailelerinde sistem bağımlılıklarını otomatik kurar.

- Debian/Ubuntu/Kubuntu/Linux Mint için apt-get davranışı korunur.
- Arch/CachyOS/Manjaro, os-release ID/ID_LIKE ile tanınır; X11/Wayland, OpenGL,
  Java GUI kitaplıkları, yazı tipleri ve binutils karşılıkları pacman ile kurulur.
- Arch'ta `pacman -Syu --needed` kullanılır; tam sistem güncellemesiyle paketler
  tutarlı tutulur. Etkileşimli işlem onayı korunur.
- Paket yöneticisi seçimi PATH sırasına göre yapılmaz. Eksik/yabancı dağıtım veya
  paket kurulum hatası uygulama kurulumunu durdurur.
- `--print-system-deps` dağıtıma uygun komutu salt okunur gösterir; `--check`
  ile sistem paketi kurulumu birleştirilemez.
- README'de Debian ve Arch aileleri için ayrı temiz kurulum adımları bulunur.
- GitHub kontrolüne gerçek Arch kapsayıcısında pacman kurulumu ve yönetilen motor
  kabul testleri eklendi. Yerel KDE testi Kubuntu/Ubuntu ortamındadır;
  CachyOS/Manjaro üzerinde gerçek KDE oturumu testi ayrıca yapılmalıdır.

Motor grubu ve haftalık uyumluluk kontrolü 0.2.0 ile aynıdır: Ghidra12.1.4,
Temurin JDK21.0.13+9, Radare2 6.2.4 ve RetDec5.0. Sistem Python/pip ortamına
kurulum yapılmaz. Kurucuyu kendi masaüstü kullanıcınızla, sudo olmadan başlatın.
