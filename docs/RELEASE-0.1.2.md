REHKC 0.1.2 includes the installed-package check fix and KDE validation in the same Linux desktop distribution.

- `current/install.sh --check` now validates an installed release without modifying it. The recursive reinstall and root/home directory protections remain active.
- User-installed analysis tools are discovered from `~/.local/bin` even when the desktop menu's PATH omits it. Existing PATH entries and explicit Java/Ghidra/RetDec settings retain priority.
- One package is used for Cinnamon and KDE; the archive is named `rehkc-0.1.2-linux-x86_64.tar.gz`.
- On Ubuntu 26.04.1 / Plasma 6.6.6, real Wayland and XWayland startup, Ghidra/Radare2/RetDec analysis, and selected-model chat/MCP with LM Studio, Ollama, and ChatGPT passed. See `docs/KDE-NEXT.md` for the exact scope and limitations.

Download the archive and `SHA256SUMS`, verify with `sha256sum -c SHA256SUMS`, extract it, and run `./install.sh --check` followed by `./install.sh`. The source installer also downloads this checksum-pinned release.

Analysis engines and model servers remain optional external installations. No personal settings, accounts, sessions, models, or machine-specific engine paths are included. This release does not claim compatibility with every Linux distribution, every model, ARM, or all KDE integrations.
