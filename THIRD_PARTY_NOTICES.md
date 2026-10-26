# Third-party notices

REHKC is an independent community desktop distribution. It is not an official
OpenAI, MakuluLinux, Cinnamon or upstream REA release.

- Original MakuluLinux REA desktop UI: attribution in the UI/source is retained.
- REA motor and accompanying bridge/skill assets: morluto and contributors, MIT.
  The shipped Makulu motor is REA 6.7.0, SHA-256
  `e5767925df037ee1bd951ad2ccaa51a3c8eccd17791e9679d8058394c6a04968`.
  Its extracted JavaScript is unchanged. See `licenses/REA-MIT.txt`,
  `packaging/doctor-runtime-spec.json` and the pinned companion repository.
- The Ghidra bridge has a small compatibility modification in listProcedures:
  omit the extra symbol field from the strict procedure inventory. Ghidra itself
  is downloaded from its official release by the installer, together with the
  catalog-pinned Temurin JDK, Radare2 and RetDec archives. Their original license
  and third-party notices remain in the extracted upstream packages; the engine
  archives are not embedded in the REHKC release. Catalog origins and hashes
  are in `app/analysis-tools.json`. Ghidra: Apache-2.0; Radare2: LGPL-3.0;
  RetDec: MIT with third-party components; Temurin OpenJDK: GPLv2 with
  Classpath Exception and bundled third-party notices.
- PyQt5 is used under GPLv3. This distribution includes the editable desktop
  source under GPLv3; upstream MIT notices are retained. The runtime includes
  wheel license/metadata files. PyQt5 5.15.11 source:
  https://pypi.org/project/PyQt5/5.15.11/#files
- Qt shared libraries retain their own LGPL/GPL licenses. Qt 5.15.19 sources:
  https://download.qt.io/archive/qt/5.15/5.15.19/single/
  Qt libraries/plugins remain separate, replaceable files under
  `runtime/python/lib/python3.12/site-packages/PyQt5/Qt5/`.
- CPython and its runtime dependencies retain their licenses, included in the
  Python standalone runtime. Exact upstream artifact and digest are recorded in
  `packaging/python-runtime.json`.
- PyJWT (MIT), cryptography (Apache-2.0/BSD), cffi (MIT) and pycparser (BSD) retain
  their wheel license files. Exact versions/hashes are in requirements.lock.

The archive contains source for the REHKC desktop/installer. The build recipe
requires the separately supplied, hash-verified vendor engine; it does not claim
that the vendor executable is reproducible from this repository alone.
