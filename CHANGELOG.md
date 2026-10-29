# Changelog

## [0.5.0](https://github.com/dstoc/creds/compare/v0.4.1...v0.5.0) (2026-10-29)


### Features

* list stored secret names ([#32](https://github.com/dstoc/creds/issues/32)) ([d137507](https://github.com/dstoc/creds/commit/d13750778ade28f2a2dbac9b38c813e314ac147b))
* remove a named stored secret ([#33](https://github.com/dstoc/creds/issues/33)) ([b469fb0](https://github.com/dstoc/creds/commit/b469fb0318adf774dfe2fbb91af3c4e1e49834f1))


### Bug Fixes

* check decrypt output before approval ([#30](https://github.com/dstoc/creds/issues/30)) ([252a5d8](https://github.com/dstoc/creds/commit/252a5d86d2a1f2f66b2924bbc7ff0680fb80eb07))

## [0.4.1](https://github.com/dstoc/creds/compare/v0.4.0...v0.4.1) (2026-10-26)


### Bug Fixes

* **qr-rendering:** preserve native QR appearance ([#28](https://github.com/dstoc/creds/issues/28)) ([bd04d38](https://github.com/dstoc/creds/commit/bd04d38680d3c9eceee706c6b9c2267a403dcc6f))

## [0.4.0](https://github.com/dstoc/creds/compare/v0.3.0...v0.4.0) (2026-10-25)


### Features

* add configurable QR rendering modes ([#27](https://github.com/dstoc/creds/issues/27)) ([cd5ced9](https://github.com/dstoc/creds/commit/cd5ced9d3de2dd9ae8c4dd636b17c5f4aebdc78a))
* **cli:** add help, version, and argument parsing ([#23](https://github.com/dstoc/creds/issues/23)) ([bbee444](https://github.com/dstoc/creds/commit/bbee4447206cf4b0b4885ccbab38897a7a648baa))
* **cli:** simplify setup, check, and approval output ([#25](https://github.com/dstoc/creds/issues/25)) ([e2c9a52](https://github.com/dstoc/creds/commit/e2c9a52e4bc605bd33c93cfdd9c3b586a2dc084f))
* **web:** restore first-time passkey setup choices ([#19](https://github.com/dstoc/creds/issues/19)) ([d68ae73](https://github.com/dstoc/creds/commit/d68ae73fe71e0cd436f3daae0d82bd72f6c05127))


### Bug Fixes

* **cli:** add contextual command diagnostics ([#24](https://github.com/dstoc/creds/issues/24)) ([22a6e80](https://github.com/dstoc/creds/commit/22a6e80bfa6265ebaf1556dfef1064629c9641a1))
* **web:** remove duplicate settings separators ([#21](https://github.com/dstoc/creds/issues/21)) ([5db9df2](https://github.com/dstoc/creds/commit/5db9df2111abf47b3eaa34f6edcb2dc7238a873d))
* **web:** simplify passkey setup copy ([#22](https://github.com/dstoc/creds/issues/22)) ([d67e30a](https://github.com/dstoc/creds/commit/d67e30ad13e3c196ff514f479abd57a8892f4955))

## [0.3.0](https://github.com/dstoc/creds/compare/v0.2.0...v0.3.0) (2026-10-25)


### Features

* add browser settings and remembered destinations ([#17](https://github.com/dstoc/creds/issues/17)) ([09328d5](https://github.com/dstoc/creds/commit/09328d56be17f169dfb427706978e968abe2c2db))
* **web:** adopt simplified Astra UI ([#18](https://github.com/dstoc/creds/issues/18)) ([4742962](https://github.com/dstoc/creds/commit/47429625dcd638c6356672424f83ad0593ae5b9b))


### Bug Fixes

* resolve draft releases by ID ([#15](https://github.com/dstoc/creds/issues/15)) ([9dda5a7](https://github.com/dstoc/creds/commit/9dda5a7e92928a5e15c4731863410dc976d7712e))

## [0.2.0](https://github.com/dstoc/creds/compare/v0.1.0...v0.2.0) (2026-10-24)


### Features

* add passkey setup and assertion verification ([#3](https://github.com/dstoc/creds/issues/3)) ([8d823de](https://github.com/dstoc/creds/commit/8d823de58ac9bc96c34c0db779f2b5a1ddf3cf4d))
* add v1 encryption envelopes and atomic storage ([#4](https://github.com/dstoc/creds/issues/4)) ([fee1ec2](https://github.com/dstoc/creds/commit/fee1ec24821bd39e345546fb7168840c6ebf7a0d))
* establish creds project skeleton and browser probes ([#2](https://github.com/dstoc/creds/issues/2)) ([bd5b422](https://github.com/dstoc/creds/commit/bd5b42218e8048ab065e39c8c59488eba6bca06d))
* implement browser-approved WebTransport handoff ([#5](https://github.com/dstoc/creds/issues/5)) ([5cf2785](https://github.com/dstoc/creds/commit/5cf2785b3e0f429a18e7414ee406ec285249eda5))
* integrate browser approval with encrypt and decrypt commands ([#6](https://github.com/dstoc/creds/issues/6)) ([5a97641](https://github.com/dstoc/creds/commit/5a976418ab29f55e57cca4856e3dc1b4e34fae16))
* separate machine DNS suffix from approval origin ([#8](https://github.com/dstoc/creds/issues/8)) ([97767e6](https://github.com/dstoc/creds/commit/97767e6745594b617ff26577c9029833ecc5e8fc))


### Bug Fixes

* honor full approval timeout (creds/8) ([#9](https://github.com/dstoc/creds/issues/9)) ([26d9c83](https://github.com/dstoc/creds/commit/26d9c8391cb39a22533f375d9e655515782ae824))
* simplify trusted browser request parsing ([#11](https://github.com/dstoc/creds/issues/11)) ([45fb535](https://github.com/dstoc/creds/commit/45fb535788c0b446e016031c4192e6e1bf872a04))
* use GITHUB_TOKEN for release automation ([#13](https://github.com/dstoc/creds/issues/13)) ([41af937](https://github.com/dstoc/creds/commit/41af937934445718e1c7763ef8eb3c7de80c0f73))


### Release automation

* add verified GitHub release automation ([#12](https://github.com/dstoc/creds/issues/12)) ([bee0c8c](https://github.com/dstoc/creds/commit/bee0c8cc5a5c8f707c100f754e199958e71a6b64))
