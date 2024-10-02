## [2.2.1](https://github.com/wetransform/gha-trivy/compare/v2.2.0...v2.2.1) (2024-10-02)

### Bug Fixes

* ignore error saving trivy cache ([9105dfb](https://github.com/wetransform/gha-trivy/commit/9105dfb41162743904efaac93075001dd6ea4c3f))

## [2.2.0](https://github.com/wetransform/gha-trivy/compare/v2.1.0...v2.2.0) (2024-09-25)

### Features

* cache trivy database ([d9cf71b](https://github.com/wetransform/gha-trivy/commit/d9cf71bf6c1d5271bbe17b16a2d7180ac5dadbb3))

### Bug Fixes

* **deps:** update actions/cache action to v4.0.2 ([624ec10](https://github.com/wetransform/gha-trivy/commit/624ec100e3c156860ce96d44e67b424675b7ad36))
* **deps:** update actions/upload-artifact action to v4.3.4 ([0bce74b](https://github.com/wetransform/gha-trivy/commit/0bce74bcd454aa5e872e13140574f8c550d6c04d))
* **deps:** update actions/upload-artifact action to v4.3.6 ([5056a0f](https://github.com/wetransform/gha-trivy/commit/5056a0ffa5ac5f326ea8005dbc5fa356c690c39d))
* **deps:** update actions/upload-artifact action to v4.4.0 ([057aa51](https://github.com/wetransform/gha-trivy/commit/057aa51c1cc69c998314b5ed808fac788b2814e4))
* **deps:** update mikepenz/action-junit-report action to v4.3.1 ([60a7fc2](https://github.com/wetransform/gha-trivy/commit/60a7fc2e279832f2ac53b69e0da3c29bc69d05ed))
* **deps:** update trivy action to 0.24.0 ([a5557a0](https://github.com/wetransform/gha-trivy/commit/a5557a0f3717353c3b2f4c56d0fd087125e15274))

## [2.1.0](https://github.com/wetransform/gha-trivy/compare/v2.0.1...v2.1.0) (2024-06-21)


### Features

* make summary creation optional ([5364d6c](https://github.com/wetransform/gha-trivy/commit/5364d6c863a77d2716a3668cbd71dd5ee51b53fc))
* support using existing SBOM ([607a0c2](https://github.com/wetransform/gha-trivy/commit/607a0c2b8d839bb056c8a6911b1815d945ad5b12))


### Bug Fixes

* **deps:** update mikepenz/action-junit-report action to v4.3.0 ([722da5d](https://github.com/wetransform/gha-trivy/commit/722da5d5864cc511b4319b67b87b9c76635bb0cb))
* don't create artifacts for existing SBOM ([5393f25](https://github.com/wetransform/gha-trivy/commit/5393f255379b342df3046e32c2a21a351bc92791))
* SBOM should be created even if no JUnit report is created ([8143d9b](https://github.com/wetransform/gha-trivy/commit/8143d9bdfbab79a3fb908e45b614e1782d9abc84))

## [2.0.1](https://github.com/wetransform/gha-trivy/compare/v2.0.0...v2.0.1) (2024-06-19)


### Bug Fixes

* avoid using invalid characters for artifact name ([d6c04e7](https://github.com/wetransform/gha-trivy/commit/d6c04e7c87db5667df07656eb1679fd5d2ae7f6f))

## [2.0.0](https://github.com/wetransform/gha-trivy/compare/v1.1.1...v2.0.0) (2024-06-19)


### ⚠ BREAKING CHANGES

* Reports are no longer uploaded to the same shared
artifact, because of the update to upload-artifact version 4

### Features

* add CSV representation of SBOM ([2bc1659](https://github.com/wetransform/gha-trivy/commit/2bc165991a988b0330c3c99d2b959ce10db27d0c))
* generate SBOM and use if for repeated scans ([ad54fe9](https://github.com/wetransform/gha-trivy/commit/ad54fe9b546b24dc1e583e9a582592f01c63f210))


### Bug Fixes

* **deps:** pin dependencies ([1de9f8e](https://github.com/wetransform/gha-trivy/commit/1de9f8edd115de1824a7eae52364ca7875f31446))
* **deps:** update all non-major dependencies ([666b486](https://github.com/wetransform/gha-trivy/commit/666b486dc333d3e664aeba42fa469cb22a6cca81))
* sanitize SBOM file names ([d71a0be](https://github.com/wetransform/gha-trivy/commit/d71a0bee035a1fab51075d36906eeac6a2577cab))

## [1.1.1](https://github.com/wetransform/gha-trivy/compare/v1.1.0...v1.1.1) (2024-04-12)


### Bug Fixes

* **deps:** pin aquasecurity/trivy-action action to d710430 ([11f10f8](https://github.com/wetransform/gha-trivy/commit/11f10f8bca8d941f65a6eabc8086300b37aa81a0))
* **deps:** pin wetransform/gha-docker-nonroot action to 163ae1a ([a510291](https://github.com/wetransform/gha-trivy/commit/a5102913aec03f3aba9aaadc0467a0e0431d4e95))
* **deps:** update all non-major dependencies ([79fe060](https://github.com/wetransform/gha-trivy/commit/79fe060c8133fcd6d574df760c029d87ab6d437d))
* **deps:** update all non-major dependencies ([0b2b80d](https://github.com/wetransform/gha-trivy/commit/0b2b80d2ec06d092ab918fa219816d84470a0695))
* **deps:** update mikepenz/action-junit-report action to v4 ([1173670](https://github.com/wetransform/gha-trivy/commit/1173670efb470eeaac7b89ed9f5c198a4c0f4276))
* **deps:** update wetransform/gha-docker-nonroot action to v1.0.3 ([a9b37f0](https://github.com/wetransform/gha-trivy/commit/a9b37f04783b8862e23959ed4f412083c432b49a))
* **deps:** update wetransform/gha-docker-nonroot digest to f46f552 ([2abca52](https://github.com/wetransform/gha-trivy/commit/2abca52fc7faf5f6fe2a44faa379a008d5bfaeb6))
* update trivy-action to 0.19.0 ([174b873](https://github.com/wetransform/gha-trivy/commit/174b8738d195d43f5239797760391db4e8da3b47))

## [1.1.0](https://github.com/wetransform/gha-trivy/compare/v1.0.0...v1.1.0) (2024-03-26)


### Features

* add Docker image user check ([9b9d36b](https://github.com/wetransform/gha-trivy/commit/9b9d36ba509a24df38f2e269d43b46383d59ace1))
