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
