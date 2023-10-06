## [3.0.3](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/3.0.2...3.0.3) (2023-10-06)


### Bug Fixes

* always remove AUTHORIZATION before policyChain.doNext ([6a739fd](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/6a739fdfabbb4b3c83e1d325eb9b3a7f740d9da7))

## [3.0.2](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/3.0.1...3.0.2) (2023-09-05)


### Bug Fixes

* pom.xml to reduce vulnerabilities ([ee5d7d6](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/ee5d7d6667b08af88f9ba71d9edb9a2e77a4353b))

## [3.0.1](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/3.0.0...3.0.1) (2023-07-20)


### Bug Fixes

* update policy description ([5331542](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/53315420d65a9c6f6b6c47af687f747fa4a78474))

# [3.0.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.3.2...3.0.0) (2023-07-18)


### Bug Fixes

* bump dependencies versions ([1312b09](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/1312b09e067e0be6542ea956f8f67e9d3b10c4ce))
* bump gravitee-parent to fix release on Maven Central ([457b84d](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/457b84d1e5bf94a347e435c11586ee3a83903af4))
* properly handle token extraction ([c34a2ee](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/c34a2ee172060f4a5f10f59337536863722f407d))
* simplify unauthorized message ([0358f05](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/0358f054ba8c83a3232669997d1293c873e2ceef))


### chore

* **deps:** update gravitee-parent ([18402bb](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/18402bb6b261e2d294b2676f31313fc494542b35))


### BREAKING CHANGES

* **deps:** require Java17
* use apim version 4

## [2.3.2](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.3.1...2.3.2) (2023-07-06)


### Bug Fixes

* bump `gravitee-parent` to 21.0.1 ([28a2620](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/28a2620eff22577f489bf384ff0b57826c7ec42b))

## [2.3.1](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.3.0...2.3.1) (2023-07-05)


### Bug Fixes

* add support for `scp` node in Oauth2PolicyV3 ([63e6c42](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/63e6c426ec19479235c19c27ac6da7054cb0b3e1))
* add support for `scp` node in TokenIntrospectionResult ([7fde7bd](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/7fde7bdff9005f8dfe2242dd32d8521cf2570bd4))
* add test support for  node ([102b726](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/102b726f3f96aec740f5a3e4d1cad15a23c2a431))

# [2.3.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.2.0...2.3.0) (2023-06-30)


### Features

* improve special resource type ui component to make it generic ([3757774](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/3757774fe7c0572acbc21df57988a179a691976c))

# [2.2.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.1.1...2.2.0) (2023-05-29)


### Features

* provide execution phase in manifest ([df36130](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/df36130865b1e553c6cdf186d031756e636b58cc))

## [2.1.1](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.1.0...2.1.1) (2023-04-18)


### Bug Fixes

* clean schema-form to make it compatible with gio-form-json-schema component ([ba443ba](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/ba443baafb7036e9c8a2f7777e38193fd5a7c4ce))

# [2.1.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.0.0...2.1.0) (2023-03-17)


### Bug Fixes

* bump gateway api version ([7013d66](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/7013d668d03f9d114a6804c76ca0bba33314b98f))
* **deps:** bump dependencies ([02b63ef](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/02b63efad651902c9bf30066d50c4660405c1ad8))


### Features

* rename 'jupiter' package in 'reactive' ([302d7d0](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/302d7d0badc7b41abb2c763027edbefe0f3d2dd4))

# [2.1.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.0.1-alpha.1...2.1.0-alpha.1) (2023-03-13)


### Features

* rename 'jupiter' package in 'reactive' ([55a95b4](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/55a95b4796a8bd1dad250774e5f2851a2cfea024))

## [2.0.1-alpha.1](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/2.0.0...2.0.1-alpha.1) (2023-02-02)


### Bug Fixes

* bump gateway api version ([a922b41](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/a922b4199062f6cea05afef55a5b14e9237ff3cc))

# [2.0.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.23.0...2.0.0) (2022-12-09)


### chore

* bump to rxJava3 ([d02d58c](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/d02d58c944a82ad2d66d59f5f8550cf6f6b9b7d6))


### BREAKING CHANGES

* rxJava3 required

# [2.0.0-alpha.1](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.23.0...2.0.0-alpha.1) (2022-10-20)


### chore

* bump to rxJava3 ([d02d58c](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/d02d58c944a82ad2d66d59f5f8550cf6f6b9b7d6))


### BREAKING CHANGES

* rxJava3 required

# [1.23.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.22.0...1.23.0) (2022-09-05)


### Bug Fixes

* plan selection for v3 engine ([798f541](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/798f5413ff2d084bdac2687b7e12c43fc39ca5ce))


### Features

* improve execution context structure ([abd7531](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/abd753109ccef5b72055c6c74acf663a16e559dd)), closes [gravitee-io/issues#8386](https://github.com/gravitee-io/issues/issues/8386)

# [1.22.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.21.0...1.22.0) (2022-08-16)


### Features

* migrate to the new version of Jupiter's SecurityPolicy ([1976b54](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/1976b544e18099ceaaacd5164e50257fc1dfa95a))

# [1.22.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.21.0...1.22.0) (2022-08-16)


### Features

* migrate to the new version of Jupiter's SecurityPolicy ([1976b54](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/1976b544e18099ceaaacd5164e50257fc1dfa95a))

# [1.21.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.20.0...1.21.0) (2022-08-08)


### Features

* **sme:** update security policy to be compatible with async reactor ([b22e2df](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/b22e2df14fea2ac20e19a869a7a9cdb0948be6a9))

# [1.20.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.19.0...1.20.0) (2022-06-10)


### Features

* **jupiter:** move to Jupiter SecurityPolicy ([87656fc](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/87656fce5a47766bfacb4a7f75779f6fca90c47b))

# [1.19.0](https://github.com/gravitee-io/gravitee-policy-oauth2/compare/1.18.0...1.19.0) (2022-01-21)


### Features

* **headers:** Internal rework and introduce HTTP Headers API ([e30b778](https://github.com/gravitee-io/gravitee-policy-oauth2/commit/e30b7780a0508ffd9fd91379b90eb2daffd59eef)), closes [gravitee-io/issues#6772](https://github.com/gravitee-io/issues/issues/6772)
