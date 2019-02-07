# t3fc ![License](https://dl.dropboxusercontent.com/s/cul64jahsd3cg14/license.svg?dl=0)

Algorithms:
* Threefish: 1024-bit key, 1024-bit block, CBC
* Kalyna: 512-bit key, 512-bit block, CBC
* HMAC-SHA3
* Argon2id: version 1.3, 512-bit salt, (T, M, P) = (9, 1 << 19, 1) (2^19 kibibytes of memory &asymp; 537 megabytes)

Dependency: [Crypto++](https://www.cryptopp.com)

Build with [meson](https://mesonbuild.com) and [ninja](https://ninja-build.org). See [build.sh](build.sh).