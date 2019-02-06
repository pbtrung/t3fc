libcppcrypto_sources = files('''
    block_cipher.cpp
    cpuinfo.cpp
    crypto_hash.cpp
    hmac.cpp
    kalyna.cpp
    kupyna.cpp
    skein512.cpp
    skein512mmx.cpp
    threefish.cpp
'''.split())

libcppcrypto = static_library('cppcrypto',
                              libcppcrypto_sources)