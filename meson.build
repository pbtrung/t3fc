project('t3fc', 'c', 'cpp', 
		version : '0.0.9999',
        license : 'BSD-3-Clause',
        default_options : ['cpp_std=c++14', 'c_std=c11'])

cppc = meson.get_compiler('cpp')
cc = meson.get_compiler('c')

if host_machine.system() == 'linux'
    if (cppc.get_id() == 'gcc' and cc.get_id() == 'gcc') or (cppc.get_id() == 'clang' and cc.get_id() == 'clang')
        args = '''
            -march=native
            -Wno-unused-value
            -Wno-sign-compare
            -Wno-maybe-uninitialized
            -Wno-stringop-overflow
        '''.split()
    else
        error('No supported compiler was found.')
    endif
else
    error('Operating system is not supported.')
endif

foreach arg: args
    if cppc.has_argument(arg)
        add_project_arguments(arg, language : 'cpp')
    endif
    if cc.has_argument(arg)
        add_project_arguments(arg, language : 'c')
    endif
endforeach

subdir('argon2')

libcryptopp = dependency('libcrypto++')
threads = dependency('threads')
dependencies = [threads, libcryptopp]

executable('t3fc',
		   sources : ['main.cpp', 'randombytes/randombytes.c'],
		   link_with : [libargon2],
           dependencies : dependencies,
           install : false)