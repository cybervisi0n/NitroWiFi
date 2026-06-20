subdir('src')

if build_target == 'arm'
libstubsssl = library('stubsssl',
    dependencies: nitrosdk_dep,
    include_directories: nitrowifi_includes,
    pic: build_target == 'nx',
    sources: libstubsssl_srcs,
    native: (build_target == 'linux' or build_target == 'win64')
)

nitrowifi_libs += libstubsssl
endif
