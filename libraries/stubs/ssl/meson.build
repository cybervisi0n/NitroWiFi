subdir('src')

if build_target == 'arm'
libstubsssl = library('stubsssl',
    dependencies: nitrosdk_dep,
    include_directories: nitrowifi_includes,
    pic: false,
    sources: libstubsssl_srcs,
    native: build_target != 'arm'
)

nitrowifi_libs += libstubsssl
endif
