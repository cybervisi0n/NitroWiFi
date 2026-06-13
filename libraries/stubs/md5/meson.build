subdir('src')

libstubsmd5 = library('stubsmd5',
    dependencies: nitrosdk_dep,
    include_directories: nitrowifi_includes,
    pic: false,
    sources: libstubsmd5_srcs,
    native: build_target != 'arm'
)

nitrowifi_libs += libstubsmd5
