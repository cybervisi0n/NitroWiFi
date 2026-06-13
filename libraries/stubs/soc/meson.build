subdir('src')

libstubsoc = library('stubsoc',
    dependencies: nitrosdk_dep,
    include_directories: nitrowifi_includes,
    pic: false,
    sources: libstubsoc_srcs,
    native: build_target != 'arm'
)

nitrowifi_libs += libstubsoc
