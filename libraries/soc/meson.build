subdir('src')

libsoc = library('soc',
    dependencies: nitrosdk_dep,
    include_directories: nitrowifi_includes,
    pic: false,
    sources: libsoc_srcs,
    native: build_target != 'arm'
)

nitrowifi_libs += libsoc
