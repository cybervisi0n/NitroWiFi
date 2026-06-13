subdir('src')

libwcm_includes = include_directories('include')

libwcm = library('wcm',
    dependencies: nitrosdk_dep,
    include_directories: [nitrowifi_includes, libwcm_includes],
    pic: false,
    sources: libwcm_srcs,
    native: build_target != 'arm'
)

nitrowifi_libs += libwcm
