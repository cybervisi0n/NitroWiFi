subdir('src')

libstubsoc = library('stubsoc',
    dependencies: nitrosdk_dep,
    include_directories: nitrowifi_includes,
    pic: build_target == 'nx',
    sources: libstubsoc_srcs,
    native: (build_target == 'linux' or build_target == 'win64')
)

nitrowifi_libs += libstubsoc
