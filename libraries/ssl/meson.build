if(build_target == 'arm')
    nitrowifi_prebuilt += fs.copyfile('prebuilt' / 'libssl.a')
else
    subdir('src')
    libssl = library('ssl',
        dependencies: [nitrosdk_dep],
        include_directories: [nitrowifi_includes],
        pic: build_target == 'nx',
        sources: libssl_srcs,
        native: (build_target == 'linux' or build_target == 'win64')
    )

    nitrowifi_libs += libssl
endif
