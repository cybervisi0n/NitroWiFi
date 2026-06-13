if(build_target == 'arm')
    nitrowifi_prebuilt += fs.copyfile('prebuilt' / 'libssl.a')
else
    subdir('src')
    libssl = library('ssl',
        dependencies: [nitrosdk_dep],
        include_directories: [nitrowifi_includes],
        pic: false,
        sources: libssl_srcs,
        native: true
    )

    nitrowifi_libs += libssl
endif
