if(build_target == 'arm')
    nitrowifi_prebuilt += fs.copyfile('prebuilt' / 'libcps.a')
else
    subdir('src')
    libcps = library('cps',
        dependencies: [nitrosdk_dep],
        include_directories: [nitrowifi_includes],
        pic: false,
        sources: libcps_srcs,
        native: true
    )

    nitrowifi_libs += libcps
endif