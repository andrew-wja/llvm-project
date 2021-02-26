include_directories(..)

set(GSAN_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_rtti_flag(OFF GSAN_CFLAGS)

set(GSAN_COMMON_SOURCES
  gsan_common.cpp
  gsan_common_fuchsia.cpp
  gsan_common_linux.cpp
  gsan_common_mac.cpp
  )

set(GSAN_SOURCES
  gsan.cpp
  gsan_allocator.cpp
  gsan_fuchsia.cpp
  gsan_interceptors.cpp
  gsan_linux.cpp
  gsan_mac.cpp
  gsan_malloc_mac.cpp
  gsan_posix.cpp
  gsan_preinit.cpp
  gsan_thread.cpp
  )

set(GSAN_HEADERS
  gsan.h
  gsan_allocator.h
  gsan_common.h
  gsan_flags.inc
  gsan_thread.h
  )

set(GSAN_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_compiler_rt_object_libraries(RTGSanCommon
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${GSAN_COMMON_SUPPORTED_ARCH}
    SOURCES ${GSAN_COMMON_SOURCES}
    ADDITIONAL_HEADERS ${GSAN_HEADERS}
    CFLAGS ${GSAN_CFLAGS})

set(SBCETS_SOURCES
  softboundcets-internal.cpp
  softboundcets-interface.cpp
  )

set(SBCETS_HEADERS
  softboundcets-internal.h
  softboundcets-interface.h
  )

add_compiler_rt_object_libraries(RTSoftboundCETS
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${GSAN_COMMON_SUPPORTED_ARCH}
    SOURCES ${SBCETS_SOURCES}
    ADDITIONAL_HEADERS ${SBCETS_HEADERS}
    CFLAGS ${GSAN_CFLAGS})

if(COMPILER_RT_HAS_GSAN)
  add_compiler_rt_component(gsan)
  if(APPLE)
    set(GSAN_LINK_LIBS ${SANITIZER_COMMON_LINK_LIBS})

    add_weak_symbols("gsan" WEAK_SYMBOL_LINK_FLAGS)
    add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)

    add_compiler_rt_runtime(clang_rt.gsan
      SHARED
      OS ${SANITIZER_COMMON_SUPPORTED_OS}
      ARCHS ${GSAN_SUPPORTED_ARCH}
      SOURCES ${GSAN_SOURCES}
      ADDITIONAL_HEADERS ${GSAN_HEADERS} ${SBCETS_HEADERS}
      OBJECT_LIBS RTSoftboundCETS
                  RTGSanCommon
                  RTInterception
                  RTSanitizerCommon
                  RTSanitizerCommonLibc
                  RTSanitizerCommonCoverage
                  RTSanitizerCommonSymbolizer
      CFLAGS ${GSAN_CFLAGS}
      LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS} ${WEAK_SYMBOL_LINK_FLAGS}
      LINK_LIBS ${GSAN_LINK_LIBS}
      PARENT_TARGET gsan)
  else()
    foreach(arch ${GSAN_SUPPORTED_ARCH})
      add_compiler_rt_runtime(clang_rt.gsan
        STATIC
        ARCHS ${arch}
        SOURCES ${GSAN_SOURCES}
                $<TARGET_OBJECTS:RTInterception.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommonCoverage.${arch}>
                $<TARGET_OBJECTS:RTSanitizerCommonSymbolizer.${arch}>
                $<TARGET_OBJECTS:RTGSanCommon.${arch}>
                $<TARGET_OBJECTS:RTSoftboundCETS.${arch}>
        ADDITIONAL_HEADERS ${GSAN_HEADERS} ${SBCETS_HEADERS}
        CFLAGS ${GSAN_CFLAGS}
        PARENT_TARGET gsan)
    endforeach()
  endif()
endif()
