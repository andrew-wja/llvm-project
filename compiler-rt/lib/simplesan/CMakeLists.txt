include_directories(..)

# Runtime library sources and build flags.
set(SIMPLESAN_RTL_SOURCES
  simplesan.cpp
  simplesan_interceptors.cpp
  )

set(SIMPLESAN_RTL_HEADERS
  simplesan.h
  simplesan_flags.h
  simplesan_flags.inc
  simplesan_interceptors.h
  )

set(SIMPLESAN_DEFINITIONS)

set(SIMPLESAN_RTL_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_rtti_flag(OFF SIMPLESAN_RTL_CFLAGS)
append_list_if(COMPILER_RT_HAS_FPIC_FLAG -fPIC SIMPLESAN_RTL_CFLAGS)
# Prevent clang from generating libc calls.
append_list_if(COMPILER_RT_HAS_FFREESTANDING_FLAG -ffreestanding SIMPLESAN_RTL_CFLAGS)

set(SIMPLESAN_DYNAMIC_LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS})

if(ANDROID)
# Put most Sanitizer shared libraries in the global group. For more details, see
# android-changes-for-ndk-developers.md#changes-to-library-search-order
  if (COMPILER_RT_HAS_Z_GLOBAL)
    list(APPEND SIMPLESAN_DYNAMIC_LINK_FLAGS -Wl,-z,global)
  endif()
endif()

set(SIMPLESAN_DYNAMIC_CFLAGS ${SIMPLESAN_RTL_CFLAGS})
append_list_if(COMPILER_RT_HAS_FTLS_MODEL_INITIAL_EXEC
  -ftls-model=initial-exec SIMPLESAN_DYNAMIC_CFLAGS)
append_list_if(MSVC /DEBUG SIMPLESAN_DYNAMIC_LINK_FLAGS)

set(SIMPLESAN_DYNAMIC_LIBS ${SANITIZER_CXX_ABI_LIBRARIES} ${SANITIZER_COMMON_LINK_LIBS})

append_list_if(COMPILER_RT_HAS_LIBDL dl SIMPLESAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBRT rt SIMPLESAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBM m SIMPLESAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBPTHREAD pthread SIMPLESAN_DYNAMIC_LIBS)

# Static runtime library.
add_compiler_rt_component(simplesan)

add_compiler_rt_object_libraries(RTSimplesan
  ARCHS ${SIMPLESAN_SUPPORTED_ARCH}
  SOURCES ${SIMPLESAN_RTL_SOURCES}
  ADDITIONAL_HEADERS ${SIMPLESAN_RTL_HEADERS}
  CFLAGS ${SIMPLESAN_RTL_CFLAGS}
  DEFS ${SIMPLESAN_DEFINITIONS})
add_compiler_rt_object_libraries(RTSimplesan_dynamic
  ARCHS ${SIMPLESAN_SUPPORTED_ARCH}
  SOURCES ${SIMPLESAN_RTL_SOURCES}
  ADDITIONAL_HEADERS ${SIMPLESAN_RTL_HEADERS}
  CFLAGS ${SIMPLESAN_DYNAMIC_CFLAGS}
  DEFS ${SIMPLESAN_DEFINITIONS})

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp "")
add_compiler_rt_object_libraries(RTSimplesan_dynamic_version_script_dummy
  ARCHS ${SIMPLESAN_SUPPORTED_ARCH}
  SOURCES ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
  CFLAGS ${SIMPLESAN_DYNAMIC_CFLAGS}
  DEFS ${SIMPLESAN_DEFINITIONS})

foreach(arch ${SIMPLESAN_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.simplesan
    STATIC
    ARCHS ${arch}
    OBJECT_LIBS RTSimplesan
                RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
                RTSanitizerCommonCoverage
                RTSanitizerCommonSymbolizer
    CFLAGS ${SIMPLESAN_RTL_CFLAGS}
    PARENT_TARGET simplesan)

  if (UNIX)
    add_sanitizer_rt_version_list(clang_rt.simplesan-dynamic-${arch}
                                  LIBS clang_rt.simplesan-${arch}
                                  EXTRA simplesan.syms.extra)
    set(VERSION_SCRIPT_FLAG
         -Wl,--version-script,${CMAKE_CURRENT_BINARY_DIR}/clang_rt.simplesan-dynamic-${arch}.vers)
    set_property(SOURCE
      ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
      APPEND PROPERTY
      OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/clang_rt.simplesan-dynamic-${arch}.vers)
  else()
    set(VERSION_SCRIPT_FLAG)
  endif()


  add_compiler_rt_runtime(clang_rt.simplesan
    SHARED
    ARCHS ${arch}
    OBJECT_LIBS
            RTSimplesan_dynamic
            RTInterception
            RTSanitizerCommon
            RTSanitizerCommonLibc
            RTSanitizerCommonCoverage
            RTSanitizerCommonSymbolizer
            # The only purpose of RTSimplesan_dynamic_version_script_dummy is to
            # carry a dependency of the shared runtime on the version script.
            # Replacing it with a straightforward
            # add_dependencies(clang_rt.asan-dynamic-${arch} clang_rt.asan-dynamic-${arch}-version-list)
            # generates an order-only dependency in ninja.
            RTSimplesan_dynamic_version_script_dummy
    CFLAGS ${SIMPLESAN_DYNAMIC_CFLAGS}
    LINK_FLAGS ${SIMPLESAN_DYNAMIC_LINK_FLAGS}
              ${VERSION_SCRIPT_FLAG}
    LINK_LIBS ${SIMPLESAN_DYNAMIC_LIBS}
    DEFS ${ASAN_DYNAMIC_DEFINITIONS}
    PARENT_TARGET simplesan)

  if(SANITIZER_USE_SYMBOLS)
    add_sanitizer_rt_symbols(clang_rt.simplesan
      ARCHS ${arch}
      EXTRA simplesan.syms.extra)
    add_dependencies(simplesan clang_rt.simplesan-${arch}-symbols)
  endif()
endforeach()

add_compiler_rt_resource_file(simplesan_blacklist simplesan_blacklist.txt simplesan)
