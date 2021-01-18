include_directories(..)

# Runtime library sources and build flags.
set(DUMMYSAN_RTL_SOURCES
  dummysan.cpp
  dummysan_allocator.cpp
  dummysan_dynamic_shadow.cpp
  dummysan_exceptions.cpp
  dummysan_globals.cpp
  dummysan_linux.cpp
  dummysan_memintrinsics.cpp
  dummysan_poisoning.cpp
  dummysan_report.cpp
  dummysan_thread.cpp
  dummysan_thread_list.cpp
  dummysan_type_test.cpp
  )

set(DUMMYSAN_RTL_HEADERS
  dummysan.h
  dummysan_allocator.h
  dummysan_dynamic_shadow.h
  dummysan_flags.h
  dummysan_flags.inc
  dummysan_globals.h
  dummysan_interface_internal.h
  dummysan_malloc_bisect.h
  dummysan_mapping.h
  dummysan_poisoning.h
  dummysan_report.h
  dummysan_thread.h
  dummysan_thread_list.h
  )

set(DUMMYSAN_DEFINITIONS)
append_list_if(COMPILER_RT_DUMMYSAN_CONTAINS_UBSAN DUMMYSAN_CONTAINS_UBSAN=1 DUMMYSAN_DEFINITIONS)

set(DUMMYSAN_RTL_CFLAGS ${SANITIZER_COMMON_CFLAGS})
append_rtti_flag(OFF DUMMYSAN_RTL_CFLAGS)
append_list_if(COMPILER_RT_HAS_FPIC_FLAG -fPIC DUMMYSAN_RTL_CFLAGS)
# Prevent clang from generating libc calls.
append_list_if(COMPILER_RT_HAS_FFREESTANDING_FLAG -ffreestanding DUMMYSAN_RTL_CFLAGS)

set(DUMMYSAN_DYNAMIC_LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS})

if(ANDROID)
# Put most Sanitizer shared libraries in the global group. For more details, see
# android-changes-for-ndk-developers.md#changes-to-library-search-order
  if (COMPILER_RT_HAS_Z_GLOBAL)
    list(APPEND DUMMYSAN_DYNAMIC_LINK_FLAGS -Wl,-z,global)
  endif()
endif()

set(DUMMYSAN_DYNAMIC_CFLAGS ${DUMMYSAN_RTL_CFLAGS})
append_list_if(COMPILER_RT_HAS_FTLS_MODEL_INITIAL_EXEC
  -ftls-model=initial-exec DUMMYSAN_DYNAMIC_CFLAGS)
append_list_if(MSVC /DEBUG DUMMYSAN_DYNAMIC_LINK_FLAGS)

set(DUMMYSAN_DYNAMIC_LIBS ${SANITIZER_CXX_ABI_LIBRARIES} ${SANITIZER_COMMON_LINK_LIBS})

append_list_if(COMPILER_RT_HAS_LIBDL dl DUMMYSAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBRT rt DUMMYSAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBM m DUMMYSAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBPTHREAD pthread DUMMYSAN_DYNAMIC_LIBS)

# Static runtime library.
add_compiler_rt_component(dummysan)

add_compiler_rt_object_libraries(RTDummysan
  ARCHS ${DUMMYSAN_SUPPORTED_ARCH}
  SOURCES ${DUMMYSAN_RTL_SOURCES}
  ADDITIONAL_HEADERS ${DUMMYSAN_RTL_HEADERS}
  CFLAGS ${DUMMYSAN_RTL_CFLAGS}
  DEFS ${DUMMYSAN_DEFINITIONS})
add_compiler_rt_object_libraries(RTDummysan_dynamic
  ARCHS ${DUMMYSAN_SUPPORTED_ARCH}
  SOURCES ${DUMMYSAN_RTL_SOURCES}
  ADDITIONAL_HEADERS ${DUMMYSAN_RTL_HEADERS}
  CFLAGS ${DUMMYSAN_DYNAMIC_CFLAGS}
  DEFS ${DUMMYSAN_DEFINITIONS})

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp "")
add_compiler_rt_object_libraries(RTDummysan_dynamic_version_script_dummy
  ARCHS ${DUMMYSAN_SUPPORTED_ARCH}
  SOURCES ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
  CFLAGS ${DUMMYSAN_DYNAMIC_CFLAGS}
  DEFS ${DUMMYSAN_DEFINITIONS})

foreach(arch ${DUMMYSAN_SUPPORTED_ARCH})
  add_compiler_rt_runtime(clang_rt.dummysan
    STATIC
    ARCHS ${arch}
    OBJECT_LIBS RTDummysan
                RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
                RTSanitizerCommonCoverage
                RTSanitizerCommonSymbolizer
                RTUbsan
    CFLAGS ${DUMMYSAN_RTL_CFLAGS}
    PARENT_TARGET dummysan)

  if (UNIX)
    add_sanitizer_rt_version_list(clang_rt.dummysan-dynamic-${arch}
                                  LIBS clang_rt.dummysan-${arch}
                                  EXTRA dummysan.syms.extra)
    set(VERSION_SCRIPT_FLAG
         -Wl,--version-script,${CMAKE_CURRENT_BINARY_DIR}/clang_rt.dummysan-dynamic-${arch}.vers)
    set_property(SOURCE
      ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
      APPEND PROPERTY
      OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/clang_rt.dummysan-dynamic-${arch}.vers)
  else()
    set(VERSION_SCRIPT_FLAG)
  endif()


  add_compiler_rt_runtime(clang_rt.dummysan
    SHARED
    ARCHS ${arch}
    OBJECT_LIBS
            RTDummysan_dynamic
            RTInterception
            RTSanitizerCommon
            RTSanitizerCommonLibc
            RTSanitizerCommonCoverage
            RTSanitizerCommonSymbolizer
            RTUbsan
            RTUbsan_cxx
            # The only purpose of RTDummysan_dynamic_version_script_dummy is to
            # carry a dependency of the shared runtime on the version script.
            # Replacing it with a straightforward
            # add_dependencies(clang_rt.asan-dynamic-${arch} clang_rt.asan-dynamic-${arch}-version-list)
            # generates an order-only dependency in ninja.
            RTDummysan_dynamic_version_script_dummy
    CFLAGS ${DUMMYSAN_DYNAMIC_CFLAGS}
    LINK_FLAGS ${DUMMYSAN_DYNAMIC_LINK_FLAGS}
              ${VERSION_SCRIPT_FLAG}
    LINK_LIBS ${DUMMYSAN_DYNAMIC_LIBS}
    DEFS ${ASAN_DYNAMIC_DEFINITIONS}
    PARENT_TARGET dummysan)

  if(SANITIZER_USE_SYMBOLS)
    add_sanitizer_rt_symbols(clang_rt.dummysan
      ARCHS ${arch}
      EXTRA dummysan.syms.extra)
    add_dependencies(dummysan clang_rt.dummysan-${arch}-symbols)
  endif()
endforeach()

add_compiler_rt_resource_file(dummysan_blacklist dummysan_blacklist.txt dummysan)

add_subdirectory("scripts")

# if(COMPILER_RT_INCLUDE_TESTS)
#   add_subdirectory(tests)
# endif()
