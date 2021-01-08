set(EXAMPLESAN_SOURCES
  examplesan.cpp
)

set(EXAMPLESAN_HEADERS
  examplesan.h
)

include_directories(..)

set(EXAMPLESAN_CFLAGS ${SANITIZER_COMMON_CFLAGS})
set(EXAMPLESAN_COMMON_DEFINITIONS "")

append_rtti_flag(OFF EXAMPLESAN_CFLAGS)

set(EXAMPLESAN_DYNAMIC_LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS})

if(ANDROID)
# Put most Sanitizer shared libraries in the global group. For more details, see
# android-changes-for-ndk-developers.md#changes-to-library-search-order
  if (COMPILER_RT_HAS_Z_GLOBAL)
    list(APPEND EXAMPLESAN_DYNAMIC_LINK_FLAGS -Wl,-z,global)
  endif()
endif()

set(EXAMPLESAN_DYNAMIC_DEFINITIONS
  ${EXAMPLESAN_COMMON_DEFINITIONS} EXAMPLESAN_DYNAMIC=1)
append_list_if(WIN32 INTERCEPTION_DYNAMIC_CRT EXAMPLESAN_DYNAMIC_DEFINITIONS)

set(EXAMPLESAN_DYNAMIC_CFLAGS ${EXAMPLESAN_CFLAGS})
append_list_if(COMPILER_RT_HAS_FTLS_MODEL_INITIAL_EXEC
  -ftls-model=initial-exec EXAMPLESAN_DYNAMIC_CFLAGS)
append_list_if(MSVC /DEBUG EXAMPLESAN_DYNAMIC_LINK_FLAGS)

set(EXAMPLESAN_DYNAMIC_LIBS ${SANITIZER_CXX_ABI_LIBRARIES} ${SANITIZER_COMMON_LINK_LIBS})

append_list_if(COMPILER_RT_HAS_LIBDL dl EXAMPLESAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBRT rt EXAMPLESAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBM m EXAMPLESAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBPTHREAD pthread EXAMPLESAN_DYNAMIC_LIBS)
append_list_if(COMPILER_RT_HAS_LIBLOG log EXAMPLESAN_DYNAMIC_LIBS)
append_list_if(MINGW "${MINGW_LIBRARIES}" EXAMPLESAN_DYNAMIC_LIBS)

set(EXAMPLESAN_STATIC_CFLAGS ${EXAMPLESAN_CFLAGS})

# Compile sources into an object library.

add_compiler_rt_object_libraries(RTExamplesan_dynamic
  OS ${SANITIZER_COMMON_SUPPORTED_OS}
  ARCHS ${EXAMPLESAN_SUPPORTED_ARCH}
  SOURCES ${EXAMPLESAN_SOURCES}
  ADDITIONAL_HEADERS ${EXAMPLESAN_HEADERS}
  CFLAGS ${EXAMPLESAN_DYNAMIC_CFLAGS}
  DEFS ${EXAMPLESAN_DYNAMIC_DEFINITIONS})

if(NOT APPLE)
  add_compiler_rt_object_libraries(RTExamplesan
    ARCHS ${EXAMPLESAN_SUPPORTED_ARCH}
    SOURCES ${EXAMPLESAN_SOURCES}
    ADDITIONAL_HEADERS ${EXAMPLESAN_HEADERS}
    CFLAGS ${EXAMPLESAN_CFLAGS}
    DEFS ${EXAMPLESAN_COMMON_DEFINITIONS})

  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp "")

  add_compiler_rt_object_libraries(RTExamplesan_dynamic_version_script_dummy
    ARCHS ${EXAMPLESAN_SUPPORTED_ARCH}
    SOURCES ${CMAKE_CURRENT_BINARY_DIR}/dummy.cpp
    CFLAGS ${EXAMPLESAN_DYNAMIC_CFLAGS}
    DEFS ${EXAMPLESAN_DYNAMIC_DEFINITIONS})
endif()

add_compiler_rt_component(examplesan)

append_list_if(COMPILER_RT_HAS_FPIE_FLAG -fPIE EXAMPLESAN_CFLAGS)
append_list_if(COMPILER_RT_HAS_FPIC_FLAG -fPIC EXAMPLESAN_CFLAGS)

if(APPLE)
  add_weak_symbols("examplesan" WEAK_SYMBOL_LINK_FLAGS)
  add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)

  add_compiler_rt_runtime(clang_rt.examplesan
    SHARED
    OS ${SANITIZER_COMMON_SUPPORTED_OS}
    ARCHS ${EXAMPLESAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTExamplesan_dynamic
                RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
                ${EXAMPLESAN_DYNAMIC_LIBS}
    CFLAGS ${EXAMPLESAN_DYNAMIC_CFLAGS}
    LINK_FLAGS ${WEAK_SYMBOL_LINK_FLAGS}
    DEFS ${EXAMPLESAN_DYNAMIC_DEFINITIONS}
    PARENT_TARGET asan)
else()
  # Build separate libraries for each target.

  set(EXAMPLESAN_COMMON_RUNTIME_OBJECT_LIBS
    RTInterception
    RTSanitizerCommon
    RTSanitizerCommonLibc)

  add_compiler_rt_runtime(clang_rt.examplesan
    STATIC
    ARCHS ${EXAMPLESAN_SUPPORTED_ARCH}
    OBJECT_LIBS RTExamplesan
                ${EXAMPLESAN_COMMON_RUNTIME_OBJECT_LIBS}
    CFLAGS ${EXAMPLESAN_STATIC_CFLAGS}
    DEFS ${EXAMPLESAN_COMMON_DEFINITIONS}
    PARENT_TARGET examplesan)

  foreach(arch ${EXAMPLESAN_SUPPORTED_ARCH})
    set(VERSION_SCRIPT_FLAG)

    add_compiler_rt_runtime(clang_rt.examplesan
      SHARED
      ARCHS ${arch}
      SOURCES ${EXAMPLESAN_SOURCES}
      OBJECT_LIBS ${EXAMPLESAN_COMMON_RUNTIME_OBJECT_LIBS}
      CFLAGS ${EXAMPLESAN_DYNAMIC_CFLAGS}
      LINK_FLAGS ${EXAMPLESAN_DYNAMIC_LINK_FLAGS}
                ${VERSION_SCRIPT_FLAG}
      LINK_LIBS ${EXAMPLESAN_DYNAMIC_LIBS}
      PARENT_TARGET examplesan
    )

    if (SANITIZER_USE_SYMBOLS AND NOT ${arch} STREQUAL "i386")
      add_sanitizer_rt_symbols(clang_rt.examplesan
        ARCHS ${arch}
        EXTRA examplesan.syms.extra)
      add_dependencies(examplesan clang_rt.examplesan-${arch}-symbols)
    endif()

  endforeach()
endif()

add_compiler_rt_resource_file(examplesan_blacklist examplesan_blacklist.txt examplesan)

if(COMPILER_RT_INCLUDE_TESTS)
  add_subdirectory(tests)
endif()
