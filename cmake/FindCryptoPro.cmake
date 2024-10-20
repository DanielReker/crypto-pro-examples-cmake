# TODO: Write docs
# TODO: Add Linux support

# This module defines the following imported targets (depending on requested COMPONENTS):
#   CryptoPro::cades
#   CryptoPro::xades
#   CryptoPro::cplib
#   CryptoPro::cpasn1
#   CryptoPro::asn1xercpp
#   CryptoPro::asn1rtcpp
#   CryptoPro::asn1bercpp
#   CryptoPro::asn1

include(FindPackageHandleStandardArgs)

find_path(CryptoPro_ROOT_DIR
  NAMES include/cades.h
  PATHS
    "C:/Program Files (x86)/Crypto Pro/SDK"
    "$ENV{CRYPTOPRO_ROOT}"
    DOC "Root directory of CryptoPro installation"
)

find_path(CryptoPro_INCLUDE_DIR
  NAMES cades.h
  PATHS ${CryptoPro_ROOT_DIR}/include
)

# Determine library architecture (x86 vs x64)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(CryptoPro_ARCH_PATH "lib/amd64")
else()
  set(CryptoPro_ARCH_PATH "lib")
endif()


foreach(component IN LISTS CryptoPro_FIND_COMPONENTS)
  find_library(CryptoPro_${component}_LIBRARY
    NAMES ${component}
    PATHS ${CryptoPro_ROOT_DIR}/${CryptoPro_ARCH_PATH}
  )
  if(CryptoPro_${component}_LIBRARY)
    set(CryptoPro_${component}_FOUND TRUE)
  endif()
endforeach()

find_package_handle_standard_args(CryptoPro
  HANDLE_COMPONENTS
  REQUIRED_VARS
    CryptoPro_INCLUDE_DIR
)

if(CryptoPro_FOUND)
  foreach(component IN LISTS CryptoPro_FIND_COMPONENTS)
    if(CryptoPro_${component}_FOUND)
      add_library(CryptoPro::${component} SHARED IMPORTED)
      set_target_properties(
          CryptoPro::${component}
          PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${CryptoPro_INCLUDE_DIR}"
            IMPORTED_IMPLIB "${CryptoPro_${component}_LIBRARY}"
      )
      if(MSVC)
        target_link_libraries(CryptoPro::${component} INTERFACE crypt32)
      endif()
    endif()
  endforeach()
endif()
