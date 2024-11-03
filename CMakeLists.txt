cmake_minimum_required (VERSION 3.19)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

project ("crypto-pro-examples-cmake")


list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(CryptoPro COMPONENTS cades xades)


# Examples from CryptoPro SDK

add_executable (AddSignCades "src/AddSignCades/AddSignCades.cpp"  "src/samples_util.h")
target_link_libraries(AddSignCades PRIVATE CryptoPro::cades)

add_executable (CounterSign "src/CounterSign/CounterSign.cpp"  "src/samples_util.h")
target_link_libraries(CounterSign PRIVATE CryptoPro::cades)

add_executable (GetCadesAttributes "src/GetCadesAttributes/GetCadesAttributes.cpp"  "src/samples_util.h")
target_link_libraries(GetCadesAttributes PRIVATE CryptoPro::cades)

add_executable (GetCadesCountersignatureAttributes "src/GetCadesCountersignatureAttributes/GetCadesCountersignatureAttributes.cpp"  "src/samples_util.h")
target_link_libraries(GetCadesCountersignatureAttributes PRIVATE CryptoPro::cades)

#add_executable (LowlevelDisplayDetachedSignature "src/LowlevelDisplayDetachedSignature/LowlevelDisplayDetachedSignature.cpp"  "src/samples_util.h")
#target_link_libraries(LowlevelDisplayDetachedSignature PRIVATE CryptoPro::cades)

add_executable (LowlevelDisplaySignatures "src/LowlevelDisplaySignatures/LowlevelDisplaySignatures.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelDisplaySignatures PRIVATE CryptoPro::cades)

add_executable (LowlevelEnhanceCadesBes "src/LowlevelEnhanceCadesBes/LowlevelEnhanceCadesBes.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelEnhanceCadesBes PRIVATE CryptoPro::cades)

add_executable (LowlevelSignCades "src/LowlevelSignCades/LowlevelSignCades.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelSignCades PRIVATE CryptoPro::cades)

add_executable (LowlevelSignCadesBes "src/LowlevelSignCadesBes/LowlevelSignCadesBes.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelSignCadesBes PRIVATE CryptoPro::cades)

add_executable (LowlevelSignCadesStream "src/LowlevelSignCadesStream/LowlevelSignCadesStream.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelSignCadesStream PRIVATE CryptoPro::cades)

add_executable (LowlevelSignDetachedCades "src/LowlevelSignDetachedCades/LowlevelSignDetachedCades.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelSignDetachedCades PRIVATE CryptoPro::cades)

add_executable (LowlevelVerifyCades "src/LowlevelVerifyCades/LowlevelVerifyCades.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelVerifyCades PRIVATE CryptoPro::cades)

add_executable (LowlevelVerifyCadesBes "src/LowlevelVerifyCadesBes/LowlevelVerifyCadesBes.cpp"  "src/samples_util.h")
target_link_libraries(LowlevelVerifyCadesBes PRIVATE CryptoPro::cades)

add_executable (SimplifiedDisplaySignatures "src/SimplifiedDisplaySignatures/SimplifiedDisplaySignatures.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedDisplaySignatures PRIVATE CryptoPro::cades)

add_executable (SimplifiedEnhanceCadesBes "src/SimplifiedEnhanceCadesBes/SimplifiedEnhanceCadesBes.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedEnhanceCadesBes PRIVATE CryptoPro::cades)

add_executable (SimplifiedSignCades "src/SimplifiedSignCades/SimplifiedSignCades.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedSignCades PRIVATE CryptoPro::cades)

add_executable (SimplifiedSignCadesBes "src/SimplifiedSignCadesBes/SimplifiedSignCadesBes.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedSignCadesBes PRIVATE CryptoPro::cades)

add_executable (SimplifiedSignHashCades "src/SimplifiedSignHashCades/SimplifiedSignHashCades.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedSignHashCades PRIVATE CryptoPro::cades)

add_executable (SimplifiedSignVerifyXadesBes "src/SimplifiedSignVerifyXadesBes/SimplifiedSignVerifyXadesBes.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedSignVerifyXadesBes PRIVATE CryptoPro::cades CryptoPro::xades)

add_executable (SimplifiedVerifyCades "src/SimplifiedVerifyCades/SimplifiedVerifyCades.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedVerifyCades PRIVATE CryptoPro::cades)

add_executable (SimplifiedVerifyCadesBes "src/SimplifiedVerifyCadesBes/SimplifiedVerifyCadesBes.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedVerifyCadesBes PRIVATE CryptoPro::cades)

add_executable (SimplifiedVerifyHashCades "src/SimplifiedVerifyHashCades/SimplifiedVerifyHashCades.cpp"  "src/samples_util.h")
target_link_libraries(SimplifiedVerifyHashCades PRIVATE CryptoPro::cades)

add_executable (VerifyCountersign "src/VerifyCountersign/VerifyCountersign.cpp"  "src/samples_util.h")
target_link_libraries(VerifyCountersign PRIVATE CryptoPro::cades)


# Other examples

add_executable (EncryptDecryptMessage "src/EncryptDecryptMessage/EncryptDecryptMessage.cpp")
target_link_libraries(EncryptDecryptMessage PRIVATE crypt32)
