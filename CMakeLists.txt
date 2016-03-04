CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(rijndael LANGUAGES C CXX)

INCLUDE(CheckCCompilerFlag)
INCLUDE(CheckCXXCompilerFlag)

MACRO(ADD_C_COMPILER_FLAG FLAGS FLAG)
    STRING(MAKE_C_IDENTIFIER "${FLAG}" ID)
    CHECK_C_COMPILER_FLAG("${FLAG}" "CFLAG_${ID}")
    IF(CFLAG_${ID})
        SET(${FLAGS} "${${FLAGS}} ${FLAG}")
    ENDIF()
ENDMACRO()

MACRO(ADD_CXX_COMPILER_FLAG FLAGS FLAG)
    STRING(MAKE_C_IDENTIFIER "${FLAG}" ID)
    CHECK_CXX_COMPILER_FLAG("${FLAG}" "CXXFLAG_${ID}")
    IF(CXXFLAG_${ID})
        SET(${FLAGS} "${${FLAGS}} ${FLAG}")
    ENDIF()
ENDMACRO()

# MSVC options
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/Wall")          # Enable all warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/WX")            # Treat warnings as errors
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/Za")            # Disable language extensions
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/Zi")            # Generate debugging information (PDB)
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/arch:SSE")      # Enable SSE opcodes
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "/arch:SSE2")     # Enable SSE2 opcodes
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS_RELEASE "/O2")    # Enable optimization
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS_RELWITHDEBINFO "/O2") # Enable optimization
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS_MINSIZEREL "/Os") # Optimize size

# GCC/Clang options
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Wall")          # Enable all (actually most) warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Weverything")   # (Clang) Enable ALL warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Wextra")        # (GCC) Enable more (all?) warnings
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Wpedantic")     # (GCC) Disable language extensions
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-Werror")        # Treat warnings as errors
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-std=c99")       # Enable C99
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++0x")     # Enable C++11 (older GCC versions)
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++11")     # Enable C++11
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++14")     # Enable C++14 (if available)
ADD_CXX_COMPILER_FLAG(CMAKE_CXX_FLAGS "-std=c++17")     # Enable C++17 (if available)
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-g")             # Generate debugging information
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-msse")          # Enable SSE opcodes
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS "-msse2")         # Enable SSE2 opcodes
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS_RELEASE "-O2")    # Enable optimization
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2") # Enable optimization
ADD_C_COMPILER_FLAG(CMAKE_C_FLAGS_MINSIZEREL "-Os") # Optimize size

ADD_LIBRARY(rijndael
    rijndael.h
    rijndael.c
)

FILE(GLOB TESTS tests/*.cpp)

ADD_EXECUTABLE(rijntest
    catch.hpp
    testmain.cpp
    ${TESTS}
)
TARGET_INCLUDE_DIRECTORIES(rijntest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
TARGET_LINK_LIBRARIES(rijntest rijndael)

ADD_CUSTOM_TARGET(gentests
    DEPENDS gentests.py KAT_AES.zip
    COMMAND python gentests.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

