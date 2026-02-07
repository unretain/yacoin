cmake_minimum_required(VERSION 3.18)
project(yacminer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Options
option(WITH_CUDA "Build with CUDA support (NVIDIA)" ON)
option(WITH_OPENCL "Build with OpenCL support (AMD)" OFF)

# Find packages
find_package(Threads REQUIRED)

# JSON library (json-c or nlohmann)
find_package(PkgConfig)
if(PkgConfig_FOUND)
    pkg_check_modules(JSON json-c)
endif()

# Source files
set(CORE_SOURCES
    src/main.cpp
    src/core/stratum.cpp
)

set(CORE_HEADERS
    src/core/miner.h
    src/core/stratum.h
)

# CUDA support
if(WITH_CUDA)
    enable_language(CUDA)
    find_package(CUDAToolkit REQUIRED)

    set(CUDA_SOURCES
        src/cuda/scrypt_jane.cu
    )

    add_library(cuda_miner STATIC ${CUDA_SOURCES})
    target_include_directories(cuda_miner PRIVATE src)
    set_target_properties(cuda_miner PROPERTIES
        CUDA_SEPARABLE_COMPILATION ON
        CUDA_ARCHITECTURES "61;70;75;80;86;89;90"  # Pascal through Ada
    )

    add_definitions(-DUSE_CUDA)
endif()

# OpenCL support
if(WITH_OPENCL)
    find_package(OpenCL REQUIRED)

    set(OPENCL_SOURCES
        src/opencl/opencl_miner.cpp
    )

    add_definitions(-DUSE_OPENCL)
endif()

# Main executable
add_executable(yacminer ${CORE_SOURCES} ${CORE_HEADERS})

target_include_directories(yacminer PRIVATE src)

# Link libraries
target_link_libraries(yacminer PRIVATE Threads::Threads)

if(WITH_CUDA)
    target_link_libraries(yacminer PRIVATE cuda_miner CUDA::cudart)
endif()

if(WITH_OPENCL)
    target_link_libraries(yacminer PRIVATE OpenCL::OpenCL)
endif()

if(JSON_FOUND)
    target_include_directories(yacminer PRIVATE ${JSON_INCLUDE_DIRS})
    target_link_libraries(yacminer PRIVATE ${JSON_LIBRARIES})
else()
    message(WARNING "json-c not found, using built-in minimal JSON parser")
endif()

# Windows specific
if(WIN32)
    target_link_libraries(yacminer PRIVATE ws2_32)
endif()

# Install
install(TARGETS yacminer RUNTIME DESTINATION bin)

# Copy OpenCL kernels
if(WITH_OPENCL)
    install(FILES src/opencl/scrypt_jane.cl DESTINATION share/yacminer)
endif()

# Print configuration
message(STATUS "")
message(STATUS "YaCoin GPU Miner Configuration:")
message(STATUS "  CUDA support: ${WITH_CUDA}")
message(STATUS "  OpenCL support: ${WITH_OPENCL}")
message(STATUS "")
