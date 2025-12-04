cmake_minimum_required(VERSION 3.20)
project(grid_watcher VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Build Options
# ============================================================================
option(ENABLE_LTO "Enable Link-Time Optimization" ON)
option(ENABLE_NATIVE "Enable -march=native optimization" ON)
option(ENABLE_PROFILING "Enable profiling support" OFF)
option(BUILD_BENCHMARKS "Build performance benchmarks" ON)

# ============================================================================
# C++ Standard
# ============================================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================================
# Output Directories
# ============================================================================
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib")

# ============================================================================
# Compiler-Specific Optimizations
# ============================================================================

# Detect compiler
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(COMPILER_IS_GCC_OR_CLANG TRUE)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    set(COMPILER_IS_MSVC TRUE)
endif()

# Base compiler flags
if(COMPILER_IS_GCC_OR_CLANG)
    set(BASE_CXX_FLAGS
        -Wall
        -Wextra
        -Wpedantic
        -Wno-c++98-compat
        -Wno-c++98-compat-pedantic
        -Wno-sign-conversion
        -Wno-c++11-narrowing
    )
    
    # Release optimizations
    set(RELEASE_CXX_FLAGS
        -O3                         # Maximum optimization
        -ffast-math                 # Fast floating-point operations
        -funroll-loops              # Aggressive loop unrolling
        -finline-functions          # Inline small functions
        -fomit-frame-pointer        # Remove frame pointer overhead
        -fstrict-aliasing           # Strict aliasing rules
        -fno-exceptions             # Disable exceptions (optional)
        -fvisibility=hidden         # Hide symbols by default
    )
    
    # Native architecture optimization
    if(ENABLE_NATIVE)
        list(APPEND RELEASE_CXX_FLAGS
            -march=native           # Use CPU-specific instructions
            -mtune=native           # Tune for current CPU
        )
    endif()
    
    # Link-Time Optimization (LTO)
    if(ENABLE_LTO)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
        list(APPEND RELEASE_CXX_FLAGS -flto)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    endif()
    
    # Profiling support
    if(ENABLE_PROFILING)
        list(APPEND BASE_CXX_FLAGS -g -fno-omit-frame-pointer)
    endif()
    
elseif(COMPILER_IS_MSVC)
    set(BASE_CXX_FLAGS
        /W4                         # Warning level 4
        /permissive-                # Strict standard conformance
        /Zc:__cplusplus             # Correct __cplusplus macro
    )
    
    set(RELEASE_CXX_FLAGS
        /O2                         # Maximum optimization
        /Ob2                        # Inline function expansion
        /Oi                         # Enable intrinsic functions
        /Ot                         # Favor fast code
        /GL                         # Whole program optimization
        /fp:fast                    # Fast floating-point
    )
    
    if(ENABLE_LTO)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /LTCG")
    endif()
endif()

# ============================================================================
# Platform-Specific Settings
# ============================================================================

if(WIN32)
    add_definitions(-D_WIN32_WINNT=0x0601)  # Windows 7+
    set(PLATFORM_LIBS ws2_32)
elseif(UNIX)
    set(PLATFORM_LIBS pthread)
endif()

# ============================================================================
# Include Directories
# ============================================================================

include_directories(${CMAKE_SOURCE_DIR}/include)

# ============================================================================
# Source Files Organization
# ============================================================================

# Core networking sources
set(CORE_HEADERS
    include/zuu/core/ipv4.hpp
    include/zuu/core/socket_address.hpp
    include/zuu/core/socket_base.hpp
    include/zuu/core/tcp_socket.hpp
)

# Meta programming headers
set(META_HEADERS
    include/zuu/meta/arithmetic.hpp
)

# Utility headers
set(UTILS_HEADERS
    include/zuu/utils/convert.hpp
    include/zuu/utils/clamp.hpp
    include/zuu/utils/subnet.hpp
)

# SCADA-specific headers
set(SCADA_HEADERS
    include/zuu/scada/scada_types.hpp
    include/zuu/scada/modbus_parser.hpp
    include/zuu/scada/behavioral_analyzer.hpp
    include/zuu/scada/mitigation_engine.hpp
)

# Performance primitives
set(PERF_HEADERS
    include/zuu/performance/lock_free.hpp
    include/zuu/performance/fast_hash.hpp
    include/zuu/performance/bloom_filter.hpp
    include/zuu/performance/cache_utils.hpp
)

# Main engine
set(ENGINE_HEADERS
    include/zuu/grid_watcher.hpp
)

# All headers
set(ALL_HEADERS
    ${CORE_HEADERS}
    ${META_HEADERS}
    ${UTILS_HEADERS}
    ${SCADA_HEADERS}
    ${PERF_HEADERS}
    ${ENGINE_HEADERS}
)

# ============================================================================
# Main Executable
# ============================================================================

add_executable(${PROJECT_NAME}
    src/main.cpp
    ${ALL_HEADERS}  # For IDE support
)

# Apply compiler flags
target_compile_options(${PROJECT_NAME} PRIVATE
    ${BASE_CXX_FLAGS}
    $<$<CONFIG:Release>:${RELEASE_CXX_FLAGS}>
    $<$<CONFIG:Debug>:-g -O0>
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE ${PLATFORM_LIBS})

# ============================================================================
# Benchmarks (Optional)
# ============================================================================

# if(BUILD_BENCHMARKS)
#     add_executable(benchmark_grid_watcher
#         src/benchmarks.cpp
#         ${ALL_HEADERS}
#     )
    
#     target_compile_options(benchmark_grid_watcher PRIVATE
#         ${BASE_CXX_FLAGS}
#         ${RELEASE_CXX_FLAGS}
#     )
    
#     target_link_libraries(benchmark_grid_watcher PRIVATE ${PLATFORM_LIBS})
# endif()

# ============================================================================
# Custom Targets
# ============================================================================

# Performance analysis with perf (Linux only)
if(UNIX AND NOT APPLE)
    add_custom_target(perf
        COMMAND perf record -g ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}
        COMMAND perf report
        DEPENDS ${PROJECT_NAME}
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        COMMENT "Running performance analysis with perf"
    )
    
    add_custom_target(perf_stat
        COMMAND perf stat -e cache-misses,cache-references,instructions,cycles
                ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}
        DEPENDS ${PROJECT_NAME}
        WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
        COMMENT "Collecting performance statistics"
    )
endif()

# Valgrind memory check
add_custom_target(memcheck
    COMMAND valgrind --leak-check=full --show-leak-kinds=all
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}
    DEPENDS ${PROJECT_NAME}
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running memory leak detection"
)

# Callgrind profiling
add_custom_target(callgrind
    COMMAND valgrind --tool=callgrind
            ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${PROJECT_NAME}
    DEPENDS ${PROJECT_NAME}
    WORKING_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    COMMENT "Running Callgrind profiler"
)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)

# ============================================================================
# Print Configuration
# ============================================================================

message(STATUS "=================================================")
message(STATUS "Grid-Watcher Build Configuration")
message(STATUS "=================================================")
message(STATUS "Build Type:            ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler:              ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ Standard:          C++${CMAKE_CXX_STANDARD}")
message(STATUS "LTO Enabled:           ${ENABLE_LTO}")
message(STATUS "Native Optimization:   ${ENABLE_NATIVE}")
message(STATUS "Profiling:             ${ENABLE_PROFILING}")
message(STATUS "Benchmarks:            ${BUILD_BENCHMARKS}")
message(STATUS "Install Prefix:        ${CMAKE_INSTALL_PREFIX}")
message(STATUS "=================================================")

# ============================================================================
# Build Commands Summary
# ============================================================================

message(STATUS "")
message(STATUS "Build commands:")
message(STATUS "  mkdir build && cd build")
message(STATUS "  cmake -DCMAKE_BUILD_TYPE=Release ..")
message(STATUS "  cmake --build . -j$(nproc)")
message(STATUS "")
message(STATUS "Performance analysis:")
message(STATUS "  make perf          # Run with perf profiler")
message(STATUS "  make perf_stat     # Cache statistics")
message(STATUS "  make callgrind     # Callgrind profiling")
message(STATUS "  make memcheck      # Memory leak detection")
message(STATUS "=================================================")
