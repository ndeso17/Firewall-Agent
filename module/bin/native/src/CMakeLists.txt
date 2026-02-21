cmake_minimum_required(VERSION 3.16)
project(infer_runner_native CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED ONNXRUNTIME_ROOT)
  message(FATAL_ERROR "ONNXRUNTIME_ROOT is required")
endif()

set(ORT_INCLUDE_ROOT "${ONNXRUNTIME_ROOT}/include")
set(ORT_SESSION_INCLUDE "${ORT_INCLUDE_ROOT}/onnxruntime/core/session")
set(ORT_LIB_DIR "${ONNXRUNTIME_ROOT}/lib")
set(ORT_CXX_HEADER "${ORT_INCLUDE_ROOT}/onnxruntime_cxx_api.h")
set(ORT_LIB "${ORT_LIB_DIR}/libonnxruntime.so")

if(NOT EXISTS "${ORT_CXX_HEADER}")
  message(FATAL_ERROR "onnxruntime_cxx_api.h not found under ${ONNXRUNTIME_ROOT}/include")
endif()

if(NOT EXISTS "${ORT_LIB}")
  message(FATAL_ERROR "libonnxruntime not found under ${ONNXRUNTIME_ROOT}/lib")
endif()

add_executable(infer_runner_native infer_runner_native.cpp)
target_include_directories(infer_runner_native PRIVATE "${ORT_INCLUDE_ROOT}" "${ORT_SESSION_INCLUDE}")
target_link_libraries(infer_runner_native PRIVATE "${ORT_LIB}")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_options(infer_runner_native PRIVATE "-Wl,-rpath,'$ORIGIN/lib'")
endif()
