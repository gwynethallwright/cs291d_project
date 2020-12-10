include_directories(.)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_executable(
  test

  test.cpp
)
target_link_libraries(
  test

  snark
)
target_include_directories(
  test

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_library(
  pour

  SHARED
  pour.cpp
  pour.hpp
)
target_link_libraries(
  pour

  PRIVATE
  snark
)
target_include_directories(
  pour

  PRIVATE
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

add_executable(
  main

  main.cpp
)
target_link_libraries(
  main 

  PRIVATE
  pour
)
