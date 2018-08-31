include_directories(.)

add_executable(
  UT_test 
  test_pb_variable.cpp
  main.cpp
)
target_link_libraries(
  UT_test
  snark
  gtest_main
)
target_include_directories(
  UT_test

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

