cmake_minimum_required (VERSION 2.8...3.10)

project(sapp_ctest)

add_test(NAME COPY_CREATE_DIR COMMAND sh -c "mkdir -p ${CMAKE_BINARY_DIR}/testing/bin ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp/ ${CMAKE_BINARY_DIR}/testing/lib/")
add_test(NAME COPY_SAPP COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/src/entry/sapp ${CMAKE_BINARY_DIR}/testing/")

add_test(NAME COPY_ISAKMP_DIR COMMAND sh -c "mkdir -p ${CMAKE_BINARY_DIR}/testing/plug/protocol/isakmp_protocol_plug")
add_test(NAME COPY_ISAKMP_INF COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/bin/plug/protocol/isakmp_protocol_plug/isakmp_protocol_plug.inf ${CMAKE_BINARY_DIR}/testing/plug/protocol/isakmp_protocol_plug")
add_test(NAME COPY_ISAKMP_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/src/extensions/isakmp_protocol_plug.so ${CMAKE_BINARY_DIR}/testing/plug/protocol/isakmp_protocol_plug")

add_test(NAME COPY_L2TP_DIR COMMAND sh -c "mkdir -p ${CMAKE_BINARY_DIR}/testing/plug/protocol/l2tp_protocol_plug")
add_test(NAME COPY_L2TP_INF COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/bin/plug/protocol/l2tp_protocol_plug/l2tp_protocol_plug.inf ${CMAKE_BINARY_DIR}/testing/plug/protocol/l2tp_protocol_plug/")
add_test(NAME COPY_L2TP_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/src/extensions/l2tp_protocol_plug.so ${CMAKE_BINARY_DIR}/testing/plug/protocol/l2tp_protocol_plug/")

add_test(NAME COPY_PPTP_DIR COMMAND sh -c "mkdir -p ${CMAKE_BINARY_DIR}/testing/plug/protocol/pptp_protocol_plug")
add_test(NAME COPY_PPTP_INF COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/bin/plug/protocol/pptp_protocol_plug/pptp_protocol_plug.inf ${CMAKE_BINARY_DIR}/testing/plug/protocol/pptp_protocol_plug/")
add_test(NAME COPY_PPTP_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/src/extensions/pptp_protocol_plug.so ${CMAKE_BINARY_DIR}/testing/plug/protocol/pptp_protocol_plug/")

add_test(NAME COPY_BENCHMARK_PLUG COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/benchmark/example/test_benchmark_plug.so ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp/")
add_test(NAME COPY_LIBBENCHMARK COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/benchmark/src/libsapp_benchmark.so ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp/")
add_test(NAME COPY_GTEST_SAPP COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/gtest_sapp_v4 ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_INLINE_SAPP COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/inline_test_sapp_v4 ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_TRANSPARENT_SAPP COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/transparent_test_sapp_v4 ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_GTEST_PLUG_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/libgtest_sapp.so ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp")
add_test(NAME COPY_GTEST_PLUG_INF COMMAND sh -c "cp ${CMAKE_SOURCE_DIR}/module_test/bin/plug/business/gtest_sapp/gtest_sapp.inf ${CMAKE_BINARY_DIR}/testing/plug/business/gtest_sapp")
add_test(NAME COPY_FAKE_MARSIO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/module_test/src/libgtest_fake_marsio.so ${CMAKE_BINARY_DIR}/testing/lib/")
add_test(NAME COPY_TEST_PCAP COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/module_test/test_case/TEST_PCAP ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_TEST_PROFILE COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/module_test/test_case/TEST_PROFILE ${CMAKE_BINARY_DIR}/testing/")
add_test(NAME COPY_DEFAULT_CONFIG COMMAND sh -c "cp -r ${CMAKE_SOURCE_DIR}/benchmark/sapp_default_config/etc ${CMAKE_BINARY_DIR}/testing/")

add_test(NAME SOFT_LINK_BENCHMARK_PCAP COMMAND sh -c "ln -fs ${CMAKE_SOURCE_DIR}/benchmark_pcap/ ${CMAKE_BINARY_DIR}/")
