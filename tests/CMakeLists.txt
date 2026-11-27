add_executable(np_tests test_packet.c)
target_link_libraries(np_tests PRIVATE np np_warnings)
add_test(NAME np_unit_tests COMMAND np_tests)

add_test(NAME network_processor_sample
         COMMAND network_processor ${CMAKE_CURRENT_SOURCE_DIR}/data/sample_frames.hex)
set_tests_properties(network_processor_sample PROPERTIES
    PASS_REGULAR_EXPRESSION "frame 1: 192.168.1.10:51234 -> 10.0.0.1:443 proto=tcp payload=5 checksum=ok\nframe 2: 192.168.1.10:40000 -> 10.0.0.1:53 proto=udp payload=10 checksum=ok")
