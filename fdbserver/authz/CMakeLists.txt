fdb_find_sources(FDBSERVER_AUTHZ_SRCS)

add_flow_target(STATIC_LIBRARY NAME fdbserver_authz SRCS ${FDBSERVER_AUTHZ_SRCS})
add_fdbserver_link_test(fdbserver_authzlinktest
  fdbserver_authz
  fdbserver_core)

configure_fdbserver_common_includes(fdbserver_authz)
target_include_directories(fdbserver_authz
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(fdbserver_authz
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(fdbserver_authz PRIVATE fdbserver_core)
