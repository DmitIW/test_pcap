cmake_minimum_required(VERSION 3.0)

include(ExternalProject)

find_program(MAKE_EXECUTABLE
             NAMES make)

set(DPDK_PATH ${CMAKE_SOURCE_DIR}/dpdk)
SET(DPDK_BUILD_DIR ${CMAKE_BINARY_DIR}/dpdk/build)
SET(ENV{RTE_OUTPUT} ${DPDK_BUILD_DIR})

IF(NOT EXISTS ${DPDK_PATH}/.git)
	MESSAGE("Submodule not initialized: dpdk")
	EXECUTE_PROCESS(
		COMMAND sh -c     "git submodule update --init"
		WORKING_DIRECTORY ${DPDK_PATH}
	)
ENDIF()

configure_file(${CMAKE_SOURCE_DIR}/rte.config ${DPDK_BUILD_DIR}/.config)

ExternalProject_Add(
	dpdk
	PREFIX ${DPDK_BUILD_DIR}
	SOURCE_DIR ${DPDK_PATH}
	CONFIGURE_COMMAND ""
	BINARY_DIR ${DPDK_BUILD_DIR}
	BUILD_COMMAND ${MAKE_EXECUTABLE} -C ${DPDK_PATH} O=${DPDK_BUILD_DIR}
	INSTALL_COMMAND ""
)

INCLUDE_DIRECTORIES(${DPDK_BUILD_DIR}/include)
LINK_DIRECTORIES(${DPDK_BUILD_DIR}/lib)


PROJECT(test_pcap)

SET(SRC
		main.c filter.c filter.h)
SET(CMAKE_C_FLAGS "-mssse3")

ADD_EXECUTABLE(${CMAKE_PROJECT_NAME} ${SRC})
TARGET_LINK_LIBRARIES(${CMAKE_PROJECT_NAME}
	 -Wl,--whole-archive
	rte_eal rte_mbuf rte_pmd_pcap rte_mempool rte_ethdev rte_kvargs rte_bus_vdev rte_ring rte_mempool_ring rte_hash

	-Wl,--as-needed
	-Wl,--no-whole-archive
	pcap pthread dl)
ADD_DEPENDENCIES(${CMAKE_PROJECT_NAME} dpdk)

file(COPY ${CMAKE_SOURCE_DIR}/test_tcp.pcap DESTINATION ${CMAKE_BINARY_DIR})

ADD_CUSTOM_TARGET(run
	${CMAKE_PROJECT_NAME} --vdev 'net_pcap0,rx_pcap=test_tcp.pcap,tx_pcap=test_tcp_accepted.pcap' --vdev 'net_pcap1,rx_pcap=test_tcp.pcap,tx_pcap=test_tcp_drop.pcap' --no-huge
	DEPENDS ${CMAKE_PROJECT_NAME}
	WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

