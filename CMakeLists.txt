cmake_minimum_required(VERSION 3.20.0)
project(digest)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules/")
find_package(QatDrv REQUIRED COMPONENTS qat_s usdm_drv_s)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")


set(qat_digest_srcs
  crypto.cc
)

add_library(qat_digest SHARED ${qat_digest_srcs})
target_link_libraries(qat_digest PRIVATE
	              QatDrv::qat_s
		      QatDrv::usdm_drv_s)

add_executable(digest main.cc)
target_link_libraries(digest 
	              PRIVATE qat_digest 
		      PRIVATE QatDrv::qat_s
		      PRIVATE QatDrv::usdm_drv_s)

