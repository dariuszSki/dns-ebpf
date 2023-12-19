cmake_minimum_required(VERSION 3.22)
project(ebpf C)

set(CMAKE_C_STANDARD 23)

add_executable(ebpf zfw-dns.c
        dns_filter_xdp.c)