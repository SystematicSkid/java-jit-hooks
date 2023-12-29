#pragma once
#include <unordered_map>
#include <map>
#include <cstdint>
#include <Windows.h>
#include <jni.h>
#include <queue>
#include <java.hpp>

struct hook_context
{
    uintptr_t flags;
    uintptr_t r15;
    uintptr_t r14;
    uintptr_t r13;
    uintptr_t r12;
    uintptr_t r11;
    uintptr_t r10;
    uintptr_t r9;
    uintptr_t r8;
    uintptr_t rbp;
    uintptr_t rdi;
    uintptr_t rsi;
    uintptr_t rdx;
    uintptr_t rcx;
    uintptr_t rbx;
    uintptr_t rax;
};

namespace hook
{

    struct hook_data
    {
        jmethodID target;
        PVOID callback;
        bool hooked;
    };
    
    extern std::unordered_map<PVOID, PVOID> original_functions;
    extern std::map<PVOID, std::uint8_t*> hook_map;
    extern std::queue<java::Method*> compile_queue;
    extern std::vector<hook_data> hook_list;
    constexpr std::size_t shell_size = 12;

    bool setup( );
    void update( );
    
    std::size_t get_minimum_shell_size( PVOID target );
    void construct_shell( std::uint8_t* shell, PVOID target );
    void* create_trampoline( PVOID target, std::size_t& size );
    void* create_naked_shell( PVOID callback, PVOID trampoline );
    bool hook( PVOID original, PVOID hook );
    bool hook_normal( PVOID original, PVOID hook );
    bool hook_method_code( jmethodID original, PVOID callback );
    bool add_hook( jmethodID original, PVOID callback );
    bool unhook( PVOID original );
    PVOID get_original( PVOID method );
}