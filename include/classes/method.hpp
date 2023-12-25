#pragma once
#include <java.hpp>

namespace java
{
    /* Specific for both C1 and this JVM build, easy to find */
    constexpr uintptr_t stack_alignment = 0x7000;

    class nmethod
    {
    private:
        void** vtable;
    public:
        uint8_t compile_mode;

        void* get_main_code( )
        {
            return *(void**)( ( uintptr_t )this + 0x20 );
        }

        void* get_internal_code_entry( )
        {
            void* code = get_main_code( );
            /* Ensure non-null */
            if( code == nullptr )
                return nullptr;

            /* Alternatively, we can just search for the end of the NOP sled */
            /* after the klass check stub */
            uint8_t* code_bytes = ( uint8_t* )code;
            uint32_t target = 0 - ( stack_alignment );
            for( uintptr_t i = 0; i < 0x1000; i++ )
            {
                /* Get DWORD at address */
                uint32_t dword = *( uint32_t* )( code_bytes + i );
                if( dword == target )
                {
                    /* Get address of 'mov esp, ebp' */
                    void* entry_point = ( void* )( (uintptr_t)code_bytes + i - 0x3 );
                    return entry_point;
                }
            }
            return nullptr;
        }
    };

    class Method
    {
    private:
        char pad[ 0x48 ];
    public:
        nmethod* code;

        /* Used for testing */
        void set_access_flags( int flags )
        {
            *( int* )( ( uintptr_t )this + 0x28 ) = flags;
        }

        void add_flag( int flag )
        {
            *( int* )( ( uintptr_t )this + 0x28 ) |= flag;
        }
    };
}