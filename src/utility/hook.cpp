#include <utility/hook.hpp>
#include <hde/hde64.hpp>
#include <memory>
#include <java.hpp>
#include <thread>

extern "C" void naked_shell( );

namespace hook
{
    std::unordered_map< PVOID, PVOID > original_functions;
    std::map< PVOID, std::uint8_t* > hook_map;
    std::queue< java::Method* > compile_queue;
    std::vector< hook_data > hook_list;

    void* __fastcall hook_compiled( java::Method** method_handle, int osr_bci,
                                       int comp_level,
                                       java::Method** hot_method, int hot_count,
                                       int compile_reason, void* thread )
{
    void* original = get_original( hook_compiled );
    /* Check if queue has items */
    while( !compile_queue.empty( ) )
    {   
        /* Get the method */
        java::Method* method = compile_queue.front( );
        /* Check if it needs to be compiled */
        if( method->code )
        {
            /* Already compiled */
            compile_queue.pop( );
            continue;
        }

        /* Compile our target method */
        reinterpret_cast<void*( __fastcall* )( java::Method**, int, int, java::Method**, int, int, void* )>( original )( &method, -1, 1, hot_method, 0, 6, thread );
        /* Pop the queue */
        compile_queue.pop( );
    }

    return reinterpret_cast<void*( __fastcall* )( java::Method**, int, int, java::Method**, int, int, void* )>( original )( method_handle, osr_bci, comp_level, hot_method, hot_count, compile_reason, thread );
}

    bool setup( )
    {
        /* Create new thread for updater */
        std::thread( update ).detach( );
        /* Hook the compiler method */
        /* E8 ? ? ? ? 48 83 7D ? ? 48 8B 07 */
        uintptr_t address = (uintptr_t)GetModuleHandleA( "jvm.dll" ) + 0x226B40;
        return hook::hook_normal( (PVOID)address, &hook_compiled );
    }

    void update( )
    {
        while( true )
        {
            /* Iterate over all hooks */
            for( auto& hook : hook_list )
            {
                /* Check if the hook has been applied */
                if( hook.hooked )
                    continue;
                /* Check if the method has been compiled */
                java::Method* method = *( java::Method** )hook.target;
                if( method->code == nullptr )
                    continue;
                /* Hook the method */
                hook_method_code( hook.target, hook.callback );
                /* Mark the hook as applied */
                hook.hooked = true;
            }
            /* Sleep for 1 second */
            std::this_thread::sleep_for( std::chrono::seconds( 1 ) );
        }
    }

    std::size_t get_minimum_shell_size( PVOID target )
    {
        std::size_t size = 0;
        hde64s hs;
        do
        {
            hde64_disasm((void *)((uintptr_t)target + size), &hs);
            size += hs.len;
        } while (size < shell_size);
        return size;
    }

    void construct_shell( std::uint8_t* shell, PVOID target )
    {
        /* Construct a shell */
        shell[ 0 ] = 0x48;
        shell[ 1 ] = 0xB8;
        memcpy( shell + 2, &target, sizeof( DWORD64 ) );
        shell[ 10 ] = 0xFF;
        shell[ 11 ] = 0xE0;
    }

    void* create_trampoline( PVOID target, std::size_t& size )
    {
        std::size_t len = 0;
        std::vector<std::uint8_t> trampoline;
        /* Iterate over all instructions */
        while ( len < size )
        {
            hde64s hs;
            hde64_disasm( ( void* )( ( uintptr_t )target + len ), &hs );
            /* Check if this is a jmp */
            if ( hs.opcode == 0xE9 )
            {
                /* We need to make a shell for this opcode because it's currently RIP relative */
                /* We need to make it absolute */
                int32_t offset = *( int32_t* )( ( uintptr_t )target + len + 1 );
                PVOID jmp_target = ( PVOID )( ( uintptr_t )target + len + hs.len + offset );
                /* Construct a shell */
                std::uint8_t shell[ shell_size ];
                construct_shell( shell, jmp_target );
                /* Copy shell to trampoline */
                for ( std::size_t i = 0; i < shell_size; i++ )
                {
                    trampoline.push_back( shell[ i ] );
                }
                len += hs.len;
                continue;
            }

            /* Copy instruction to trampoline */
            for ( std::size_t i = 0; i < hs.len; i++ )
            {
                trampoline.push_back( *( std::uint8_t* )( ( uintptr_t )target + len + i ) );
            }
            len += hs.len;
        }
        /* Allocate memory for the trampoline */
        PVOID trampoline_address = VirtualAlloc( nullptr, trampoline.size( ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        /* Copy trampoline to allocated memory */
        memcpy( trampoline_address, trampoline.data( ), trampoline.size( ) );
        /* Update size */
        size = trampoline.size( );

        return trampoline_address;
    }

    void* create_naked_shell( PVOID callback, PVOID trampoline )
    {
        /* Get address of naked_shell in code */
        PVOID naked_shell_address = naked_shell;
        std::vector<std::uint8_t> naked_shell_bytes;
        uint32_t call_offset = 0x1E + 2;
        /* Iterate over all instructions until we reach a `jmp` */
        std::size_t len = 0;
        while ( true )
        {
            hde64s hs;
            hde64_disasm( ( void* )( ( uintptr_t )naked_shell_address + len ), &hs );
            /* Copy instruction to naked shell */
            for ( std::size_t i = 0; i < hs.len; i++ )
            {
                naked_shell_bytes.push_back( *( std::uint8_t* )( ( uintptr_t )naked_shell_address + len + i ) );
            }
            len += hs.len;

            /* If it's a `jmp rax`, quit */
            if ( hs.opcode == 0xFF && hs.modrm == 0xE0 )
                break;
        }

        /* Allocate new memory for the shell */
        PVOID naked_shell_memory = VirtualAlloc( nullptr, naked_shell_bytes.size( ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        /* Copy the naked shell to the allocated memory */
        memcpy( naked_shell_memory, naked_shell_bytes.data( ), naked_shell_bytes.size( ) );
        /* Write address of callback to call_offset */
        *( uintptr_t* )( ( uintptr_t )naked_shell_memory + call_offset ) = ( uintptr_t )callback;
        /* Write address of trampoline to jmp rax */
        *( uintptr_t* )( ( uintptr_t )naked_shell_memory + 0x4C + 2 ) = ( uintptr_t )trampoline;
        return naked_shell_memory;
    }

    bool hook( PVOID original, PVOID hook )
    {
        /* TODO: ADD PROPER ERROR HANDLING FOR PROD. */
        std::size_t length = get_minimum_shell_size(original);
        if(length < shell_size)
        {
            printf("Failed to hook function: %p", original);
            return false;
        }
        // Copy original bytes
        auto original_bytes = std::make_unique<std::uint8_t[]>(length);
        memcpy(original_bytes.get(), reinterpret_cast<PVOID>(original), length);
        hook_map[original] = original_bytes.get();

        // Create jmp shellcode back to the original function after the hook
        std::uint8_t trampolineShell[shell_size];
        DWORD64 trampolineAddress = (uintptr_t)original + length;
        construct_shell(trampolineShell, (PVOID)trampolineAddress);

        

        // Allocate memory for the trampoline and copy the original bytes
        size_t hookLength = static_cast<size_t>(length);
        std::uint8_t* trampoline = reinterpret_cast<std::uint8_t*>(create_trampoline(original, hookLength));

        /* Create naked shell */
        PVOID naked_shell = create_naked_shell(hook, trampoline);

        // Create jmp shellcode to the callback function
        std::uint8_t callbackShell[shell_size];
        construct_shell(callbackShell, naked_shell);

        // Insert jmp shellcode into trampoline
        memcpy(trampoline + hookLength, trampolineShell, shell_size);
        original_functions[hook] = trampoline;
        // Update protection of trampoline memory to allow execution
        DWORD protection;
        VirtualProtect(trampoline, hookLength + shell_size, PAGE_EXECUTE_READWRITE, &protection);

        // Overwrite original function with jmp shellcode to the callback
        DWORD originalProtection;
        PVOID targetAddress = reinterpret_cast<PVOID>(original);
        VirtualProtect(targetAddress, shell_size, PAGE_EXECUTE_READWRITE, &originalProtection);
        memcpy(targetAddress, callbackShell, shell_size);
        VirtualProtect(targetAddress, shell_size, originalProtection, &originalProtection);

        return true;
    }

    bool hook_normal( PVOID original, PVOID hook )
    {
        std::size_t length = get_minimum_shell_size(original);
        if(length < shell_size)
        {
            printf("Failed to hook function: %p", original);
            return false;
        }
        // Copy original bytes
        auto original_bytes = std::make_unique<std::uint8_t[]>(length);
        memcpy(original_bytes.get(), reinterpret_cast<PVOID>(original), length);
        hook_map[original] = original_bytes.get();

        // Create jmp shellcode to the callback function
        std::uint8_t callbackShell[shell_size];
        construct_shell(callbackShell, hook);

        // Allocate memory for the trampoline and copy the original bytes
        size_t hookLength = static_cast<size_t>(length);
        std::uint8_t* trampoline = reinterpret_cast<std::uint8_t*>(create_trampoline(original, hookLength));

        // Create jmp shellcode back to the original function after the hook
        std::uint8_t trampolineShell[shell_size];
        DWORD64 trampolineAddress = (uintptr_t)original + hookLength;
        construct_shell(trampolineShell, (PVOID)trampolineAddress);

        // Insert jmp shellcode into trampoline
        memcpy(trampoline + hookLength, trampolineShell, shell_size);
        original_functions[hook] = trampoline;
        // Update protection of trampoline memory to allow execution
        DWORD protection;
        VirtualProtect(trampoline, hookLength + shell_size, PAGE_EXECUTE_READWRITE, &protection);

        // Overwrite original function with jmp shellcode to the callback
        DWORD originalProtection;
        PVOID targetAddress = reinterpret_cast<PVOID>(original);
        VirtualProtect(targetAddress, shell_size, PAGE_EXECUTE_READWRITE, &originalProtection);
        memcpy(targetAddress, callbackShell, shell_size);
        VirtualProtect(targetAddress, shell_size, originalProtection, &originalProtection);

        return true;
    }

    bool hook_method_code( jmethodID original, PVOID callback )
    {
        return true;
        /* Get method pointer */
        java::Method* method = *( java::Method** )original;
        if(!method)
            return false;
        /* Get compiled code */
        java::nmethod* code = method->code;
        if(!code)
            return false;
        /* Get main code */
        PVOID entry_point = code->get_internal_code_entry( );
        if(!entry_point)
            return false;
        /* Hook the entry point */
        return hook( entry_point, callback );
    }

    bool add_hook( jmethodID original, PVOID callback )
    {
        /* Get method pointer */
        java::Method* method = *( java::Method** )original;
        if(!method)
            return false;
        /* Get compiled code */
        java::nmethod* code = method->code;
        if(code)
        {
            /* This method has already been compiled */
            /* We can hook it right away */
            return hook_method_code( original, callback );
        }
        /* Add the hook to the queue */
        compile_queue.push( method );
        /* Add the hook to the list */
        hook_data data;
        data.target = original;
        data.callback = callback;
        data.hooked = false;
        hook_list.push_back( data );
        return true;
    }

    bool unhook( PVOID original )
    {
        /* Get the original bytes */
        auto original_bytes = hook_map[ original ];
        /* Write the original bytes to the original pointer */
        memcpy( original, original_bytes, shell_size );
        /* Free the original bytes */
        delete[ ] original_bytes;
        /* Remove the hook from the map */
        hook_map.erase( original );
        /* Remove the original function from the map */
        original_functions.erase( original );
        return true;
    }

    PVOID get_original( PVOID method )
    {
        /* Return the original function */
        return original_functions[ method ];
    }
}