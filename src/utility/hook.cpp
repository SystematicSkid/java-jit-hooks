#include <utility/hook.hpp>
#include <hde/hde64.hpp>
#include <memory>
#include <java.hpp>
#include <thread>

extern "C" {
	int jhook_shellcode_numelems();
	void jhook_shellcode_stub();
	uint8_t* jhook_shellcode_getcode();
    uint64_t jhook_end_shellcode_magic();
}

namespace hook
{
    /*
; Pointer[0] = Whether support for XSAVE is available
; Pointer[1] = Size required for saved FPU state using XSAVE or FXSAVE
; Pointer[2] = Address of callback function
; Pointer[3] = Address of next hook)*/
    const unsigned int bit_XSAVE = 0x04000000;
    const unsigned int bit_FXSAVE = 0x00000001;
    const unsigned int bit_OSXSAVE = 0x08000000;

    // Determines the required size of the FXSAVE/XSAVE area on the stack.
    uint64_t get_fxsave_xsave_size() {
        int cpu_info[4];
        __cpuidex(cpu_info, 0x0D, 0);
        return static_cast<uint64_t>(cpu_info[1]);
    }

    // Returns the level of XSAVE support:
    // 0 = Neither XSAVE nor FXSAVE supported (if this is the case then you may as well throw an exception because the CPU is ancient)
    // 1 = FXSAVE supported
    // 2 = XSAVE and OSXSAVE supported
    uint64_t get_xsave_support_level() {
        int cpu_info[4];
        __cpuid(cpu_info, 1);

        // Both CPU and OS support the xsave instruction.
        if ((cpu_info[2] & bit_XSAVE) && (cpu_info[2] & bit_OSXSAVE))
            return 2ULL;

        // The CPU supports the fxsave instruction.
        if (cpu_info[3] & bit_FXSAVE)
            return 1ULL;

        return 0ULL;
    }

    // Simple RAII wrapper for VirtualProtect.
    struct ScopedVirtualProtect {
        ScopedVirtualProtect(void* Addr, size_t Size, DWORD NewProtect) : Addr(Addr), Size(Size) { VirtualProtect(Addr, Size, NewProtect, &OldProtect); }
	    ~ScopedVirtualProtect() { VirtualProtect(Addr, Size, OldProtect, &OldProtect); }
        
        void* Addr;
        size_t Size;
        DWORD OldProtect;
    };

    // The first 'jhook_shellcode_numelems' pointer elements are at the very top of the 'jhook_shellcode_stub' function.
    // This will set those elements to the correct values.
    template<typename... TArgs>
    void jhook_shellcode_setargs(TArgs... Args) {
        ScopedVirtualProtect vp(jhook_shellcode_stub, 0x1, PAGE_EXECUTE_READWRITE);

        uint8_t* pbFunc = (uint8_t*)jhook_shellcode_stub;
        uintptr_t* pArgs[] = { (uintptr_t*)&Args... };
        for (int i = 0; i < jhook_shellcode_numelems(); ++i)
            *(uintptr_t*)(pbFunc + i * sizeof(uintptr_t)) = *pArgs[i];
    }
}

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

    void init_shell_args( PVOID callback, PVOID trampoline )
    {
        /* Get the size of the FXSAVE/XSAVE area */
        uint64_t fxsave_xsave_size = get_fxsave_xsave_size( );
        /* Get the XSAVE support level */
        uint64_t xsave_support_level = get_xsave_support_level( );
        /* Set the arguments for the shellcode */
        jhook_shellcode_setargs( xsave_support_level, fxsave_xsave_size, callback, trampoline );
    }

    void* create_naked_shell( PVOID callback, PVOID trampoline )
    {
        /* Get number of shellcode arguments and initialize them */
        int naked_shellcode_numargs = jhook_shellcode_numelems();
        init_shell_args( callback, trampoline );
        /* Get address of naked_shell in code */
        uint8_t* naked_shell_address = jhook_shellcode_getcode();
        uint8_t* naked_shell_codeptr = naked_shell_address;
        /* Get magic number marking the end of naked shell in code */
        uint64_t naked_shell_endmagic = jhook_end_shellcode_magic();
        /* Iterate over all bytes in the naked shell until reaching the end */
        std::vector<std::uint8_t> naked_shell_bytes;
        while (*(uint64_t*)naked_shell_codeptr != naked_shell_endmagic)
            naked_shell_bytes.push_back(*naked_shell_codeptr++);
        /* Insert the shellcode arguments at the start */
        naked_shell_bytes.insert(naked_shell_bytes.begin(), (uint8_t*)jhook_shellcode_stub, (uint8_t*)naked_shell_address);
        /* Allocate new memory for the shell */
        uint8_t* naked_shell_memory = reinterpret_cast<uint8_t*>(VirtualAlloc( nullptr, naked_shell_bytes.size( ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ));
        /* Copy the naked shell to the allocated memory */
        memcpy( naked_shell_memory, naked_shell_bytes.data( ), naked_shell_bytes.size( ) );
        /* Return the actual first instruction in the naked shell after the embedded arguments */
        return naked_shell_memory + (sizeof(uintptr_t) * naked_shellcode_numargs);
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

        /* Removed since the trampoline is already allocated with RWE permissions */
        // Update protection of trampoline memory to allow execution
        //DWORD protection;
        //VirtualProtect(trampoline, hookLength + shell_size, PAGE_EXECUTE_READWRITE, &protection);

        // Overwrite original function with jmp shellcode to the callback
        {
            ScopedVirtualProtect vp_orig(original, shell_size, PAGE_EXECUTE_READWRITE);
            memcpy(original, callbackShell, shell_size);
        }

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

        /* Commented out because I'm guessing Sebastian did this out of habit since the trampoline is allocated with RWE permissions anyway */
        // Update protection of trampoline memory to allow execution
        // DWORD protection;
        // VirtualProtect(trampoline, hookLength + shell_size, PAGE_EXECUTE_READWRITE, &protection);

        // Overwrite original function with jmp shellcode to the callback
        /* Switched to the RAII wrapper just to simplify things */
        {
            ScopedVirtualProtect vp_orig(original, shell_size, PAGE_EXECUTE_READWRITE);
            memcpy(original, callbackShell, shell_size);
        }

        return true;
    }

    bool hook_method_code( jmethodID original, PVOID callback )
    {
        /* Commented out because I'm guessing Sebastian made a mistake here? */
        // return true;

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