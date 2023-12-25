#include <iostream>
#include <Windows.h>
#include <jni.h>

#include <java.hpp>
#include <utility/hook.hpp>

HMODULE my_module;

JavaVM* get_main_vm( )
{
    jint vm_count = 0;
    JavaVM* jvm = nullptr;
    jint error = JNI_GetCreatedJavaVMs( &jvm, 1, &vm_count );

    if( error != JNI_OK || vm_count == 0 )
        return nullptr;

    return jvm;
}

jclass find_class( JNIEnv* env, const char* class_name )
{
    if( env == nullptr )
        return nullptr;

    jclass class_id = env->FindClass( class_name );
    if( class_id == nullptr )
    {
        printf( "Failed to find class: %s\n", class_name );
        return nullptr;
    }

    return class_id;
}

jmethodID find_method( JNIEnv* env, jclass klass, const char* method_name, const char* method_sig )
{
    if( env == nullptr || klass == nullptr )
        return nullptr;

    jmethodID method_id = env->GetMethodID( klass, method_name, method_sig );
    if( method_id == nullptr )
    {
        printf( "Failed to find method: %s %s\n", method_name, method_sig );
        return nullptr;
    }

    return method_id;
}

jmethodID find_static_method( JNIEnv* env, jclass klass, const char* method_name, const char* method_sig )
{
    if( env == nullptr || klass == nullptr )
        return nullptr;

    jmethodID method_id = env->GetStaticMethodID( klass, method_name, method_sig );
    if( method_id == nullptr )
    {
        printf( "Failed to find static method: %s %s\n", method_name, method_sig );
        return nullptr;
    }

    return method_id;

}

jfieldID find_field( JNIEnv* env, jclass klass, const char* field_name, const char* field_sig )
{
    if( env == nullptr || klass == nullptr )
        return nullptr;

    jfieldID field_id = env->GetFieldID( klass, field_name, field_sig );
    if( field_id == nullptr )
    {
        printf( "Failed to find field: %s %s\n", field_name, field_sig );
        return nullptr;
    }

    return field_id;
}

void* get_instance_klass( jclass klass )
{
    /* Ensure non-null */
    if( klass == nullptr )
        return nullptr;

    /* Dereference klass and get ptr at +0x10 */
    void* klass_ptr = *(void**)( klass );
    if ( klass_ptr == nullptr )
        return nullptr;
        
    klass_ptr = *(void**)( ( uintptr_t )klass_ptr + 0x10 );
    return klass_ptr;
}

void __fastcall test_hook( hook_context* ctx )
{
    printf("Minecraft::startAttack()\n");
    printf("\tInstance: %p\n", ctx->rdx);
    return;
}

void __fastcall hook_pause_game( hook_context* ctx )
{
    printf("Minecraft::pauseGame()\n");
    printf("\tInstance: %p\n", ctx->rdx);
    return;
}

void main_thread( )
{
    /* Create console */
    AllocConsole( );
    freopen( "CONOUT$", "w", stdout );

    /* Get main JavaVM */
    JavaVM* jvm = get_main_vm( );

    /* Attach thread to VM */
    JNIEnv* env = nullptr;
    jvm->AttachCurrentThread( ( void** )&env, nullptr );

    /* Find the minecraft class (1.20.4) */
    jclass minecraft_class = find_class( env, "evi" );
    printf( "minecraft_class: 0x%p\n", minecraft_class );
    /* Find 'nextDouble()' method */
    jmethodID start_attack = find_method( env, minecraft_class, "bo", "()Z" );
    jmethodID pause_game = find_method( env, minecraft_class, "c", "(Z)V" );

    if( !hook::setup( ) )
    {
        printf( "Failed to setup hooking\n" );
        jvm->DetachCurrentThread( );
        FreeLibraryAndExitThread( my_module, 0 );
        return;
    }
    hook::add_hook( start_attack, test_hook );
    hook::add_hook( pause_game, hook_pause_game );
    
    /* Wait for INSERT */
    while( !GetAsyncKeyState( VK_INSERT ) )
        Sleep( 100 );
    
    printf("Unhooking...\n");
    /* Detach thread */
    jvm->DetachCurrentThread( );

    /* Unload library */
    FreeLibraryAndExitThread( my_module, 0 );
}

BOOL APIENTRY DllMain( HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved ) 
{
    if( ul_reason_for_call != DLL_PROCESS_ATTACH )
        return TRUE;
    
    my_module = hModule;

    /* Create thread */
    CreateThread( NULL, 0, ( LPTHREAD_START_ROUTINE )main_thread, NULL, 0, NULL );

    return TRUE;
}