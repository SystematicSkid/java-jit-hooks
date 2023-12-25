#pragma once
#include <java.hpp>

namespace java
{
    class JavaString
    {
    private:
        char pad[ 0xC ];
    public:
        int32_t length;
        char value[1];

    public:
        std::string to_string( )
        {
            return std::string( value, length );
        }
    };
}