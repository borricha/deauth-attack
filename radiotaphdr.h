#pragma once

#include "headers.h"

#pragma pack(push, 1)
struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
        u_int8_t datarate;
        u_int8_t unknown;
        u_int16_t txflag;
};
#pragma pack(pop)
