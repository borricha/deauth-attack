#pragma once
#include "headers.h"

#pragma pack(push, 1)
struct beacon_header{
    uint8_t ver:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;
    uint16_t duration_id;
    Mac dest_addr;
    Mac src_addr;
    Mac bssid;
    uint16_t squence_num;
    uint16_t fixed;
    //Mac bssid() {return bssid;}

    //fixed parameters
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_info;

    //tagged parameters
    uint8_t tag_num;
    uint8_t len;
    char ssid[100];
} ;
#pragma pack(pop)


// #pragma pack(push, 1)
// typedef struct fixed_parameters{
//     uint64_t timestamp;
//     uint16_t beacon_interval;
//     uint16_t capabilities_info;
// }fp;
// #pragma pack(pop)

// #pragma pack(push, 1)
// typedef struct tag_SSID_parameter{
//     uint8_t tag_num;
//     uint8_t len;
//     uint8_t ssid[32];
// };
// #pragma pack(pop)
