#pragma once
#define WINDOWS_LEAN_AND_MEAN
#include <Windows.h>
/*      [00] TLS-over-TCP, IPv4 address
           A four-byte IPv4 address plus two-byte ORPort
      [01] TLS-over-TCP, IPv6 address
           A sixteen-byte IPv6 address plus two-byte ORPort
      [02] Legacy identity
           A 20-byte SHA1 identity fingerprint. At most one may be listed.
      [03] Ed25519 identity
           A 32-byte Ed25519 identity fingerprint. At most one may
           be listed.*/

#define TOR_EXT2_LINKSPEC_TLS_OVER_IPV4 0x00
#define TOR_EXT2_LINKSPEC_TLS_OVER_IPV6 0x01
#define TOR_EXT2_LINKSPEC_SHA1_IDENTITY 0x02
#define TOR_EXT2_LINKSPEC_ED25519_IDENTITY 0x03

//TODO: Is it potentially smart to define some types w different data lengths, etc? EG: sTor_link_spec_ed25519, etc..

#pragma pack(push)
#pragma pack(1)
typedef struct {
    BYTE ls_type;
    BYTE ls_len;
    //BYTE ls_data[ANYSIZE_ARRAY];
} TOR_LINKSPEC_HEADER;
#pragma pack(pop)