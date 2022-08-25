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

#define STOR_EXT2_LINKSPEC_TLS_OVER_IPV4 0x00
#define STOR_EXT2_LINKSPEC_TLS_OVER_IPV6 0x01
#define STOR_EXT2_LINKSPEC_SHA1_IDENTITY 0x02
#define STOR_EXT2_LINKSPEC_ED25519_IDENTITY 0x03

#pragma pack(push)
#pragma pack(1)
typedef struct {
	UINT16 ext_len;
	BYTE ext_type;
	BYTE ext_flags;
} TOR_CERT_DATA;

typedef struct {
	BYTE version;//VERSION[1 Byte]
	BYTE cert_type;//CERT_TYPE[1 Byte]
	UINT32 exp_date;//EXPIRATION_DATE[4 Bytes]
	BYTE cert_key_type;//CERT_KEY_TYPE[1 byte]
	BYTE certif_key_data[32];//CERTIFIED_KEY[32 Bytes]
	BYTE n_extensions;
	//tor_cert_data[n_extensions]
	//SIGNATURE[64 Bytes]
} TOR_CERTIFICATE;
#pragma pack(pop)

#define TOR_CERT_SIGNING_KEY_SIGNED_WITH_IDENTITY 0x04 //[04] - signing a signing key with an identity key (Section 2.5.2.2)
#define TOR_CERT_TLS_LINK_SIGNED_WITH_ED25519 0x05 //[05] - TLS link certificate signed with ed25519 signing key (Section 4.2)
#define TOR_CERT_ED25519_SIGNED_WITH_ED25519 0x06 //[06] - Ed25519 authentication key signed with ed25519 signing key (Section 4.2)
#define TOR_CERT_INTRO_AUTH_KEY_SIGNED_WITH_DESC_KEY 0x09 //used in hs3 for grabbing the auth key. (Section 2.5.2.2)
#define TOR_CERT_NTOR_ONION_KEY_CROSS_CERT_NTOR_IDENT 0x0A //ntor onion key cross-certifying ntor identity key (Section 2.5.2.2) */

//This function will extract out signing certs and etc, according to the tor spec, see the defines above, it is used mainly in the hs3_dirlist parse functions, but also in hs3 descriptor parsing.
BOOL tor_cert_extract(CONST BYTE* raw_cert_data, CONST INT32 cert_data_sz, BYTE* cert_out, CONST BYTE cert_type_expected); //This is according to the TOR cert spec.
