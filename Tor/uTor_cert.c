#include "uTor_cert.h"
#include "../Cryptography/uTor_crypto_pk.h"
#include "../Platform/uTor_memory.h"

BOOL tor_cert_extract(CONST BYTE* raw_cert_data, CONST INT32 cert_data_sz, BYTE* cert_out, CONST BYTE cert_type_expected) {
	if (cert_data_sz < (sizeof(TOR_CERTIFICATE))) //size of a cert with 1 extension atleast.
		return FALSE;

	TOR_CERTIFICATE* cert = (TOR_CERTIFICATE*)raw_cert_data;
	if ((cert->version != 1) || (cert->cert_key_type != 1) || (cert->cert_type != cert_type_expected))
		return FALSE;

	if (cert->cert_type == 9) {
		memory_copy(cert_out, cert->certif_key_data, 32);
		return TRUE;
	}

	UINT32 ofs = sizeof(TOR_CERTIFICATE);
	for (BYTE I = 0; I != cert->n_extensions; I++) {
		if ((ofs + sizeof(TOR_CERT_DATA)) > cert_data_sz)
			return FALSE;
		TOR_CERT_DATA* cert_data = raw_cert_data + ofs;
		ofs += sizeof(TOR_CERT_DATA);

		UINT16 cert_len = ntohs(cert_data->ext_len);
		if ((ofs + cert_len) > cert_data_sz)
			return FALSE;
		if (cert_data->ext_type == 4) {
			if (cert_len != CRYPTO_ECC25519_KEY_LEN)
				return FALSE;
			memory_copy(cert_out, raw_cert_data + ofs, cert_len);
			return TRUE;
		}
		ofs += cert_len;
	}

	return FALSE;
}