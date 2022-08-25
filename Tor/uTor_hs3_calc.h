#pragma once
#include "uTor_consensus.h"
#include "../Cryptography/uTor_crypto_sha3.h"

VOID tor_hs3_calc_directory_index(UINT64 time_period_len, UINT64 time_period_num, BYTE* currently_used_srv, BYTE* identity_key, BYTE* hsdir_index_out);
VOID tor_hs3_calc_comparison_index(UINT64 time_period_len, UINT64 time_period_num, UINT64 replica, const BYTE* blinded_pk, BYTE* hs_index_out);
VOID tor_hs3_calc_subcredential(const BYTE* blinded_key, const BYTE* hsvc_credential, BYTE* subcredential_out);

INT32 tor_hs3_calc_next_tp_start(TOR_CONSENSUS* active_consensus, INT32 time);
BOOL tor_hs3_calc_is_period_between_tp_and_srv(TOR_CONSENSUS* active_consensus);
