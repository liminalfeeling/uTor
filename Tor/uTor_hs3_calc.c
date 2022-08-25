#include "uTor_hs3_calc.h"
#include "../Cryptography/uTor_crypto_sha3.h"
#include "../Platform/uTor_time.h"

//TAKEN FROM TOR SOURCE CODE.
#define TOR_HS3_SHARED_RANDOM_N_ROUNDS 12 /* Each protocol phase has 12 rounds  */
#define TOR_HS3_SHARED_RANDOM_N_PHASES 2 /* Number of phase we have in a protocol. */

#define HS_INDEX_PREFIX "store-at-idx"
#define HS_INDEX_PREFIX_LEN (sizeof(HS_INDEX_PREFIX) - 1)

//Calculates the directory index for a known hsdir.
VOID tor_hs3_calc_directory_index(UINT64 time_period_len, UINT64 time_period_num, BYTE* currently_used_srv, BYTE* identity_key, BYTE* hsdir_index_out) {
	time_period_num = htonll(time_period_num);
	time_period_len = htonll(time_period_len);

	CRYPTO_SHA3_CTXT sha3_ctxt;
	crypto_sha3_init(&sha3_ctxt, CRYPTO_SHA3_256_HASH_LEN);
	crypto_sha3_update(&sha3_ctxt, "node-idx", 8);
	crypto_sha3_update(&sha3_ctxt, identity_key, CRYPTO_ECC25519_KEY_LEN);
	crypto_sha3_update(&sha3_ctxt, currently_used_srv, 32);
	crypto_sha3_update(&sha3_ctxt, &time_period_num, sizeof(UINT64));
	crypto_sha3_update(&sha3_ctxt, &time_period_len, sizeof(UINT64));
	crypto_sha3_final(hsdir_index_out, &sha3_ctxt);
}

//Calculates the comparison index, which is then compared to all the directory indexes.
VOID tor_hs3_calc_comparison_index(UINT64 time_period_len, UINT64 time_period_num, UINT64 replica, const BYTE* blinded_pk, BYTE* hs_index_out) {
	time_period_len = htonll(time_period_len);
	time_period_num = htonll(time_period_num);
	replica = htonll(replica);

	CRYPTO_SHA3_CTXT sha3_ctxt;
	crypto_sha3_init(&sha3_ctxt, CRYPTO_SHA3_256_HASH_LEN);
	crypto_sha3_update(&sha3_ctxt, HS_INDEX_PREFIX, HS_INDEX_PREFIX_LEN);
	crypto_sha3_update(&sha3_ctxt, blinded_pk, CRYPTO_ECC25519_KEY_LEN);
	crypto_sha3_update(&sha3_ctxt, &replica, sizeof(UINT64));
	crypto_sha3_update(&sha3_ctxt, &time_period_len, sizeof(UINT64));
	crypto_sha3_update(&sha3_ctxt, &time_period_num, sizeof(UINT64));
	crypto_sha3_final(hs_index_out, &sha3_ctxt);
}

VOID tor_hs3_calc_subcredential(const BYTE* blinded_key, const BYTE* hsvc_credential, BYTE* subcredential_out) {
	CRYPTO_SHA3_CTXT sha3_ctxt;
	crypto_sha3_init(&sha3_ctxt, CRYPTO_SHA3_256_HASH_LEN);
	crypto_sha3_update(&sha3_ctxt, "subcredential", (sizeof("subcredential") - 1));
	crypto_sha3_update(&sha3_ctxt, hsvc_credential, CRYPTO_ECC25519_KEY_LEN);
	crypto_sha3_update(&sha3_ctxt, blinded_key, CRYPTO_ECC25519_KEY_LEN);
	crypto_sha3_final(subcredential_out, &sha3_ctxt);
}

INT32 tor_hs3_calc_next_tp_start(TOR_CONSENSUS* active_consensus, INT32 time) {
	UINT32 voting_interval_s = active_consensus->fresh_until_posix - active_consensus->valid_after_posix;
	UINT16 next_time_period_num = tor_time_calculate_period(time, active_consensus->time_period_len) + 1;
	INT32 start_of_next_tp_in_mins = ((INT32)next_time_period_num * (INT32)active_consensus->time_period_len);
	return ((start_of_next_tp_in_mins) * 60ULL) + (TOR_HS3_SHARED_RANDOM_N_ROUNDS * (UINT64)voting_interval_s);
}

BOOL tor_hs3_calc_is_period_between_tp_and_srv(TOR_CONSENSUS* active_consensus) {
	INT32 voting_interval_s = active_consensus->fresh_until_posix - active_consensus->valid_after_posix;
	INT32 round_start = active_consensus->valid_after_posix;
	INT32 curr_round_slot = (round_start / voting_interval_s) % (TOR_HS3_SHARED_RANDOM_N_ROUNDS * TOR_HS3_SHARED_RANDOM_N_PHASES);
	INT32 time_elapsed_since_start_of_run = curr_round_slot * voting_interval_s;
	INT32 srv_start_time = round_start - time_elapsed_since_start_of_run;
	INT32 start_of_next_tp = tor_hs3_calc_next_tp_start(active_consensus, srv_start_time);
	return !((active_consensus->valid_after_posix >= srv_start_time) && (active_consensus->valid_after_posix < start_of_next_tp));
}
