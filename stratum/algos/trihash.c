#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sha3/sph_blake.h>
#include <sha3/sph_bmw.h>
#include <sha3/sph_groestl.h>
#include <sha3/sph_jh.h>
#include <sha3/sph_keccak.h>
#include <sha3/sph_skein.h>
#include <sha3/sph_luffa.h>
#include <sha3/sph_cubehash.h>
#include <sha3/sph_shavite.h>
#include <sha3/sph_simd.h>
#include <sha3/sph_echo.h>
#include <sha3/sph_hamsi.h>
#include <sha3/sph_fugue.h>
#include <sha3/sph_shabal.h>
#include <sha3/sph_whirlpool.h>
#include <sha3/sph_sha2.h>
#include <sha3/sph_haval.h>
#include "common.h"
#include "uint256.h"

enum Algo {
	BLAKE = 0,
	BMW,
	GROESTL,
	JH,
	KECCAK,
	SKEIN,
	LUFFA,
	CUBEHASH,
	SHAVITE,
	SIMD,
	ECHO,
	HAMSI,
	FUGUE,
	SHABAL,
	WHIRLPOOL,
	SHA512,
	HAVAL,
	HASH_FUNC_COUNT
};

static bool isScrambleHash(const uint256& blockHash) {
	#define START_OF_LAST_35_NIBBLES_OF_HASH 29
	int last35Nibble = blockHash.GetNibble(START_OF_LAST_35_NIBBLES_OF_HASH);
	return (last35Nibble % 2 == 0);
}

static uint256 scrambleHash(const uint256& blockHash) {
	// Cliffnotes: use last 34 of PrevBlockHash to shuffle
	// a list of all algos and append that to PrevBlockHash and pass to hasher
	//////

	std::string hashString = blockHash.GetHex(); // uint256 to string
	std::string list = "0123456789abcdef";
	std::string order = list;
	std::string order2 = list;

	std::string hashFront = hashString.substr(0,30); // preserve first 30 chars
	std::string sixteen2 = hashString.substr(30,46); // extract last 19-34 chars
	std::string sixteen = hashString.substr(46,62); // extract last 3-18 chars
	std::string last2 = hashString.substr(62,64); // extract last 2 chars
	for(int i=0; i<16; i++){
	  int offset = list.find(sixteen[i]); // find offset of 16 char

	  order.insert(0, 1, order[offset]); // insert the nth character at the beginning
	  order.erase(offset+1, 1);  // erase the n+1 character (was nth)
	}

	for(int j=0; j<16; j++){
	  int offset = list.find(sixteen2[j]); // find offset of 16 char

	  order2.insert(0, 1, order2[offset]); // insert the nth character at the beginning
	  order2.erase(offset+1, 1);  // erase the n+1 character (was nth)
	}
	int offset = list.find(last2[0]); // find offset of 16 char
	order2.insert(0, 1, order2[offset]);
	offset = list.find(last2[1]); // find offset of 16 char
	order2.insert(0, 1, order2[offset]);
	uint256 scrambleHash = uint256(hashFront + order2 + order); // uint256 with length of hash and shuffled last seventeen
	return scrambleHash;
}

static uint8_t GetSelection(const uint256& blockHash, const int index) {
	//assert(index >= 0);
	///assert(index < 17);

	#define START_OF_LAST_17_NIBBLES_OF_HASH 47
	uint8_t hashSelection = blockHash.GetNibble(START_OF_LAST_17_NIBBLES_OF_HASH + index);
	#define START_OF_LAST_34_NIBBLES_OF_HASH 30
	uint8_t additionalSelection = blockHash.GetNibble(START_OF_LAST_34_NIBBLES_OF_HASH + index);
	hashSelection += (additionalSelection % 2);
	return(hashSelection);
}

static void getAlgoString(const uint32_t* prevblock, char *output)
{

	uint256 prevHash;
	prevHash.setUint32t(prevblock);
	bool toBeScamble = isScrambleHash(prevHash);
	uint256 hash;
	if(toBeScamble) {
		hash = scrambleHash(prevHash);
	} else {
		hash = prevHash;
	}
	char *sptr = output;
	for(int i = 0; i < 17; i ++) {
		uint8_t hashSelection =  GetSelection(hash, i);
		if (hashSelection >= 10) {
			//printf("%c", 'A' + (hashSelection - 10));
			sprintf(sptr, "%c", 'A' + (hashSelection - 10));
		}
		else {
			//printf("%d", hashSelection);
			sprintf(sptr, "%u", (uint32_t) hashSelection);
		}
		sptr++;
	}
	*sptr = '\0';
}

void trihash(const char* input, char* output, uint32_t len)
{

		uint32_t hash[17];
		char hashOrder[18] = { 0 };

		sph_blake512_context     ctx_blake;
		sph_bmw512_context       ctx_bmw;
		sph_groestl512_context   ctx_groestl;
		sph_skein512_context     ctx_skein;
		sph_jh512_context        ctx_jh;
		sph_keccak512_context    ctx_keccak;
		sph_luffa512_context     ctx_luffa;
		sph_cubehash512_context  ctx_cubehash;
		sph_shavite512_context   ctx_shavite;
		sph_simd512_context      ctx_simd;
		sph_echo512_context      ctx_echo;
		sph_hamsi512_context     ctx_hamsi;
		sph_fugue512_context     ctx_fugue;
		sph_shabal512_context    ctx_shabal;
		sph_whirlpool_context    ctx_whirlpool;
		sph_sha512_context       ctx_sha512;
		sph_haval256_5_context   ctx_haval;

		void *in = (void*) input;
		int size = len;

		getAlgoString(&input[4], hashOrder);

		for (int i = 0; i < 17; i++)
		{
			const char elem = hashOrder[i];
			const uint8_t algo = elem >= 'A' ? elem - 'A' + 10 : elem - '0';

			switch (algo) {
			case BLAKE:
				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, in, size);
				sph_blake512_close(&ctx_blake, hash);
				break;
			case BMW:
				sph_bmw512_init(&ctx_bmw);
				sph_bmw512(&ctx_bmw, in, size);
				sph_bmw512_close(&ctx_bmw, hash);
				break;
			case GROESTL:
				sph_groestl512_init(&ctx_groestl);
				sph_groestl512(&ctx_groestl, in, size);
				sph_groestl512_close(&ctx_groestl, hash);
				break;
			case SKEIN:
				sph_skein512_init(&ctx_skein);
				sph_skein512(&ctx_skein, in, size);
				sph_skein512_close(&ctx_skein, hash);
				break;
			case JH:
				sph_jh512_init(&ctx_jh);
				sph_jh512(&ctx_jh, in, size);
				sph_jh512_close(&ctx_jh, hash);
				break;
			case KECCAK:
				sph_keccak512_init(&ctx_keccak);
				sph_keccak512(&ctx_keccak, in, size);
				sph_keccak512_close(&ctx_keccak, hash);
				break;
			case LUFFA:
				sph_luffa512_init(&ctx_luffa);
				sph_luffa512(&ctx_luffa, in, size);
				sph_luffa512_close(&ctx_luffa, hash);
				break;
			case CUBEHASH:
				sph_cubehash512_init(&ctx_cubehash);
				sph_cubehash512(&ctx_cubehash, in, size);
				sph_cubehash512_close(&ctx_cubehash, hash);
				break;
			case SHAVITE:
				sph_shavite512_init(&ctx_shavite);
				sph_shavite512(&ctx_shavite, in, size);
				sph_shavite512_close(&ctx_shavite, hash);
				break;
			case SIMD:
				sph_simd512_init(&ctx_simd);
				sph_simd512(&ctx_simd, in, size);
				sph_simd512_close(&ctx_simd, hash);
				break;
			case ECHO:
				sph_echo512_init(&ctx_echo);
				sph_echo512(&ctx_echo, in, size);
				sph_echo512_close(&ctx_echo, hash);
				break;
			case HAMSI:
				sph_hamsi512_init(&ctx_hamsi);
				sph_hamsi512(&ctx_hamsi, in, size);
				sph_hamsi512_close(&ctx_hamsi, hash);
				break;
			case FUGUE:
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, in, size);
				sph_fugue512_close(&ctx_fugue, hash);
				break;
			case SHABAL:
				sph_shabal512_init(&ctx_shabal);
				sph_shabal512(&ctx_shabal, in, size);
				sph_shabal512_close(&ctx_shabal, hash);
				break;
			case WHIRLPOOL:
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, in, size);
				sph_whirlpool_close(&ctx_whirlpool, hash);
				break;
			case SHA512:
				sph_sha512_init(&ctx_sha512);
				sph_sha512(&ctx_sha512,(const void*) in, size);
				sph_sha512_close(&ctx_sha512,(void*) hash);
				break;
			case HAVAL:
				sph_haval256_5_init(&ctx_haval);
				sph_haval256_5(&ctx_haval,(const void*) in, size);
				sph_haval256_5_close(&ctx_haval, hash);
				break;
			}
			in = (void*) hash;
			size = 64;
		}
		memcpy(output, hash, 32);
}
