/*
	By Sirus Shahini
	~cyn

	This is a slightly modified version of Murmurhash3 originally
	written by Austin Appleby.
*/

#include "hash.h"

u32 hashmap( const void * key, int len, u32 seed)
{
	const uint8_t * data = (const uint8_t*)key;
	const int nblocks = len / 4;
	u32 h1 = seed;
	const u32 c1 = 0xcc9e2d51;
	const u32 c2 = 0x1b873593;
	const u32 * blocks = (const u32 *)(data + nblocks*4);
	const uint8_t * tail;
	u32 k1;

	for(int i = -nblocks; i; i++)
	{
		u32 k1 = getblock32(blocks,i);

		k1 *= c1;
		k1 = ROTL32(k1,15);
		k1 *= c2;

		h1 ^= k1;
		h1 = ROTL32(h1,13);
		h1 = h1*5+0xe6546b64;
	}

	tail = (const uint8_t*)(data + nblocks*4);

	k1 = 0;

	switch(len & 3)
	{
		case 3: k1 ^= tail[2] << 16;
		case 2: k1 ^= tail[1] << 8;
		case 1: k1 ^= tail[0];
			k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
	};

	h1 ^= len;

	h1 = fmix32(h1);

	return h1;
}
