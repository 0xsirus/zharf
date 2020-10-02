/*
	By Sirus Shahini
	~cyn
	
	This is a slightly modified version of Murmurhash3 originally
	written by Austin Appleby.
*/



#include "head.h"

u32 hashmap( const void * , int , u32 );

static inline u32 rotl32 ( u32 x, int8_t r )
{
	return (x << r) | (x >> (32 - r));
}

static inline u64 rotl64 ( u64 x, int8_t r )
{
	return (x << r) | (x >> (64 - r));
}

#define	ROTL32(x,y)	rotl32(x,y)
#define ROTL64(x,y)	rotl64(x,y)

#define BIG_CONSTANT(x) (x##LLU)

static inline u32 getblock32 ( const u32 * p, int i )
{
	return p[i];
}

static inline u64 getblock64 ( const u64 * p, int i )
{
	return p[i];
}


static inline u32 fmix32 ( u32 h )
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}


static inline u64 fmix64 ( u64 k )
{
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xff51afd7ed558ccd);
	k ^= k >> 33;
	k *= BIG_CONSTANT(0xc4ceb9fe1a85ec53);
	k ^= k >> 33;

	return k;
}



#define HASH_SEED	0x5271405A

