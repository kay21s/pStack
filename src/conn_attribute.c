#include "conn_attribute.h"
#include  <nmmintrin.h>

inline sig_type calc_signature(const uint32_t sip, const uint32_t dip, const uint16_t sport, const uint16_t dport)
{
	uint32_t port = sport ^ dport;
	unsigned int res = 0;
#if defined(CRC_SIGN)
	unsigned int crc1 = 0, crc2 = 0;

	crc1 = _mm_crc32_u32(crc1, sip);
	crc1 = _mm_crc32_u32(crc1, dip);
	crc1 = _mm_crc32_u32(crc1, port);

	crc2 = _mm_crc32_u32(crc2, dip);
	crc2 = _mm_crc32_u32(crc2, sip);
	crc2 = _mm_crc32_u32(crc2, port);

	res = crc1 ^ crc2;
	// Since we set the signature of an empty slot to be zero,
	// if the calculated signature turned to be zero, there will be a false positive,
	// We make it a arbitrary number rather than zero.
	if (res == 0) res = 0xFFFFFFFF;

	return (sig_type)res;
#elif defined(CRC_SIGN1)
	res = _mm_crc32_u32(res, sip ^ dip);
	res = _mm_crc32_u32(res, port);

	if (res == 0) res = 0xFFFFFFFF;

	return (sig_type)res;

#elif defined(CRC_SIGN2)
	unsigned int crc1 = 0, crc2 = 0;

	crc1 = _mm_crc32_u32(crc1, sip);
	crc1 = _mm_crc32_u32(crc1, dip);
	crc1 = _mm_crc32_u32(crc1, sport);
	crc1 = _mm_crc32_u32(crc1, dport);

	crc2 = _mm_crc32_u32(crc2, dip);
	crc2 = _mm_crc32_u32(crc2, sip);
	crc2 = _mm_crc32_u32(crc2, dport);
	crc2 = _mm_crc32_u32(crc2, sport);

	res = (crc1 & 0xFFFF0000) | (crc2 >> 16);
	// Since we set the signature of an empty slot to be zero,
	// if the calculated signature turned to be zero, there will be a false positive,
	// We make it a arbitrary number rather than zero.
	if (res == 0) {
		res = sip ^ dip ^ port;
		if (res == 0) {
			res = 0xFFFFFFFF;
		}
	}

	return (sig_type)res;

#else
	res = sip ^ dip ^ port;
	if (res == 0) res = 0xFFFFFFFF;

	return (sig_type)res;
#endif
}

inline int sig_match_e(const sig_type sign, const elem_type *ptr)
{
#if defined(CRC_SIGN2)
	sig_type rev_sign;
	if(sign == ptr->signature) return 1;
	rev_sign = ((sign & 0xFFFF)<<16) | ((sign & 0xFFFF0000)>>16);
	if(rev_sign == ptr->signature) return 1;
	return 0;
#endif
	return (sign == ptr->signature)? 1 : 0;
}

inline int sig_match_l(const sig_type sign, const elem_list_type *ptr)
{
	return (sign == ptr->elem.signature)? 1 : 0;
}

inline void store_sig_l(const sig_type sign, elem_list_type *ptr)
{
	ptr->elem.signature = sign;
}

#if defined(INDEXFREE_TCP) || defined (MAJOR_INDEXFREE_TCP)
inline void store_index_l(const idx_type index, elem_list_type *ptr)
{
	ptr->index = index;
}

inline idx_type index_l(const elem_list_type *ptr)
{
	return ptr->index;
}

inline idx_type calc_index(const int hash_index, const int pos)
{
	return (idx_type)(hash_index * SET_ASSOCIATIVE + pos);
}

#elif defined(COMPACT_TABLE)
inline void store_index_l(const idx_type index, elem_list_type *ptr)
{
	ptr->index = index;
}

inline idx_type index_l(const elem_list_type *ptr)
{
	return ptr->index;
}

inline idx_type get_cached_index(const void *set_header, const int pos)
{
	uint8_t *ptr = (uint8_t *)set_header + INDEX_OFFSET + pos * INDEX_SIZE;

	return (ptr[0] << 16) + (ptr[1] << 8) + ptr[2];
}

inline void store_cached_index(const void *set_header, const int pos, const idx_type index)
{
	uint8_t *ptr = (uint8_t *)set_header + INDEX_OFFSET + pos * INDEX_SIZE;

	ptr[2] = index & 0x0FF;
	ptr[1] = (index >> 8) & 0x0FF;
	ptr[0] = (index >> 16) & 0x0FF;
	return;
}

// This can be altered to better algorithm, 
// three bits for indexing 8 way-associative
inline uint8_t get_major_location(sig_type sign)
{
	// the least significant 3 bits
	return sign & 0x07;
}

#else // NEW_TCP macro is enabled only.
inline void store_index_l(const idx_type index, elem_list_type *ptr)
{
	ptr->elem.index = index;
}

inline idx_type index_l(const elem_list_type *ptr)
{
	return ptr->elem.index;
}

inline idx_type index_e(const elem_type *ptr)
{
	return ptr->index;
}

inline idx_type get_cached_index(const void *set_header, const int pos)
{
	elem_type *ptr = (elem_type *)set_header + pos;

	return ptr->index;
}

inline void store_cached_index(const void *set_header, const int pos, const idx_type index)
{
	elem_type *ptr = (elem_type *)set_header + pos;
	ptr->index = index;
	return;
}
#endif
