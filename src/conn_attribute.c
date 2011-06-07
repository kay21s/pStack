#include "conn_attribute.h"

inline sig_type calc_signature(const uint32_t sip, const uint32_t dip, const uint16_t sport, const uint16_t dport)
{
	uint32_t port = sport ^ dport;
	return sip ^ dip ^ port;
}

inline int sig_match_e(const sig_type sign, const elem_type *ptr)
{
	return (sign == ptr->signature)? 1 : 0;
}

inline int sig_match_l(const sig_type sign, const elem_list_type *ptr)
{
	return (sign == ptr->elem.signature)? 1 : 0;
}

#if defined(COMPACT_TABLE)
inline idx_type index_l(const elem_list_type *ptr)
{
	return ptr->index;
}

inline idx_type get_cached_index(const void *set_header, const int pos)
{
	char *ptr = (char *)set_header + INDEX_OFFSET + pos * INDEX_SIZE;

	return (ptr[0] << 16) + (ptr[1] << 8) + ptr[2];
}

inline void store_cached_index(const void *set_header, const int pos, const idx_type index)
{
	char *ptr = (char *)set_header + INDEX_OFFSET + pos * INDEX_SIZE;

	ptr[2] = index & 0x0FF;
	ptr[1] = (index >> 8) & 0x0FF;
	ptr[0] = (index >> 16) & 0x0FF;
	return;
}

// This can be altered to better algorithm, 
// two bits for indexing 8 way-associative
inline uint8_t get_major_location(sig_type sign)
{
	// the least significant 3 bits
	return sign & 0x07;
}

#else
inline idx_type index_l(const elem_list_type *ptr)
{
	return ptr->elem.index;
}

inline idx_type index_e(const elem_type *ptr)
{
	return ptr->index;
}
#endif
