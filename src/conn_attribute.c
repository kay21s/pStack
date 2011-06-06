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

inline idx_type index_e(const elem_type *ptr)
{
	return ptr->index;
}

inline idx_type index_l(const elem_list_type *ptr)
{
	return ptr->elem.index;
}
