/*****************************************************************
* A macro definition file for our own version of libpcap --Kay   *
*****************************************************************/

#ifndef my_def_h
#define my_def_h

#define PRE_MEM 1		// Pre-allocate a large buffer when reading from trace file
//#define OFFLOAD_PCAP 1	// Eliminate the copy from ring buffer to user space buffer,
				// let the application free the ring frame. used when getting
				// packets from NIC

#endif

