#ifndef DISK_LATENCY_H
#define DISK_LATENCY_H

//#include <linux/types.h>

#define DISK_HISTOGRAM_BUCKETS 20

// Disk I/O latency histogram bucket upper bounds (in microseconds)
// 20 geometric buckets from 10us to 10ms
static const double disk_histogram_boundaries[DISK_HISTOGRAM_BUCKETS] = {
    10,    // 10us
    14,    // 14us
    21,    // 21us
    30,    // 30us
    43,    // 43us
    62,    // 62us
    89,    // 89us
    127,   // 127us
    183,   // 183us
    264,   // 264us
    379,   // 379us
    546,   // 546us
    785,   // 785us
    1129,  // 1.13ms
    1624,  // 1.62ms
    2336,  // 2.34ms
    3360,  // 3.36ms
    4833,  // 4.83ms
    6952,  // 6.95ms
    10000  // 10ms
};


#endif // DISK_LATENCY_H
