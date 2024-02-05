#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdint.h>
#include <rte_ethdev.h>

// 全局变量定义
extern volatile int g_exit_flag;

// 收发 mempool 中的 mbuf 数量
#define TXRX_MBUF_SIZE (4096-1)
#define TXRX_RING_SIZE	1024
#define TXRX_BURST_SIZE 512

// DEBUG
void print_mac(struct rte_ether_addr *mac);

// 简单做法，不考虑各线程的 socket，统一管理 ring。
struct inout_ring {
	struct rte_ring *in;
	struct rte_ring *out;
};

// 单例模式 - 创建ring
struct inout_ring *ringInstance(void);

#endif // __COMMON_H__
