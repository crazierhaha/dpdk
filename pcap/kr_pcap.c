

#define KR_MBUF_SIZE (4096-1)
#define KR_MBUF_CACHE_SIZE 250
#define MAX_PKT_BURST 32

// 全局变量定义
static volatile bool g_bForce_quit;
static uint16_t g_nCap_port;
static const struct rte_eth_conf g_default_rte_eth_conf = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void print_stats(void) {
	struct rte_eth_stats stats;
	printf("\nStatistics for port %d\n", g_nCap_port);
	rte_eth_stats_get(g_nCap_port, &stats);
	printf("RX:%9"PRIu64" TX:%9"PRIu64" dropped:%9"PRIu64"\n",
		stats.ipackets, stats.opackets, stats.imissed);
}

static void signal_handler(int sig_num) {
	if (sig_num == SIGINT || sig_num == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", sig_num);
		g_bForce_quit = true;
	
		// 打印统计信息
		print_stats
	}
}

static void
signal_handler(int sig_num)
{
	if (sig_num == SIGINT) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				sig_num);
		quit_signal = 1;
	}
}

static void kr_init_port(uint16_t port, struct rte_mempool *mbuf_pool) {
	// 参数定义
	int ret;
	const uint16_t nb_rx_queues = 1;
	const uint16_t nb_tx_queues = 1;
	struct rte_eth_conf port_conf = g_default_rte_eth_conf;

	// 判断端口是否合法
	uint16_t nb_ports = rte_eth_dev_count();
	if (port < 0 || port >= nb_ports) {
		rte_exit(EXIT_FAILURE, "Error: invalid port input.\n");
	}

	

	
}


int main(int argc, char **argv) {
	// 0. 参数定义
	int ret;
	struct rte_mempool *kr_mbuf_pool;

	// 1. 注册中断信号处理函数
	g_bForce_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGETRM, signal_handler);

	// 2. 初始化eal
	ret = rte_eal_init(argc, argv);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE, "Error: EAL init failed.\n");
	}

	// 打印可用网口信息
	uint8_t nb_ports = rte_eth_dev_count();
	for (uint16_t i = 0; i < nb_ports; i++) {
		char dev_name[RTE_DEV_NAME_MAX_LEN];
		rte_eth_dev_get_name_by_port(i, dev_name);
		printf("Number %d: %s ", i, dev_name);

		struct rte_ether_addr mac_addr;
		rte_eth_macaddr_get(i, &mac_addr);

		char mac_fmt[RTE_ETHER_ADDR_FMT_SIZE] = {0};
		rte_ether_format_addr(mac_fmt, RTE_ETHER_ADDR_FMT_SIZE, (const struct rte_ether_addr *)&mac_addr);
		printf("mac: %s\n", mac_fmt);
	}

	printf("Choose a port, enter ther port number: \n");
	scanf("%d", &g_nCap_port);

	// 3. 申请内存池
	kr_mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", KR_MBUF_SIZE * nb_ports, KR_MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (kr_mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Error: mempool create failed.\n");
	}

	// 4. 初始化网卡
	

	return 0;
}
