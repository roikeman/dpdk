/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_icmp.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static bool no_swap_ports = false;
static bool no_swap_ip = false;
static int use_fixed_src_ip = 0;
static uint32_t fixed_src_ip = 0;
static int use_fixed_dst_ip = 0;
static uint32_t fixed_dst_ip = 0;

static int  use_fixed_src_port = 0;
static uint16_t fixed_src_port = 0;

static int aws_health_check_enabled = 1;
#define AWS_HEALTH_PORT_DEFAULT 18191
static uint16_t aws_health_check_port = AWS_HEALTH_PORT_DEFAULT;
/* If set via NO_PRINTING=1 environment variable, suppress per-packet logs */
static int suppress_packet_logs = 0;

/* Packet logging macro (only for dynamic packet prints) */
#define PKT_LOG(fmt, ...) do { if (!suppress_packet_logs) printf(fmt, ##__VA_ARGS__); } while (0)


/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. 8< */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = rte_lcore_count(), tx_rings = rte_lcore_count();
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. 8< */
	retval = rte_eth_dev_start(port);
	/* >8 End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0 && retval != -ENOTSUP)
		return retval;
	if (retval == -ENOTSUP)
		printf("Warning: promiscuous mode not supported on port %u, skipping.\n", port);

	return 0;
}
/* >8 End of main functional part of port initialization. */

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */


static void swap_ether(struct rte_ether_hdr *eth) {
    struct rte_ether_addr tmp;
    rte_ether_addr_copy(&eth->src_addr, &tmp);
    rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
    rte_ether_addr_copy(&tmp, &eth->dst_addr);
}

 /* Basic forwarding application lcore. 8< */
static int lcore_main(void *arg)
{
    uint16_t port;
    unsigned lcore_id = rte_lcore_id();

    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    RTE_ETH_FOREACH_DEV(port)
        if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", lcore_id);

    printf("\nlets party!!!\n");
    /* Main work of application loop. 8< */
		for (;;) {
        RTE_ETH_FOREACH_DEV(port) {
            struct rte_mbuf *bufs[BURST_SIZE];
            uint16_t queue_id = lcore_id % rte_lcore_count();
            uint16_t nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE);
            if (unlikely(nb_rx == 0)) continue;

        (void)arg;
            for (uint16_t i = 0; i < nb_rx; i++) {
                struct rte_mbuf *m = bufs[i];
                struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

                // ARP
                if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                    struct rte_arp_hdr *arp =
                        rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *,
                                                sizeof(struct rte_ether_hdr));

                    if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
                        struct in_addr req_ip = {
                            .s_addr = arp->arp_data.arp_tip
                        };
                        PKT_LOG("[Core %u] ARP request for %s\n", lcore_id, inet_ntoa(req_ip));

                        /* 1) Swap Ethernet MACs */
                        struct rte_ether_addr tmp_mac;
                        rte_ether_addr_copy(&eth->src_addr, &tmp_mac);
                        rte_ether_addr_copy(&eth->dst_addr, &eth->src_addr);
                        rte_ether_addr_copy(&tmp_mac, &eth->dst_addr);

                        /* 2) Build ARP reply */
                        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);

                        /* Swap and set ARP MAC fields */
                        rte_ether_addr_copy(&arp->arp_data.arp_sha,
											&arp->arp_data.arp_tha);
                        struct rte_ether_addr my_mac;
                        rte_eth_macaddr_get(port, &my_mac);
                        rte_ether_addr_copy(&my_mac, &arp->arp_data.arp_sha);

                        /* Swap and set ARP IP fields */
                        uint32_t req_proto = arp->arp_data.arp_sip;
                        // arp->arp_data.arp_sip = rte_cpu_to_be_32((172<<24)|(16<<16)|(0<<8)|3);
                        arp->arp_data.arp_sip = arp->arp_data.arp_tip;
                        arp->arp_data.arp_tip = req_proto;

                        /* 3) Transmit the ARP reply and continue */
                        rte_eth_tx_burst(port, queue_id, &m, 1);
                        continue;
                    }
                }
                // ARP end	

                // Drop non-IPv4 packets
                if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                    PKT_LOG("[Core %u] Dropping packet: non-IPv4 ether_type 0x%04x\n", lcore_id, eth->ether_type);
                    rte_pktmbuf_free(m);
                    continue;
                }

                // Parse IPv4 header
                struct rte_ipv4_hdr *ip = (void *)(eth + 1);
                uint8_t ihl = ip->version_ihl & 0x0f;    // low 4 bits hold header length in 32‑bit words

                if (ip->next_proto_id == IPPROTO_ICMP) {
                    uint8_t ihl = ip->version_ihl & 0x0f;
                    struct rte_icmp_hdr *icmp = (void *)((char*)ip + ihl * sizeof(uint32_t));

                    if (icmp->icmp_type == RTE_ICMP_TYPE_ECHO_REQUEST) {
                        // For ICMP, we still need src_addr for this one print
                        struct in_addr src_addr = { .s_addr = ip->src_addr };
                        PKT_LOG("[Core %u] ICMP echo request from %s\n", lcore_id, inet_ntoa(src_addr));

                        // 1) Swap MACs
                        swap_ether(eth);

                        // 2) Swap IPs & recalc checksum
                        uint32_t tmp_ip = ip->src_addr;
                        ip->src_addr = ip->dst_addr;
                        ip->dst_addr = tmp_ip;
                        ip->hdr_checksum = 0;
                        ip->hdr_checksum = rte_ipv4_cksum(ip);

                        // 3) Build ICMP reply
                        icmp->icmp_type = RTE_ICMP_TYPE_ECHO_REPLY;
                        icmp->icmp_cksum = 0;

                        // Calculate checksum over ICMP header + payload
                        uint16_t icmp_len = rte_be_to_cpu_16(ip->total_length) - (ihl * 4);
                        icmp->icmp_cksum = rte_raw_cksum(icmp, icmp_len);

                        // 4) Transmit back
                        rte_eth_tx_burst(port, queue_id, &m, 1);
                        continue;
                    }
                }
                // Handle UDP and TCP
                if (ip->next_proto_id == IPPROTO_UDP) {
                    struct rte_udp_hdr *udp = (void *)((char*)ip + ihl * sizeof(uint32_t));
                    uint16_t src_port = rte_be_to_cpu_16(udp->src_port);
                    uint16_t dst_port = rte_be_to_cpu_16(udp->dst_port);
                    char src_ip_str[INET_ADDRSTRLEN];
                    char dst_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip->src_addr, src_ip_str, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &ip->dst_addr, dst_ip_str, INET_ADDRSTRLEN);
                    PKT_LOG("[Core %u] Rx IPv4 UDP %s:%u → %s:%u\n", lcore_id, src_ip_str, src_port, dst_ip_str, dst_port);

                    // Now do all the swapping/modifications
                    if (!no_swap_ip) {
                        swap_ether(eth);
                        uint32_t tmp_ip = ip->src_addr;
                        ip->src_addr = ip->dst_addr;
                        ip->dst_addr = tmp_ip;
                    }
                    if (use_fixed_src_ip) {
                        ip->src_addr = fixed_src_ip;
                    } 
                    if (use_fixed_dst_ip) {
                        ip->dst_addr = fixed_dst_ip;
                    } 
                    
                    // Swap UDP ports
                    if (!no_swap_ports) {
                        udp->src_port = rte_cpu_to_be_16(dst_port);
                        udp->dst_port = rte_cpu_to_be_16(src_port);
                    }
                    
                    if (use_fixed_src_port) {
                        udp->src_port = rte_cpu_to_be_16(fixed_src_port);
                    }

                    // Recompute checksums
                    udp->dgram_cksum = 0;
                    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
                    ip->hdr_checksum = 0;
                    ip->hdr_checksum = rte_ipv4_cksum(ip);

                    // Print TRANSMITTED packet AFTER all modifications
                    char new_src_str[INET_ADDRSTRLEN];
                    char new_dst_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip->src_addr, new_src_str, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &ip->dst_addr, new_dst_str, INET_ADDRSTRLEN);
                    PKT_LOG("[Core %u] Tx IPv4 UDP %s:%u → %s:%u\n", lcore_id, new_src_str, rte_be_to_cpu_16(udp->src_port), new_dst_str, rte_be_to_cpu_16(udp->dst_port));
                } else if (ip->next_proto_id == IPPROTO_TCP) {
                    struct rte_tcp_hdr *tcp = (void *)((char*)ip + ihl * sizeof(uint32_t));
                    uint16_t src_port = rte_be_to_cpu_16(tcp->src_port);
                    uint16_t dst_port = rte_be_to_cpu_16(tcp->dst_port);
                    char src_ip_str[INET_ADDRSTRLEN];
                    char dst_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip->src_addr, src_ip_str, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &ip->dst_addr, dst_ip_str, INET_ADDRSTRLEN);
                    PKT_LOG("[Core %u] Rx IPv4 TCP %s:%u → %s:%u\n", lcore_id, src_ip_str, src_port, dst_ip_str, dst_port);

                    // AWS Gateway health check: respond to SYN on configured port
                    if (aws_health_check_enabled && dst_port == aws_health_check_port && (tcp->tcp_flags & RTE_TCP_SYN_FLAG) && !(tcp->tcp_flags & RTE_TCP_ACK_FLAG)) {
                        PKT_LOG("[Core %u] TCP SYN received on port %u - handling AWS health check\n", lcore_id, dst_port);
                        swap_ether(eth);
                        uint32_t tmp_ip = ip->src_addr;
                        ip->src_addr = ip->dst_addr;
                        ip->dst_addr = tmp_ip;
                        tcp->src_port = rte_cpu_to_be_16(dst_port);
                        tcp->dst_port = rte_cpu_to_be_16(src_port);
                        
                        // Set sequence and ack numbers
                        uint32_t seq = rte_be_to_cpu_32(tcp->sent_seq);
                        tcp->sent_seq = rte_cpu_to_be_32(0x1000); // arbitrary initial seq
                        tcp->recv_ack = rte_cpu_to_be_32(seq + 1);
                        
                        // Set flags to SYN+ACK
                        tcp->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
                        
                        // Window size
                        tcp->rx_win = rte_cpu_to_be_16(65535);
                        
                        // Recompute checksums
                        tcp->cksum = 0;
                        tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
                        ip->hdr_checksum = 0;
                        ip->hdr_checksum = rte_ipv4_cksum(ip);
                        
                        PKT_LOG("[Core %u] Sent SYN-ACK for AWS health check to %s:%u\n", lcore_id, src_ip_str, src_port);
                        rte_eth_tx_burst(port, queue_id, &m, 1);
                        continue; // Skip normal packet processing
                    }

                    // Now do all the swapping/modifications
                    swap_ether(eth);
                    uint32_t tmp_ip = ip->src_addr;
                    ip->src_addr = ip->dst_addr;
                    ip->dst_addr = tmp_ip;
                    
                    // Swap TCP ports
                    tcp->src_port = rte_cpu_to_be_16(dst_port);
                    tcp->dst_port = rte_cpu_to_be_16(src_port);
                    
                    // Recompute checksums
                    tcp->cksum = 0;
                    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
                    ip->hdr_checksum = 0;
                    ip->hdr_checksum = rte_ipv4_cksum(ip);
                    
                    // Print TRANSMITTED packet AFTER all modifications
                    char new_src_str[INET_ADDRSTRLEN];
                    char new_dst_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ip->src_addr, new_src_str, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &ip->dst_addr, new_dst_str, INET_ADDRSTRLEN);
                    PKT_LOG("[Core %u] Tx IPv4 TCP %s:%u → %s:%u\n", lcore_id, new_src_str, rte_be_to_cpu_16(tcp->src_port), new_dst_str, rte_be_to_cpu_16(tcp->dst_port));
                } else {
                    PKT_LOG("[Core %u] Dropping non-TCP/UDP IPv4 packet (proto %u)\n", lcore_id, ip->next_proto_id);
                    rte_pktmbuf_free(m);
                    continue;
                }
            }

            // Transmit all modified packets back out the same port
            uint16_t nb_tx = rte_eth_tx_burst(port, queue_id, bufs, nb_rx);
            if (unlikely(nb_tx < nb_rx)) {
                for (uint16_t i = nb_tx; i < nb_rx; i++)
                    rte_pktmbuf_free(bufs[i]);
            }
        }
    }

    /* >8 End of loop. */
    return 0;
}
/* >8 End Basic forwarding application lcore. */

static void print_welcome_message(void)
{
    printf("\n");
    printf("=========================================\n");
    printf("     DPDK Network Packet Reflector      \n");
    printf("=========================================\n");
    printf("\n");
    printf("This application reflects network packets back to the sender.\n");
    printf("Supported protocols: ARP, ICMP, UDP, TCP\n");
    printf("\n");
    printf("Configuration via Environment Variables:\n");
    printf("----------------------------------------\n");
    printf("NO_SWAP_PORTS=1    - Disable port swapping (keep original ports)\n");
    printf("NO_SWAP_IPS=1      - Disable IPs swapping (keep original IPs)\n");
    printf("FIX_SRC_IP=x.x.x.x - Use fixed source IP address\n");
    printf("FIX_DST_IP=x.x.x.x - Use fixed destination IP address\n");
    printf("FIX_SRC_PORT=N     - Use fixed source port (1-65535)\n");
    printf("AWS_HEALTH_PORT=N  - Enable AWS Gateway health check on port N (default: %d, 0=disable)\n", AWS_HEALTH_PORT_DEFAULT);
    printf("NO_PRINTING=1      - Suppress per-packet logging output\n");
    printf("\n");
    printf("Core Parameters:\n");
    printf("----------------------------------------\n");
    printf("-l <corelist>      - Specify which CPU cores to use (e.g. -l 0-3 for cores 0,1,2,3)\n");
    printf("-n <numchannels>   - Number of memory channels (usually 1)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  NO_SWAP_PORTS=1 FIX_SRC_IP=192.168.1.100 ./your_app -l 0-3 -n 1\n");
    printf("  FIX_DST_IP=10.0.0.1 FIX_SRC_PORT=8080 ./your_app -l 2,4,6 -n 1\n");
    printf("  AWS_HEALTH_PORT=80 ./your_app -l 1-2 -n 1\n");
    printf("\n");
    printf("Packet Flow:\n");
    printf("  ARP Requests  -> ARP Replies\n");
    printf("  ICMP Pings    -> ICMP Pong\n");
    printf("  UDP/TCP       -> Reflected with swapped addresses/ports\n");
    printf("\n");
    printf("Press Ctrl+C to stop the application.\n");
    printf("=========================================\n");
    printf("\n");
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint16_t portid;
    

	print_welcome_message();

	/* Initializion the Environment Abstraction Layer (EAL). 8< */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* >8 End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is be at least one of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 1)
		rte_exit(EXIT_FAILURE, "Error: number of ports must be at least one\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. 8< */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* >8 End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. 8< */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* >8 End of initializing all ports. */
	
	printf("\nRunning on %u cores\n", rte_lcore_count());
	
	/* Read the environment variable at startup */
    char *env = getenv("NO_SWAP_PORTS");
    if (env && strcmp(env, "1") == 0){
		no_swap_ports = true;
		printf("\nNOTICE: No Ports swaping mode is active.\n");
	}
	env = getenv("NO_SWAP_IPS");
	if (env && strcmp(env, "1") == 0){
		no_swap_ip = true;
		printf("\nNOTICE: No IPs swaping mode is active.\n");
	}
	/* Check for static ip source configuration*/
	env = NULL;
	env = getenv("FIX_SRC_IP");
	if (env) {
		struct in_addr addr;
		if (inet_pton(AF_INET, env, &addr) == 1) {
			fixed_src_ip = addr.s_addr;
			use_fixed_src_ip = 1;
			printf("Using fixed source IP: %s\n", env);
		} else {
			fprintf(stderr, "Invalid FIX_SRC_IP address: %s\n", env);
			exit(1);
		}
	}

	env = getenv("FIX_DST_IP");
	if (env) {
		struct in_addr addr;
		if (inet_pton(AF_INET, env, &addr) == 1) {
			fixed_dst_ip = addr.s_addr;
			use_fixed_dst_ip = 1;
			printf("Using fixed destenation IP: %s\n", env);
		} else {
			fprintf(stderr, "Invalid FIX_DST_IP address: %s\n", env);
			exit(1);
		}
	}
	
	env = getenv("FIX_SRC_PORT");
    if (env) {
        long p = strtol(env, NULL, 10);
        if (p > 0 && p <= 65535) {
            fixed_src_port   = (uint16_t)p;
            use_fixed_src_port = 1;
            printf("Using fixed source port: %u\n", fixed_src_port);
        } else {
            fprintf(stderr,
                "Invalid FIX_SRC_PORT value: %s (must be 1–65535)\n", env);
            exit(1);
        }
    }

	env = getenv("AWS_HEALTH_PORT");
	if (env) {
		long p = strtol(env, NULL, 10);
		if (p < 0 || p > 65535) {
			fprintf(stderr,
				"Invalid AWS_HEALTH_PORT value: %s (must be 0–65535)\n", env);
			exit(1);
		}
		aws_health_check_port = (uint16_t)p;
		if (aws_health_check_port == 0) {
			aws_health_check_enabled = 0;
			printf("AWS Gateway health check is disabled.\n");
		} else {
			aws_health_check_enabled = 1;
			printf("AWS Gateway health check enabled on port: %u\n", aws_health_check_port);
		}
	}

    /* Check for packet printing suppression */
    env = getenv("NO_PRINTING");
    if (env && strcmp(env, "1") == 0) {
        suppress_packet_logs = 1;
        printf("NOTICE: Packet printing disabled (NO_PRINTING=1).\n");
    }

	if (aws_health_check_enabled) {
		printf("Packet Flow: TCP SYN (port %u) -> SYN-ACK (AWS Health Check)\n", aws_health_check_port);
	}

	/* Launch lcore_main on all available cores */
	rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
	
	/* Wait for all cores to finish (they won't in this infinite loop app) */
	unsigned lcore_id;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
