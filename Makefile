DIR_NAME=dns_cache_server
NET=lo

build:
	docker build --build-arg DIR_NAME="$(DIR_NAME)" -t $(DIR_NAME):latest .

run:
	docker run --net host --privileged --name $(DIR_NAME) -itd $(DIR_NAME):latest ./xdp -n $(NET)

# cmd run service
dns_cache_server:
	go run -exec sudo dns_cache_server/main.go dns_cache_server/bpf_bpfel.go -n $(NET)

ipv4_firewall_v1:
	go run -exec sudo ipv4_firewall_v1/main.go ipv4_firewall_v1/bpf_bpfel.go -n $(NET)

ipv4_firewall_v2:
	go run -exec sudo ipv4_firewall_v2/main.go ipv4_firewall_v2/bpf_bpfel.go -n $(NET)

packets_record:
	go run -exec sudo packets_record/main.go packets_record/bpf_bpfel.go -n $(NET)

parse_ipv4:
	go run -exec sudo parse_ipv4/main.go parse_ipv4/bpf_bpfel.go -n $(NET)

parse_udp_dns:
	go run -exec sudo parse_udp_dns/main.go parse_udp_dns/bpf_bpfel.go -n $(NET)

printk_pass:
	go run -exec sudo printk_pass/main.go printk_pass/bpf_bpfel.go -n $(NET)