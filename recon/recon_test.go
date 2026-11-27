package recon

import "testing"

const sampleIPAddr = `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 10.0.1.5/24 brd 10.0.1.255 scope global eth0
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 192.168.99.7/24 brd 192.168.99.255 scope global eth1
`

const sampleIPRoute = `default via 10.0.1.1 dev eth0 proto dhcp metric 100
10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.5 metric 100
172.16.0.0/16 via 10.0.1.254 dev eth0
192.168.99.0/24 dev eth1 proto kernel scope link src 192.168.99.7 metric 200
`

const sampleArp = `? (10.0.1.1) at 00:11:22:33:44:55 [ether] on eth0
? (10.0.1.20) at aa:bb:cc:dd:ee:ff [ether] on eth0
? (10.0.1.99) at <incomplete> on eth0
`

const sampleHosts = `# comment
127.0.0.1 localhost
10.0.1.10 db.internal fileserver
`

const sampleSS = `tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*
tcp LISTEN 0 4096 0.0.0.0:3306 0.0.0.0:*
tcp ESTAB 0 0 10.0.1.5:43120 172.16.5.9:443
tcp ESTAB 0 0 10.0.1.5:51234 10.0.1.20:445
`

func TestParseNICsAuto(t *testing.T) {
	nics := ParseNICsAuto(sampleIPAddr)
	if len(nics) != 3 {
		t.Fatalf("网卡数 = %d, want 3", len(nics))
	}
	if nics[1].IP != "10.0.1.5" || nics[1].Prefix != 24 || nics[1].Iface != "eth0" {
		t.Fatalf("eth0 解析错误：%+v", nics[1])
	}
	if seg := SegmentOf("10.0.1.5", 24); seg != "10.0.1.0/24" {
		t.Fatalf("SegmentOf = %q", seg)
	}
}

func TestParseRoutesAuto(t *testing.T) {
	routes := ParseRoutesAuto(sampleIPRoute)
	if len(routes) != 4 {
		t.Fatalf("路由数 = %d, want 4", len(routes))
	}
	static := 0
	for _, r := range routes {
		if r.IsStatic {
			static++
			if r.Dest != "172.16.0.0/16" || r.Via != "10.0.1.254" {
				t.Fatalf("静态路由解析错误：%+v", r)
			}
		}
	}
	if static != 1 {
		t.Fatalf("静态路由数 = %d, want 1", static)
	}
}

func TestParseNeighbors(t *testing.T) {
	nb := ParseNeighbors(sampleArp)
	if len(nb) != 2 {
		t.Fatalf("邻居数 = %d, want 2（<incomplete> 应跳过）", len(nb))
	}
	if nb[0].IP != "10.0.1.1" || nb[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("邻居解析错误：%+v", nb[0])
	}
}

func TestParseHosts(t *testing.T) {
	hosts := ParseHosts(sampleHosts)
	if len(hosts) != 2 {
		t.Fatalf("hosts 条数 = %d, want 2", len(hosts))
	}
	if len(hosts[1].Names) != 2 || hosts[1].Names[0] != "db.internal" {
		t.Fatalf("hosts 解析错误：%+v", hosts[1])
	}
}

func TestParseConnTable(t *testing.T) {
	listening, peers := ParseConnTable(sampleSS)
	if len(listening) != 2 {
		t.Fatalf("监听端口 = %d, want 2", len(listening))
	}
	if listening[0].Port != 22 || listening[1].Port != 3306 {
		t.Fatalf("监听端口解析错误：%+v", listening)
	}
	if len(peers) != 2 {
		t.Fatalf("对端数 = %d, want 2", len(peers))
	}
}

func TestInfer(t *testing.T) {
	r := &ReconReport{
		NICs:         ParseNICsAuto(sampleIPAddr),
		Routes:       ParseRoutesAuto(sampleIPRoute),
		Neighbors:    ParseNeighbors(sampleArp),
		HostsEntries: ParseHosts(sampleHosts),
	}
	r.Listening, r.Peers = ParseConnTable(sampleSS)
	inf := Infer(r)
	kinds := map[string]bool{}
	for _, i := range inf {
		kinds[i.Kind] = true
	}
	for _, want := range []string{"multi_nic", "static_route", "proven_peer", "arp_neighbors"} {
		if !kinds[want] {
			t.Fatalf("推断缺 %s，实际 %v", want, inf)
		}
	}
}

func TestServiceOf(t *testing.T) {
	if got := ServiceOf(22); got != "SSH" {
		t.Fatalf("ServiceOf(22) = %q", got)
	}
	if got := ServiceOf(9999); got != "" {
		t.Fatalf("ServiceOf(9999) = %q, want 空", got)
	}
}
