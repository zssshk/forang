// select.go 是隧道适配器自动选型（v0.6.3 artex-ymh 移植，INTRANET-PIVOT-DESIGN.md
// 期 3.5 选型规则 + chains pivot-tunnel-choice 骨架的纯函数版）。
//
// 规则（probe 驱动，见 ymh tunnel/suo5.go 期 3.5 实测结论）：
//   - 目标能直接出网（TCP 出网探针通）→ chisel（反向 TCP 隧道，socks 与
//     portfwd 双形态都支持）；
//   - 目标不能出网、但有 webshell 通道 → suo5（经 webshell payload 建 socks5，
//     仅 socks 形态；portfwd 强制 chisel）；
//   - 两者皆无 → 不选型，返回错误（诚实失败，不编一个假隧道）。
//
// suo5 的部署本身（payload 投递）依赖立足点会话子系统，FORANG 暂无 session
// 层，故本包只做选型 + 计划生成，远端投递记为后续项。
package tunnel

import "fmt"

// AdapterSuo5 是经 webshell 的 HTTP 隧道适配器（仅 socks）。
const AdapterSuo5 = "suo5"

// ProbeResult 是隧道选型的输入：目标侧出网探测结果（由 session 探针或
// 人工判定填入；FORANG 暂无 session 子系统时由调用方按已知拓扑填）。
type ProbeResult struct {
	TCPOut      bool   // 目标能直接 TCP 出网（可回连平台）
	WebshellURL string // 立足点 webshell URL（空 = 无 webshell 通道）
}

// SelectAdapter 按 probe 结果选适配器。kind 为 socks|portfwd。
// 返回 adapter + 选型理由；选不出时返回错误。
func SelectAdapter(kind string, probe ProbeResult) (adapter, reason string, err error) {
	if kind != KindSocks && kind != KindPortfwd {
		return "", "", fmt.Errorf("非法隧道类型 %q（socks|portfwd）", kind)
	}
	// portfwd 强制 chisel：suo5 仅 socks（ymh 期 3.5 实测结论）。
	if kind == KindPortfwd {
		if !probe.TCPOut {
			return "", "", fmt.Errorf("portfwd 强制 chisel，但目标不能 TCP 出网（无回连通道）")
		}
		return AdapterChisel, "portfwd 强制 chisel（suo5 仅 socks）", nil
	}
	if probe.TCPOut {
		return AdapterChisel, "目标能 TCP 出网，走 chisel 反向隧道", nil
	}
	if probe.WebshellURL != "" {
		return AdapterSuo5, "目标不能出网，经 webshell 走 suo5", nil
	}
	return "", "", fmt.Errorf("目标既不能 TCP 出网又无 webshell 通道，无法建隧道")
}
