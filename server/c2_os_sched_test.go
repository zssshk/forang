package server

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// 生成的 crontab 语句必须能被 /bin/sh（dash）解析：emp3r0r 的 run_module exec
// 走的就是 sh -c，用 <(...) 之类的 bash 扩展会静默失败。
func TestC2ScheduleCmdLinuxIsPOSIXSh(t *testing.T) {
	if _, err := exec.LookPath("crontab"); err != nil {
		t.Skip("crontab 未安装，跳过语法校验")
	}
	for _, action := range []string{"add", "ls", "rm", "clear"} {
		cmd := c2ScheduleCmd(false, action, 60, "/root/x.sh", 1)
		if strings.TrimSpace(cmd) == "" {
			t.Fatalf("%s: 生成了空命令", action)
		}
		if strings.Contains(cmd, "<(") {
			t.Fatalf("%s: 含进程替换，dash 不支持：%s", action, cmd)
		}
		if out, err := exec.Command("/bin/sh", "-n", "-c", cmd).CombinedOutput(); err != nil {
			t.Fatalf("%s: sh 语法检查失败 %v\n%s\n%s", action, err, cmd, out)
		}
	}
}

// rm 的序号语义：删掉第 n 个 FORANG_SCH 条目，用户的无关条目必须原样保留。
func TestC2ScheduleRmKeepsUserEntries(t *testing.T) {
	user := []string{
		"9 2 * * * bash -c 'curl -sS -O https://x/k.sh'",
		"@reboot iptables-restore < /etc/iptables/rules.v4",
		"*/1 * * * * echo probe-a # FORANG_SCH",
		"0 3 * * * /root/backup.sh >> /root/backup.log 2>&1",
		"*/2 * * * * echo probe-b # FORANG_SCH",
	}
	in := strings.Join(user, "\n") + "\n"
	cases := []struct {
		n    int
		want []string
	}{
		{1, []string{user[0], user[1], user[3], user[4]}},
		{2, []string{user[0], user[1], user[2], user[3]}},
	}
	for _, tc := range cases {
		script := fmt.Sprintf("printf '%%s' %s | awk -v n=%d -v tag=FORANG_SCH "+
			"'index($0,tag){c++; if(c==n) next} {print}'", shellQuote(in), tc.n)
		got, err := exec.Command("/bin/sh", "-c", script).Output()
		if err != nil {
			t.Fatalf("rm %d 执行失败: %v", tc.n, err)
		}
		lines := strings.Split(strings.TrimRight(string(got), "\n"), "\n")
		if len(lines) != len(tc.want) {
			t.Fatalf("rm %d: 期望 %d 行，实得 %d：%q", tc.n, len(tc.want), len(lines), lines)
		}
		for i := range tc.want {
			if lines[i] != tc.want[i] {
				t.Fatalf("rm %d: 第 %d 行不符\n期望 %q\n实得 %q", tc.n, i+1, tc.want[i], lines[i])
			}
		}
	}
}
