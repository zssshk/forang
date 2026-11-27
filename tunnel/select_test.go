package tunnel

import "testing"

func TestSelectAdapter(t *testing.T) {
	cases := []struct {
		name    string
		kind    string
		probe   ProbeResult
		want    string
		wantErr bool
	}{
		{"socks+出网=chisel", KindSocks, ProbeResult{TCPOut: true}, AdapterChisel, false},
		{"socks+无出网+有webshell=suo5", KindSocks, ProbeResult{WebshellURL: "http://10.0.0.5/shell.php"}, AdapterSuo5, false},
		{"socks+两无=失败", KindSocks, ProbeResult{}, "", true},
		{"portfwd+出网=chisel", KindPortfwd, ProbeResult{TCPOut: true}, AdapterChisel, false},
		{"portfwd+无出网+有webshell=仍失败", KindPortfwd, ProbeResult{WebshellURL: "http://10.0.0.5/shell.php"}, "", true},
		{"非法类型=失败", "http", ProbeResult{TCPOut: true}, "", true},
	}
	for _, c := range cases {
		got, reason, err := SelectAdapter(c.kind, c.probe)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v wantErr=%v", c.name, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("%s: adapter=%q want %q (reason=%q)", c.name, got, c.want, reason)
		}
	}
}
