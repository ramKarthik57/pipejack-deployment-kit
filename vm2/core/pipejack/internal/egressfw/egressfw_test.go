package egressfw

import "testing"

func TestParseSpecValid(t *testing.T) {
	cases := []struct{ in, wantIP, wantPt string }{
		{"*:443", "*", "443"},
		{"127.0.0.1:*", "127.0.0.1", "*"},
		{"10.0.0.0/8:80", "10.0.0.0/8", "80"},
		{"172.17.0.1:5000", "172.17.0.1", "5000"},
	}
	for _, c := range cases {
		ip, pt, err := parseSpec(c.in)
		if err != nil {
			t.Errorf("parseSpec(%q): %v", c.in, err)
			continue
		}
		if ip != c.wantIP || pt != c.wantPt {
			t.Errorf("parseSpec(%q)=(%s,%s) want (%s,%s)", c.in, ip, pt, c.wantIP, c.wantPt)
		}
	}
}

func TestParseSpecInvalid(t *testing.T) {
	bad := []string{"", "no-colon", "999.999.999.999:80", "*:notaport", "*:99999"}
	for _, s := range bad {
		if _, _, err := parseSpec(s); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}
