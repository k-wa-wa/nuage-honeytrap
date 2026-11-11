package countryname

import "testing"

func TestJapanese(t *testing.T) {
	tests := []struct {
		code   string
		want   string
		wantOK bool
	}{
		{"JP", "日本", true},
		{"us", "アメリカ合衆国", true},
		{" CN ", "中国", true},
		{"HK", "香港", true},
		{"MK", "北マケドニア", true},
		{"T1", "Tor", true},
		{"XX", "不明", true},
		{"ZZ", "", false},
		{"", "", false},
		{"<script>", "", false},
	}
	for _, tt := range tests {
		got, ok := Japanese(tt.code)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("Japanese(%q) = (%q, %v), want (%q, %v)", tt.code, got, ok, tt.want, tt.wantOK)
		}
	}
}

// 表のすべての国コードが大文字 2 文字で、名前が空でないことを確かめる。
func TestTableIsWellFormed(t *testing.T) {
	if len(japaneseNames) != 252 {
		t.Errorf("table has %d entries, want 252 (ISO 3166-1 249 + XK + T1 + XX)", len(japaneseNames))
	}
	for code, name := range japaneseNames {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || ((code[1] < 'A' || code[1] > 'Z') && (code[1] < '0' || code[1] > '9')) {
			t.Errorf("invalid code %q", code)
		}
		if name == "" {
			t.Errorf("empty name for %q", code)
		}
	}
}
