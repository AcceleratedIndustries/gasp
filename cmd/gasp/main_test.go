package main

import "testing"

func TestResolveListenAddress(t *testing.T) {
	tests := []struct {
		name          string
		listenAddress string
		port          int
		portFlagSet   bool
		want          string
		wantErr       bool
	}{
		{"no listen_address uses port on all interfaces", "", 8080, false, ":8080", false},
		{"no listen_address with --port", "", 9000, true, ":9000", false},
		{"listen_address used as given", "127.0.0.1:9090", 8080, false, "127.0.0.1:9090", false},
		{"IPv6 listen_address", "[::1]:9090", 8080, false, "[::1]:9090", false},
		{"explicit --port replaces only the port", "127.0.0.1:9090", 7000, true, "127.0.0.1:7000", false},
		{"explicit --port with IPv6 host", "[::1]:9090", 7000, true, "[::1]:7000", false},
		{"all interfaces in listen_address", "0.0.0.0:9090", 8080, false, "0.0.0.0:9090", false},
		{"missing port", "127.0.0.1", 8080, false, "", true},
		{"bad port", "127.0.0.1:http", 8080, false, "", true},
		{"port out of range", "127.0.0.1:70000", 8080, false, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveListenAddress(tt.listenAddress, tt.port, tt.portFlagSet)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
