package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the complete GASP configuration
type Config struct {
	Server       ServerConfig       `yaml:"server"`
	Mode         string             `yaml:"mode"` // hub or spoke
	Auth         AuthConfig         `yaml:"auth"`
	Security     SecurityConfig     `yaml:"security"`
	Logging      LoggingConfig      `yaml:"logging"`
	RateLimiting RateLimitingConfig `yaml:"rate_limiting"`
	Collection   CollectionConfig   `yaml:"collection,omitempty"`
	Output       OutputConfig       `yaml:"output,omitempty"`
}

type ServerConfig struct {
	ListenAddress string        `yaml:"listen_address"`
	ReadTimeout   time.Duration `yaml:"read_timeout,omitempty"`
	WriteTimeout  time.Duration `yaml:"write_timeout,omitempty"`
}

type AuthConfig struct {
	Enabled         bool             `yaml:"enabled"`
	LocalhostBypass bool             `yaml:"localhost_bypass"`
	Passwords       []PasswordConfig `yaml:"passwords"`
	JWT             JWTConfig        `yaml:"jwt"`
	// PwauthPath overrides the pwauth helper location (default /usr/bin/pwauth)
	PwauthPath string `yaml:"pwauth_path,omitempty"`
}

type PasswordConfig struct {
	Name           string         `yaml:"name"`
	PasswordHash   string         `yaml:"password_hash"`
	AllowedClients []string       `yaml:"allowed_clients"`
	AllowedSources []AllowedIP    `yaml:"allowed_sources"`
	TokenTTL       string         `yaml:"token_ttl"`
	TokenTTLParsed time.Duration  `yaml:"-"`
}

type AllowedIP struct {
	IP   string `yaml:"ip"`
	Name string `yaml:"name,omitempty"`
}

type JWTConfig struct {
	SecretFile string `yaml:"secret_file"`
}

type SecurityConfig struct {
	Alerts AlertsConfig `yaml:"alerts"`
}

type AlertsConfig struct {
	Enabled bool        `yaml:"enabled"`
	Email   EmailConfig `yaml:"email,omitempty"`
	SMTP    SMTPConfig  `yaml:"smtp,omitempty"`
}

type EmailConfig struct {
	To   string `yaml:"to"`
	From string `yaml:"from"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"` // json or text
	Output string `yaml:"output"` // stdout, file, or both
	File   string `yaml:"file,omitempty"`
}

type RateLimitingConfig struct {
	FailedLogin FailedLoginConfig `yaml:"failed_login"`
}

type FailedLoginConfig struct {
	MaxAttempts     int    `yaml:"max_attempts"`
	LockoutDuration string `yaml:"lockout_duration"`
	WindowDuration  string `yaml:"window_duration,omitempty"`
}

type CollectionConfig struct {
	Interval time.Duration  `yaml:"interval,omitempty"`
	Packages PackagesConfig `yaml:"packages,omitempty"`
}

// PackagesConfig controls package update reporting. Every field is optional;
// see PackagesConfig.Resolve for the defaults.
type PackagesConfig struct {
	Enabled             *bool                    `yaml:"enabled,omitempty"`
	RefreshInterval     time.Duration            `yaml:"refresh_interval,omitempty"`
	NetworkCheckAt      string                   `yaml:"network_check_at,omitempty"` // HH:MM, local time
	NetworkJitter       *time.Duration           `yaml:"network_jitter,omitempty"`
	AllowNetwork        *bool                    `yaml:"allow_network,omitempty"`
	StaleAfter          time.Duration            `yaml:"stale_after,omitempty"`
	OverdueAfter        map[string]time.Duration `yaml:"overdue_after,omitempty"` // keyed by manager, plus "default"
	ListSecurityUpdates *bool                    `yaml:"list_security_updates,omitempty"`
	MaxListed           int                      `yaml:"max_listed,omitempty"`
	Timeout             time.Duration            `yaml:"timeout,omitempty"`
	ScorePenalty        ScorePenaltyConfig       `yaml:"score_penalty,omitempty"`
}

// ScorePenaltyConfig sets how many health-score points each package flag
// costs. Unset fields use the defaults (10, 5, 5).
type ScorePenaltyConfig struct {
	Security *int `yaml:"security,omitempty"`
	Reboot   *int `yaml:"reboot,omitempty"`
	Overdue  *int `yaml:"overdue,omitempty"`
}

// PackageSettings is PackagesConfig with every default filled in.
type PackageSettings struct {
	Enabled             bool
	RefreshInterval     time.Duration
	NetworkCheckHour    int
	NetworkCheckMinute  int
	NetworkJitter       time.Duration
	AllowNetwork        bool
	StaleAfter          time.Duration
	OverdueAfter        map[string]time.Duration
	ListSecurityUpdates bool
	MaxListed           int
	Timeout             time.Duration
	PenaltySecurity     int
	PenaltyReboot       int
	PenaltyOverdue      int
}

// Defaults for package update reporting.
const (
	DefaultPackagesRefreshInterval = time.Hour
	DefaultPackagesNetworkCheckAt  = "03:30"
	DefaultPackagesNetworkJitter   = 30 * time.Minute
	DefaultPackagesStaleAfter      = 7 * 24 * time.Hour
	DefaultPackagesMaxListed       = 20
	DefaultPackagesTimeout         = 60 * time.Second
	DefaultOverdueAfterPacman      = 7 * 24 * time.Hour
	DefaultOverdueAfter            = 30 * 24 * time.Hour
	DefaultPenaltySecurity         = 10
	DefaultPenaltyReboot           = 5
	DefaultPenaltyOverdue          = 5
)

// parseClock parses "HH:MM" (24-hour)
func parseClock(s string) (int, int, error) {
	t, err := time.Parse("15:04", s)
	if err != nil {
		return 0, 0, fmt.Errorf("want HH:MM (24-hour), got %q", s)
	}
	return t.Hour(), t.Minute(), nil
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func intOr(p *int, def int) int {
	if p == nil {
		return def
	}
	return *p
}

// Resolve fills in defaults. It assumes Validate has passed; an unparseable
// network_check_at falls back to the default time.
func (p PackagesConfig) Resolve() PackageSettings {
	s := PackageSettings{
		Enabled:             boolOr(p.Enabled, true),
		RefreshInterval:     p.RefreshInterval,
		AllowNetwork:        boolOr(p.AllowNetwork, true),
		StaleAfter:          p.StaleAfter,
		ListSecurityUpdates: boolOr(p.ListSecurityUpdates, true),
		MaxListed:           p.MaxListed,
		Timeout:             p.Timeout,
		PenaltySecurity:     intOr(p.ScorePenalty.Security, DefaultPenaltySecurity),
		PenaltyReboot:       intOr(p.ScorePenalty.Reboot, DefaultPenaltyReboot),
		PenaltyOverdue:      intOr(p.ScorePenalty.Overdue, DefaultPenaltyOverdue),
		OverdueAfter: map[string]time.Duration{
			"pacman":  DefaultOverdueAfterPacman,
			"default": DefaultOverdueAfter,
		},
	}
	if s.RefreshInterval <= 0 {
		s.RefreshInterval = DefaultPackagesRefreshInterval
	}
	if s.StaleAfter <= 0 {
		s.StaleAfter = DefaultPackagesStaleAfter
	}
	if s.MaxListed <= 0 {
		s.MaxListed = DefaultPackagesMaxListed
	}
	if s.Timeout <= 0 {
		s.Timeout = DefaultPackagesTimeout
	}
	s.NetworkJitter = DefaultPackagesNetworkJitter
	if p.NetworkJitter != nil {
		s.NetworkJitter = *p.NetworkJitter
	}
	at := p.NetworkCheckAt
	if at == "" {
		at = DefaultPackagesNetworkCheckAt
	}
	h, m, err := parseClock(at)
	if err != nil {
		h, m, _ = parseClock(DefaultPackagesNetworkCheckAt)
	}
	s.NetworkCheckHour, s.NetworkCheckMinute = h, m
	for k, v := range p.OverdueAfter {
		if v > 0 {
			s.OverdueAfter[strings.ToLower(k)] = v
		}
	}
	return s
}

// OverdueFor returns the overdue threshold for a package manager.
func (s PackageSettings) OverdueFor(manager string) time.Duration {
	if d, ok := s.OverdueAfter[manager]; ok {
		return d
	}
	if d, ok := s.OverdueAfter["default"]; ok {
		return d
	}
	return DefaultOverdueAfter
}

func (p PackagesConfig) validate() error {
	if p.NetworkCheckAt != "" {
		if _, _, err := parseClock(p.NetworkCheckAt); err != nil {
			return fmt.Errorf("invalid collection.packages.network_check_at: %w", err)
		}
	}
	for name, d := range map[string]time.Duration{
		"refresh_interval": p.RefreshInterval,
		"stale_after":      p.StaleAfter,
		"timeout":          p.Timeout,
	} {
		if d < 0 {
			return fmt.Errorf("collection.packages.%s must not be negative", name)
		}
	}
	if p.NetworkJitter != nil && *p.NetworkJitter < 0 {
		return fmt.Errorf("collection.packages.network_jitter must not be negative")
	}
	for k, d := range p.OverdueAfter {
		if d <= 0 {
			return fmt.Errorf("collection.packages.overdue_after.%s must be positive", k)
		}
	}
	if p.MaxListed < 0 {
		return fmt.Errorf("collection.packages.max_listed must not be negative")
	}
	for name, v := range map[string]*int{
		"security": p.ScorePenalty.Security,
		"reboot":   p.ScorePenalty.Reboot,
		"overdue":  p.ScorePenalty.Overdue,
	} {
		if v != nil && (*v < 0 || *v > 100) {
			return fmt.Errorf("collection.packages.score_penalty.%s must be between 0 and 100", name)
		}
	}
	return nil
}

type OutputConfig struct {
	File string `yaml:"file,omitempty"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	expandedPath := ExpandPath(path)

	data, err := os.ReadFile(expandedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Parse duration strings
	for i := range cfg.Auth.Passwords {
		if cfg.Auth.Passwords[i].TokenTTL != "" {
			ttl, err := time.ParseDuration(cfg.Auth.Passwords[i].TokenTTL)
			if err != nil {
				return nil, fmt.Errorf("invalid token_ttl for password %s: %w", cfg.Auth.Passwords[i].Name, err)
			}
			cfg.Auth.Passwords[i].TokenTTLParsed = ttl
		} else {
			cfg.Auth.Passwords[i].TokenTTLParsed = 7 * 24 * time.Hour // Default 7 days
		}
	}

	// Expand paths in config
	if cfg.Auth.JWT.SecretFile != "" {
		cfg.Auth.JWT.SecretFile = ExpandPath(cfg.Auth.JWT.SecretFile)
	}
	if cfg.Auth.PwauthPath != "" {
		cfg.Auth.PwauthPath = ExpandPath(cfg.Auth.PwauthPath)
	}
	if cfg.Logging.File != "" {
		cfg.Logging.File = ExpandPath(cfg.Logging.File)
	}
	if cfg.Output.File != "" {
		cfg.Output.File = ExpandPath(cfg.Output.File)
	}

	return &cfg, nil
}

// ExpandPath expands ~ to home directory
func ExpandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// validSource reports whether s is an IP address or a CIDR network
func validSource(s string) bool {
	if strings.Contains(s, "/") {
		_, err := netip.ParsePrefix(s)
		return err == nil
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Server.ReadTimeout < 0 {
		return fmt.Errorf("server.read_timeout must not be negative")
	}
	if c.Server.WriteTimeout < 0 {
		return fmt.Errorf("server.write_timeout must not be negative")
	}

	if c.Auth.Enabled {
		if len(c.Auth.Passwords) == 0 {
			return fmt.Errorf("auth enabled but no passwords configured")
		}

		if c.Auth.JWT.SecretFile == "" {
			return fmt.Errorf("jwt.secret_file is required when auth is enabled")
		}

		for _, pw := range c.Auth.Passwords {
			for _, src := range pw.AllowedSources {
				if !validSource(src.IP) {
					return fmt.Errorf("invalid allowed_sources entry %q for password %s: want an IP address or CIDR network", src.IP, pw.Name)
				}
			}
		}
	}

	// Failed-login settings are optional (defaults: 5 attempts, 15m lockout,
	// 5m window), but values that are given must be usable
	fl := c.RateLimiting.FailedLogin
	if fl.MaxAttempts < 0 {
		return fmt.Errorf("rate_limiting.failed_login.max_attempts must not be negative")
	}
	for name, value := range map[string]string{
		"lockout_duration": fl.LockoutDuration,
		"window_duration":  fl.WindowDuration,
	} {
		if value == "" {
			continue
		}
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid rate_limiting.failed_login.%s %q: %w", name, value, err)
		}
		if d <= 0 {
			return fmt.Errorf("rate_limiting.failed_login.%s must be positive", name)
		}
	}

	if err := c.Collection.Packages.validate(); err != nil {
		return err
	}

	return nil
}
