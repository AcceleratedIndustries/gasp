package config

import (
	"fmt"
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
	Interval time.Duration `yaml:"interval,omitempty"`
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

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Auth.Enabled {
		if len(c.Auth.Passwords) == 0 {
			return fmt.Errorf("auth enabled but no passwords configured")
		}

		if c.Auth.JWT.SecretFile == "" {
			return fmt.Errorf("jwt.secret_file is required when auth is enabled")
		}
	}

	return nil
}
