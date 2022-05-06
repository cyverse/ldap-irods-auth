package commons

import (
	"fmt"

	"github.com/kelseyhightower/envconfig"
	yaml "gopkg.in/yaml.v2"
)

const (
	ServiceHostDefault      string = ""
	ServicePortDefault      int    = 1389
	IRODSPortDefault        int    = 1247
	AuthCacheTimeoutDefault int    = 60 * 5 // 5min
	LDAPBaseDNDefault       string = "dc=iplantcollaborative,dc=org"
	LogFilePathDefault      string = "/tmp/ldap-irods-auth.log"
)

// Config holds the parameters list which can be configured
type Config struct {
	ServiceHost string `envconfig:"LDAP_IRODS_AUTH_SERVICE_HOST" yaml:"service_host"`
	ServicePort int    `envconfig:"LDAP_IRODS_AUTH_SERVICE_PORT" yaml:"service_port"`

	IRODSHost string `envconfig:"LDAP_IRODS_AUTH_IRODS_HOST" yaml:"irods_host"`
	IRODSPort int    `envconfig:"LDAP_IRODS_AUTH_IRODS_PORT" yaml:"irods_port"`
	IRODSZone string `envconfig:"LDAP_IRODS_AUTH_IRODS_ZONE" yaml:"irods_zone"`

	AuthCacheTimeout int `envconfig:"LDAP_IRODS_AUTH_CACHE_TIMEOUT" yaml:"auth_cache_timeout"`

	LDAPBaseDN string `envconfig:"LDAP_IRODS_AUTH_LDAP_BASE_DN" yaml:"ldap_base_dn"`

	LogPath string `envconfig:"LDAP_IRODS_AUTH_LOG_PATH" yaml:"log_path,omitempty"`

	Foreground   bool `yaml:"foreground,omitempty"`
	ChildProcess bool `yaml:"childprocess,omitempty"`
}

// NewDefaultConfig creates DefaultConfig
func NewDefaultConfig() *Config {
	return &Config{
		ServiceHost:      ServiceHostDefault,
		ServicePort:      ServicePortDefault,
		IRODSPort:        IRODSPortDefault,
		AuthCacheTimeout: AuthCacheTimeoutDefault,
		LDAPBaseDN:       LDAPBaseDNDefault,
		LogPath:          LogFilePathDefault,

		Foreground:   false,
		ChildProcess: false,
	}
}

// NewConfigFromENV creates Config from Environmental Variables
func NewConfigFromENV() (*Config, error) {
	config := Config{
		ServiceHost:      ServiceHostDefault,
		ServicePort:      ServicePortDefault,
		IRODSPort:        IRODSPortDefault,
		AuthCacheTimeout: AuthCacheTimeoutDefault,
		LDAPBaseDN:       LDAPBaseDNDefault,
		LogPath:          LogFilePathDefault,

		Foreground:   false,
		ChildProcess: false,
	}

	err := envconfig.Process("", &config)
	if err != nil {
		return nil, fmt.Errorf("Env Read Error - %v", err)
	}

	return &config, nil
}

// NewConfigFromYAML creates Config from YAML
func NewConfigFromYAML(yamlBytes []byte) (*Config, error) {
	config := Config{
		ServiceHost:      ServiceHostDefault,
		ServicePort:      ServicePortDefault,
		IRODSPort:        IRODSPortDefault,
		AuthCacheTimeout: AuthCacheTimeoutDefault,
		LDAPBaseDN:       LDAPBaseDNDefault,
		LogPath:          LogFilePathDefault,

		Foreground:   false,
		ChildProcess: false,
	}

	err := yaml.Unmarshal(yamlBytes, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML - %v", err)
	}

	return &config, nil
}

// Validate validates configuration
func (config *Config) Validate() error {
	if config.ServicePort <= 0 {
		return fmt.Errorf("Service port must be given")
	}

	if len(config.IRODSHost) == 0 {
		return fmt.Errorf("IRODS hostname must be given")
	}

	if config.IRODSPort <= 0 {
		return fmt.Errorf("IRODS port must be given")
	}

	if len(config.IRODSZone) == 0 {
		return fmt.Errorf("IRODS zone must be given")
	}

	return nil
}
