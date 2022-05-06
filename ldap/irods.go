package ldap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	irodsclient_conn "github.com/cyverse/go-irodsclient/irods/connection"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/ldap-irods-auth/commons"
	gocache "github.com/patrickmn/go-cache"
)

const (
	applicationName    string        = "ldap-irods-auth"
	authRequestTimeout time.Duration = 30 * time.Second
	hashSeed           string        = "ldap-irods-auth-hash-seed1684165998778980816333407110267630157905106677102502820120929196213565346863704918937246704453519613"
)

// IRODSAuth is a module for iRODS auth
type IRODSAuth struct {
	config    *commons.Config
	authCache *gocache.Cache
}

// NewLDAP creates a new LDAP service
func NewIRODSAuth(config *commons.Config) (*IRODSAuth, error) {
	timeout := time.Duration(config.AuthCacheTimeout) * time.Second

	return &IRODSAuth{
		config:    config,
		authCache: gocache.New(timeout, timeout),
	}, nil
}

// Auth authenticate a user via password
func (auth *IRODSAuth) Auth(username string, password string) (bool, error) {
	usernamehash := makeHash(fmt.Sprintf("%s%s", hashSeed, username))
	authhash := makeHash(fmt.Sprintf("%s%s%s", hashSeed, username, password))

	entry, _ := auth.authCache.Get(usernamehash)
	if cachedAuthHash, ok := entry.(string); ok {
		// has auth cache
		if cachedAuthHash == authhash {
			return true, nil
		}
	}

	irodsAccount, err := irodsclient_types.CreateIRODSAccount(auth.config.IRODSHost, auth.config.IRODSPort, username, auth.config.IRODSZone, irodsclient_types.AuthSchemeNative, password, "")
	if err != nil {
		return false, err
	}

	irodsConn := irodsclient_conn.NewIRODSConnection(irodsAccount, authRequestTimeout, applicationName)
	err = irodsConn.Connect()
	if err != nil {
		// auth fail
		return false, err
	}

	defer irodsConn.Disconnect()

	auth.authCache.Add(usernamehash, authhash, 0)
	return true, nil
}

// makeHash returns hash string from plain text
func makeHash(s string) string {
	hash := sha256.New()
	hash.Write([]byte(s))
	hashBytes := hash.Sum(nil)
	return hex.EncodeToString(hashBytes)
}
