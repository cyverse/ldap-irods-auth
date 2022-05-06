package ldap

import (
	"fmt"
	"sync"

	"github.com/cyverse/ldap-irods-auth/commons"
	log "github.com/sirupsen/logrus"
	"github.com/vjeantet/ldapserver"
)

// LDAPService is a service object
type LDAPService struct {
	config     *commons.Config
	ldapServer *ldapserver.Server
	irodsAuth  *IRODSAuth
	terminate  bool
	mutex      sync.Mutex
}

// NewLDAP creates a new LDAP service
func NewLDAP(config *commons.Config) (*LDAPService, error) {
	ldapserver.Logger = log.WithFields(log.Fields{
		"package": "ldap",
		"module":  "github.com/vjeantet/ldapserver",
	})

	server := ldapserver.NewServer()
	routes := ldapserver.NewRouteMux()

	irodsAuth, err := NewIRODSAuth(config)
	if err != nil {
		return nil, err
	}

	svc := &LDAPService{
		config:     config,
		ldapServer: server,
		irodsAuth:  irodsAuth,
	}

	routes.Bind(svc.handleBind)
	server.Handle(routes)

	return svc, nil
}

func (svc *LDAPService) Start() error {
	logger := log.WithFields(log.Fields{
		"package":  "ldap",
		"struct":   "LDAPService",
		"function": "Start",
	})

	logger.Info("Starting the LDAP-iRODS-Auth service")

	// start service
	hostport := fmt.Sprintf("%s:%d", svc.config.ServiceHost, svc.config.ServicePort)
	return svc.ldapServer.ListenAndServe(hostport)
}

// Destroy destroys the LDAP service
func (svc *LDAPService) Destroy() {
	logger := log.WithFields(log.Fields{
		"package":  "ldap",
		"struct":   "LDAPService",
		"function": "Destroy",
	})

	svc.mutex.Lock()
	defer svc.mutex.Unlock()

	if svc.terminate {
		// already terminated
		return
	}

	svc.terminate = true

	logger.Info("Destroying the LDAP-iRODS-Auth service")

	svc.ldapServer.Stop()
}

func (svc *LDAPService) handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()

	irodsUsername := string(r.Name())
	irodsPassword := string(r.AuthenticationSimple())

	authSuccess, _ := svc.irodsAuth.Auth(irodsUsername, irodsPassword)
	if authSuccess {
		w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
		return
	}

	log.Printf("Bind failed User=%s", string(r.Name()))
	failRes := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
	failRes.SetDiagnosticMessage("invalid credentials")
	w.Write(failRes)
}
