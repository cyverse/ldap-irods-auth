package ldap

import (
	"fmt"
	"sync"

	"github.com/cyverse/ldap-irods-auth/commons"
	ldap_message "github.com/lor00x/goldap/message"
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

	routes.NotFound(svc.handleNotFound)
	routes.Abandon(svc.handleAbandon)
	routes.Bind(svc.handleBind)
	routes.Search(svc.handleSearch).Label("Search - Generic")
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

func (svc *LDAPService) handleNotFound(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	switch m.ProtocolOpType() {
	case ldapserver.ApplicationBindRequest:
		res := ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess)
		res.SetDiagnosticMessage("Default binding behavior set to return Success")
		w.Write(res)
	default:
		res := ldapserver.NewResponse(ldapserver.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Operation not implemented by server")
		w.Write(res)
	}
}

func (svc *LDAPService) handleAbandon(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	var req = m.GetAbandonRequest()
	// retreive the request to abandon, and send a abort signal to it
	if requestToAbandon, ok := m.Client.GetMessageByID(int(req)); ok {
		requestToAbandon.Abandon()
		log.Printf("Abandon signal sent to request processor [messageID=%d]", int(req))
	}
}

func (svc *LDAPService) handleBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()
	if r.AuthenticationChoice() == "simple" {
		dn := string(r.Name())
		if dn == "" {
			// anonymous access
			log.Printf("Anonymous user bind")
			w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
			return
		}

		irodsPassword := string(r.AuthenticationSimple())

		authSuccess, _ := svc.irodsAuth.Auth(dn, irodsPassword)
		if authSuccess {
			log.Printf("Bind User=%s", dn)
			w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
			return
		}

		log.Printf("Bind failed User=%s", dn)
		failRes := ldapserver.NewBindResponse(ldapserver.LDAPResultInvalidCredentials)
		failRes.SetDiagnosticMessage("invalid credentials")
		w.Write(failRes)
		return
	}

	log.Printf("Unhandled bind authentication choice %s", r.AuthenticationChoice())
	failRes := ldapserver.NewBindResponse(ldapserver.LDAPResultUnwillingToPerform)
	failRes.SetDiagnosticMessage("authentication choice not supported")
	w.Write(failRes)
}

func (svc *LDAPService) handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()
	log.Printf("Request BaseDn=%s", r.BaseObject())
	log.Printf("Request Filter=%s", r.Filter())
	log.Printf("Request FilterString=%s", r.FilterString())
	log.Printf("Request Attributes=%s", r.Attributes())
	log.Printf("Request TimeLimit=%d", r.TimeLimit().Int())

	// Handle Stop Signal (server stop / client disconnected / Abandoned request....)
	select {
	case <-m.Done:
		log.Print("Leaving handleSearch...")
		return
	default:
	}

	// to quick search
	attributes := map[string]string{}
	for _, att := range r.Attributes() {
		attributes[string(att)] = string(att)
	}

	// included all id
	usersAdded := map[string]string{}

	dns := svc.irodsAuth.GetDNs()
	for _, dn := range dns {
		username := GetUsernameFromDN(dn)
		filter := r.FilterString()
		if CheckDNFilter(filter, dn) {
			log.Printf("Returning search result - %s", dn)

			e := ldapserver.NewSearchResultEntry(dn)
			if len(attributes) == 0 {
				// display all
				e.AddAttribute("mail", ldap_message.AttributeValue(username+"@cyverse.org"))
				e.AddAttribute("cn", ldap_message.AttributeValue(username))
			} else {
				if _, ok := attributes["uid"]; ok {
					e.AddAttribute("uid", ldap_message.AttributeValue(username))
				}

				if _, ok := attributes["cn"]; ok {
					e.AddAttribute("cn", ldap_message.AttributeValue(username))
				}
			}

			w.Write(e)

			usersAdded[username] = dn
		}
	}

	// include asked id
	askedUser := ExtractFilterValue(r.FilterString(), "uid")
	log.Printf("asked user := %s", askedUser)
	if _, ok := usersAdded[askedUser]; !ok {
		// not added
		// make a new dn
		log.Printf("Adding an asked user %s to search result", askedUser)
		dn := fmt.Sprintf("uid=%s,ou=People,%s", askedUser, r.BaseObject())

		e := ldapserver.NewSearchResultEntry(dn)
		if len(attributes) == 0 {
			// display all
			e.AddAttribute("mail", ldap_message.AttributeValue(askedUser+"@cyverse.org"))
			e.AddAttribute("cn", ldap_message.AttributeValue(askedUser))
		} else {
			if _, ok := attributes["uid"]; ok {
				e.AddAttribute("uid", ldap_message.AttributeValue(askedUser))
			}

			if _, ok := attributes["cn"]; ok {
				e.AddAttribute("cn", ldap_message.AttributeValue(askedUser))
			}
		}
		w.Write(e)

		usersAdded[askedUser] = dn
	}

	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)
}
