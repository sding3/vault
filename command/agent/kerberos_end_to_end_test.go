package agent

import (
	"os"
	"testing"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	agentKerb "github.com/hashicorp/vault/command/agent/auth/kerberos"
	"github.com/hashicorp/vault/sdk/helper/logging"
)

/*
This test is meant to be run against the dev environment you gain when you
run "$ make dev-env" in the home directory of
https://github.com/hashicorp/vault-plugin-auth-kerberos.

Once you run "$ make dev-env" and copy over the env variables it outputs,
this test can be run via:
VAULT_ACC=1 go test -v ./command/agent/. -run=TestKerberosEndToEnd
*/
func TestKerberosEndToEnd(t *testing.T) {
	if !runAcceptanceTests {
		t.Skip("acc flag off")
	}

	// TODO check that all of these are actually used, strip if not
	vaultToken := os.Getenv("VAULT_TOKEN")
	vaultAddr := os.Getenv("VAULT_ADDR")
	domainDN := os.Getenv("DOMAIN_DN")
	domainJoinedContainer := os.Getenv("DOMAIN_JOINED_CONTAINER")
	domainVaultAccount := os.Getenv("DOMAIN_VAULT_ACCOUNT")
	domainVaultPass := os.Getenv("DOMAIN_VAULT_PASS")
	domainUserAccount := os.Getenv("DOMAIN_USER_ACCOUNT")
	dnsName := os.Getenv("DNS_NAME")
	realmName := os.Getenv("REALM_NAME")
	sambaContainer := os.Getenv("SAMBA_CONTAINER")
	vaultContainer := os.Getenv("VAULT_CONTAINER")

	// Check if any of the needed settings are empty.
	if empty(vaultToken) ||
		empty(vaultAddr) ||
		empty(domainDN) ||
		empty(domainJoinedContainer) ||
		empty(domainVaultAccount) ||
		empty(domainVaultPass) ||
		empty(domainUserAccount) ||
		empty(dnsName) ||
		empty(realmName) ||
		empty(sambaContainer) ||
		empty(vaultContainer) {
		t.Skip("skipping kerberos agent test because test environment not running")
	}

	// TODO document this
	pathToKerbProj := os.Getenv("KERB_PROJ_PATH")
	if pathToKerbProj == "" {
		pathToKerbProj = os.Getenv("GOPATH") + "/src/github.com/hashicorp/vault-plugin-auth-kerberos"
	}

	// A Vault instance that's reachable from the private network between our
	// 3 containers is included as part of the $ make dev-env command.
	client, err := api.NewClient(&api.Config{
		Address:    vaultAddr,
		HttpClient: cleanhttp.DefaultClient(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Enable the Kerberos plugin.
	if err := client.Sys().EnableAuthWithOptions("kerberos", &api.EnableAuthOptions{
		Type: "kerberos",
		Options: map[string]string{
			"passthrough-request-headers": "Authorization",
			"allowed-response-headers":    "www-authenticate",
		},
	}); err != nil {
		t.Fatal(err)
	}

	// Configure it to talk to LDAP.
	if _, err := client.Logical().Write("auth/kerberos/config/ldap", map[string]interface{}{
		"binddn":       domainVaultAccount + "@" + realmName,
		"bindpass":     domainVaultPass,
		"groupattr":    "sAMAccountName",
		"groupdn":      domainDN,
		"groupfilter":  `(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))`,
		"insecure_tls": true,
		"starttls":     true,
		"userdn":       "CN=Users," + domainDN,
		"userattr":     "sAMAccountName",
		"upndomain":    realmName,
		"url":          "ldaps://" + sambaContainer[0:12] + "." + dnsName,
	}); err != nil {
		t.Fatal(err)
	}

	// Configure it to talk to Kerberos.
	if _, err := client.Logical().Write("auth/kerberos/config", map[string]interface{}{
		"service_account": "vault_svc",
		// This b64 files appears in the kerb repo's home directory when you run $ make dev-env.
		"keytab": pathToKerbProj + "/vault_svc.keytab.base64",
	}); err != nil {
		t.Fatal(err)
	}

	// TODO Execute a login.
	logger := logging.NewVaultLogger(hclog.Trace)
	/*
	login-kerb \
		-username=$DOMAIN_USER_ACCOUNT \
		-service="HTTP/$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200" \
		-realm=$REALM_NAME \
		-keytab_path=$KRB5_CLIENT_KTNAME \
		-krb5conf_path=$KRB5_CONFIG \
		-vault_addr="http://$VAULT_CONTAINER_PREFIX.$DNS_NAME:8200"
	 */
	// TODO the agent actually needs to be in the domain joined container
	am, err := agentKerb.NewKerberosAuthMethod(&auth.AuthConfig{
		Logger:    logger.Named("auth.kerberos"),
		MountPath: "auth/kerberos",
		Config: map[string]interface{}{
			"username":                     "TODO",
			"service":                     "TODO",
			"realm":                     "TODO",
			"keytab_path":                     "TODO",
			"krb5conf_path":                     "TODO",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func empty(v string) bool {
	return v == ""
}
