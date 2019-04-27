package authorizer

import (
	"github.com/golang/glog"
	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/extensions/trusts"
	tokens3 "github.com/gophercloud/gophercloud/openstack/identity/v3/tokens"
	"gopkg.in/gcfg.v1"
	"io"
	openstack_provider "k8s.io/kubernetes/pkg/cloudprovider/providers/openstack"
	"log"
	"os"
	"sync"
)

type Authorizer struct {
	authClient *gophercloud.ServiceClient
}

var authorizer *Authorizer
var once sync.Once

func New() (*Authorizer, error) {
	var err error
	once.Do(func() {
		authorizer, err = Init("/etc/kittenhouse/auth.cfg")
	})
	if err != nil {
		return nil, err
	}
	return authorizer, nil
}

func v3auth(client *gophercloud.ProviderClient, endpoint string, opts tokens3.AuthOptionsBuilder, eo gophercloud.EndpointOpts) error {
	// Override the generated service endpoint with the one returned by the version endpoint.
	v3Client, err := openstack.NewIdentityV3(client, eo)
	if err != nil {
		return err
	}

	if endpoint != "" {
		v3Client.Endpoint = endpoint
	}

	result := tokens3.Create(v3Client, opts)

	token, err := result.ExtractToken()
	if err != nil {
		return err
	}

	catalog, err := result.ExtractServiceCatalog()
	if err != nil {
		return err
	}

	client.TokenID = token.ID

	if opts.CanReauth() {
		// here we're creating a throw-away client (tac). it's a copy of the user's provider client, but
		// with the token and reauth func zeroed out. combined with setting `AllowReauth` to `false`,
		// this should retry authentication only once
		tac := *client
		tac.ReauthFunc = nil
		tac.TokenID = ""
		var tao tokens3.AuthOptionsBuilder
		switch ot := opts.(type) {
		case *gophercloud.AuthOptions:
			o := *ot
			o.AllowReauth = false
			tao = &o
		case *tokens3.AuthOptions:
			o := *ot
			o.AllowReauth = false
			tao = &o
		default:
			tao = opts
		}
		client.ReauthFunc = func() error {
			err := v3auth(&tac, endpoint, tao, eo)
			if err != nil {
				return err
			}
			client.TokenID = tac.TokenID
			return nil
		}
	}
	client.EndpointLocator = func(opts gophercloud.EndpointOpts) (string, error) {
		return openstack.V3EndpointURL(catalog, opts)
	}

	return nil
}

func buildProviderClient(cfg *openstack_provider.Config) (*gophercloud.ProviderClient, error) {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: cfg.Global.AuthURL,
		Username:         cfg.Global.Username,
		UserID:           cfg.Global.UserID,
		Password:         cfg.Global.Password,
		DomainID:         cfg.Global.DomainID,
		DomainName:       cfg.Global.DomainName,
		AllowReauth:      true,
	}

	authOptsExt := trusts.AuthOptsExt{
		TrustID:            cfg.Global.TrustID,
		AuthOptionsBuilder: &opts,
	}

	client, err := openstack.NewClient(cfg.Global.AuthURL)
	if err != nil {
		return nil, err
	}

	v3auth(client, cfg.Global.AuthURL, authOptsExt, gophercloud.EndpointOpts{})
	if err != nil {
		return nil, err
	}

	return client, nil
}

func Init(cfgPath string) (*Authorizer, error) {
	var config io.ReadCloser
	configReader, err := os.Open(cfgPath)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	var cfg openstack_provider.Config
	if configReader != nil {
		if err := gcfg.ReadInto(&cfg, configReader); err != nil {
			glog.Errorf("Couldn't read config: %v", err)
			return nil, err
		}
	}
	providerClient, err := buildProviderClient(&cfg)

	eo := gophercloud.EndpointOpts{
		Region:       "RegionOne",
		Type:         "identity",
		Availability: "public",
	}

	eurl, err := providerClient.EndpointLocator(eo)
	if err != nil {
		return nil, err
	}

	authClient := gophercloud.ServiceClient{
		ProviderClient: providerClient,
		Endpoint:       eurl,
	}
	authorizer := &Authorizer{
		authClient: &authClient,
	}
	return authorizer, nil
}

func (a *Authorizer) validate(token string) (bool, error) {

	valid, err := tokens3.Validate(a.authClient, token)
	if err != nil {
		return false, err
	}
	return valid, nil
}

func Validate(token string) bool {
	var err error
	var valid bool
	authorizer, err = New()
	if err != nil {
		log.Fatalf("Error initializing authorizer: %s", err)
		return false
	}
	valid, err = authorizer.validate(token)
	if err != nil {
		log.Fatalf("Error validating token: %s", err)
		return false
	}
	return valid
}
