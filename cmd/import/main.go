package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"sort"
	"text/template"
	"time"

	"github.com/ghodss/yaml"
	"github.com/jim-minter/impexp/pkg/templates"
	"github.com/jim-minter/impexp/pkg/tls"
	"github.com/jim-minter/impexp/pkg/translate"
	"github.com/satori/uuid"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
)

var rootConfig = struct {
	DNSPrefix              string
	Location               string
	RouterIP               net.IP
	MasterHostname         string
	RegistryStorageAccount string
	RegistryAccountKey     string
	CAKey                  *rsa.PrivateKey
	CACert                 *x509.Certificate
	ServiceSignerCACert    *x509.Certificate
	FrontProxyCACert       *x509.Certificate
}{}

var derivedConfig = struct {
	RootConfig                     interface{}
	RegistryServiceIP              net.IP
	RegistryHTTPSecret             []byte
	AlertManagerProxySessionSecret []byte
	AlertsProxySessionSecret       []byte
	PrometheusProxySessionSecret   []byte
	ServiceCatalogClusterID        uuid.UUID
	ServiceCatalogCAKey            *rsa.PrivateKey
	ServiceCatalogCACert           *x509.Certificate
	ServiceCatalogAPIServerKey     *rsa.PrivateKey
	ServiceCatalogAPIServerCert    *x509.Certificate
	AnsibleServiceBrokerCAKey      *rsa.PrivateKey
	AnsibleServiceBrokerCACert     *x509.Certificate
	RegistryKey                    *rsa.PrivateKey
	RegistryCert                   *x509.Certificate
	RouterKey                      *rsa.PrivateKey
	RouterCert                     *x509.Certificate
}{}

func loadRootConfig() error {
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})

	restconfig, err := kubeconfig.ClientConfig()
	if err != nil {
		return err
	}

	core, err := corev1.NewForConfig(restconfig)
	if err != nil {
		return err
	}

	cm, err := core.ConfigMaps("openshift-impexp").Get("rootconfig", metav1.GetOptions{})
	if err != nil {
		return err
	}

	rootConfig.DNSPrefix = cm.Data["DNSPrefix"]
	rootConfig.Location = cm.Data["Location"]
	rootConfig.RouterIP = net.ParseIP(cm.Data["RouterIP"])
	rootConfig.MasterHostname = cm.Data["MasterHostname"]
	rootConfig.RegistryStorageAccount = cm.Data["RegistryStorageAccount"]
	rootConfig.RegistryAccountKey = cm.Data["RegistryAccountKey"]

	rootConfig.CAKey, err = tls.ParseBase64PrivateKey(cm.Data["CAKey"])
	if err != nil {
		return err
	}

	rootConfig.CACert, err = tls.ParseBase64Cert(cm.Data["CACert"])
	if err != nil {
		return err
	}

	rootConfig.ServiceSignerCACert, err = tls.ParseBase64Cert(cm.Data["ServiceSignerCACert"])
	if err != nil {
		return err
	}

	rootConfig.FrontProxyCACert, err = tls.ParseBase64Cert(cm.Data["FrontProxyCACert"])
	if err != nil {
		return err
	}

	return nil
}

func makeSecret(b *[]byte) error {
	*b = make([]byte, 32)
	_, err := rand.Read(*b)
	return err
}

func deriveConfig() error {
	derivedConfig.RootConfig = &rootConfig
	derivedConfig.RegistryServiceIP = net.ParseIP("172.30.190.177")
	err := makeSecret(&derivedConfig.RegistryHTTPSecret)
	if err != nil {
		return err
	}
	err = makeSecret(&derivedConfig.AlertManagerProxySessionSecret)
	if err != nil {
		return err
	}
	err = makeSecret(&derivedConfig.AlertsProxySessionSecret)
	if err != nil {
		return err
	}
	err = makeSecret(&derivedConfig.PrometheusProxySessionSecret)
	if err != nil {
		return err
	}
	derivedConfig.ServiceCatalogClusterID = uuid.NewV4()

	derivedConfig.ServiceCatalogCAKey, derivedConfig.ServiceCatalogCACert, err =
		tls.NewCA("service-catalog-signer")
	if err != nil {
		return err
	}

	derivedConfig.AnsibleServiceBrokerCAKey, derivedConfig.AnsibleServiceBrokerCACert, err =
		tls.NewCA(fmt.Sprintf("openshift-signer@%d", time.Now().Unix()))
	if err != nil {
		return err
	}

	derivedConfig.ServiceCatalogAPIServerKey, derivedConfig.ServiceCatalogAPIServerCert, err =
		tls.NewCert("apiserver.kube-service-catalog",
			[]string{"apiserver.kube-service-catalog",
				"apiserver.kube-service-catalog.svc",
				"apiserver.kube-service-catalog.svc.cluster.local",
			},
			nil,
			derivedConfig.ServiceCatalogCAKey,
			derivedConfig.ServiceCatalogCACert)
	if err != nil {
		return err
	}

	derivedConfig.RegistryKey, derivedConfig.RegistryCert, err =
		tls.NewCert(derivedConfig.RegistryServiceIP.String(),
			[]string{"docker-registry-default." + derivedConfig.RegistryServiceIP.String() + ".nip.io",
				"docker-registry.default.svc",
				"docker-registry.default.svc.cluster.local",
			},
			[]net.IP{derivedConfig.RegistryServiceIP},
			rootConfig.CAKey,
			rootConfig.CACert)
	if err != nil {
		return err
	}

	derivedConfig.RouterKey, derivedConfig.RouterCert, err =
		tls.NewCert("*."+rootConfig.RouterIP.String()+".nip.io",
			[]string{"*." + rootConfig.RouterIP.String() + ".nip.io",
				rootConfig.RouterIP.String() + ".nip.io",
			},
			nil,
			rootConfig.CAKey,
			rootConfig.CACert)
	if err != nil {
		return err
	}

	return nil
}

func readDB() (map[string]unstructured.Unstructured, error) {
	db := map[string]unstructured.Unstructured{}

	assets := templates.AssetNames()
	sort.Strings(assets)

	for _, asset := range assets {
		b := templates.MustAsset(asset)

		var o unstructured.Unstructured
		err := yaml.Unmarshal(b, &o.Object)
		if err != nil {
			return nil, err
		}

		ts := translate.Translations[translate.KeyFunc(o.GroupVersionKind().GroupKind(), o.GetNamespace(), o.GetName())]
		for _, tr := range ts {
			t := template.New("")
			t = t.Funcs(template.FuncMap{
				"Base64Encode":      base64.StdEncoding.EncodeToString,
				"CertsAsBytes":      tls.CertsAsBytes,
				"PrivateKeyAsBytes": tls.PrivateKeyAsBytes,
				"String":            func(b []byte) string { return string(b) },
				"Bytes":             func(s string) []byte { return []byte(s) },
			})
			t, err = t.Parse(tr.Template)
			if err != nil {
				return nil, err
			}

			b := &bytes.Buffer{}
			err = t.Execute(b, derivedConfig)
			if err != nil {
				return nil, err
			}

			err = translate.Translate(o.Object, tr.Path, tr.NestedPath, tr.NestedFlags, b.String())
			if err != nil {
				return nil, err
			}
		}

		db[translate.KeyFunc(o.GroupVersionKind().GroupKind(), o.GetNamespace(), o.GetName())] = o
	}

	return db, nil
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func writeDB(db map[string]unstructured.Unstructured) error {
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})

	restconfig, err := kubeconfig.ClientConfig()
	if err != nil {
		return err
	}

	cli, err := discovery.NewDiscoveryClientForConfig(restconfig)
	if err != nil {
		return err
	}

	grs, err := discovery.GetAPIGroupResources(cli)
	if err != nil {
		return err
	}

	rm := discovery.NewRESTMapper(grs, meta.InterfacesForUnstructured)
	dyn := dynamic.NewClientPool(restconfig, rm, dynamic.LegacyAPIPathResolverFunc)

	for _, o := range db {
		if o.GroupVersionKind().Kind == "Namespace" {
			err = write(dyn, grs, o)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func write(dyn dynamic.ClientPool, grs []*discovery.APIGroupResources, o unstructured.Unstructured) error {
	dc, err := dyn.ClientForGroupVersionKind(o.GroupVersionKind())
	if err != nil {
		return err
	}

	var gr *discovery.APIGroupResources
	for _, g := range grs {
		if g.Group.Name == o.GroupVersionKind().Group {
			gr = g
			break
		}
	}

	var res *metav1.APIResource
	for _, r := range gr.VersionedResources[o.GroupVersionKind().Version] {
		if gr.Group.Name == "template.openshift.io" && r.Name == "processedtemplates" {
			continue
		}
		if r.Kind == o.GroupVersionKind().Kind {
			res = &r
			break
		}
	}

	_, err = dc.Resource(res, o.GetNamespace()).Create(&o)
	return err
}

func main() {
	err := loadRootConfig()
	if err != nil {
		panic(err)
	}

	err = deriveConfig()
	if err != nil {
		panic(err)
	}

	db, err := readDB()
	if err != nil {
		panic(err)
	}

	err = writeDB(db)
	if err != nil {
		panic(err)
	}
}
