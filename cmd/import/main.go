package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"reflect"
	"sort"
	"text/template"
	"time"

	"github.com/ghodss/yaml"
	"github.com/jim-minter/impexp/pkg/encoding/configmap"
	"github.com/jim-minter/impexp/pkg/templates"
	"github.com/jim-minter/impexp/pkg/tls"
	"github.com/jim-minter/impexp/pkg/translate"
	"github.com/satori/uuid"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	kaggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

const (
	impexpNamespace   = "openshift-impexp"
	derivedConfigName = "derivedconfig"
	rootConfigName    = "rootconfig"
)

// rootConfig contains configuration items which are provided externally, e.g.
// acs-engine configurables, Azure environment, external OpenShift cluster-level
// configurables.  It is read in from the `openshift-impexp/rootconfig`
// ConfigMap.  Note: these values may not be constant over the lifetime of a
// cluster.
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

// derivedConfig contains configuration items which are derivable from
// rootConfig, or which are scoped to objects running within the OpenShift
// cluster.  It is persisted in the `openshift-impexp/derivedconfig` ConfigMap.
// derivedConfig is the struct passed into template.Execute() to populate
// configuration items on import.
// TODO: presumably this struct needs a version field and migration
// functionality.
var derivedConfig = struct {
	RootConfig                     interface{} `configmap:"-"`
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
	RegistryKey                    *rsa.PrivateKey
	RegistryCert                   *x509.Certificate
	RouterKey                      *rsa.PrivateKey
	RouterCert                     *x509.Certificate
}{}

var (
	restconfig *rest.Config
	kc         *kubernetes.Clientset
	ac         *kaggregator.Clientset
)

// loadRootConfig loads the rootConfig object from its ConfigMap.
func loadRootConfig() error {
	cm, err := kc.CoreV1().ConfigMaps(impexpNamespace).Get(rootConfigName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	return configmap.Unmarshal(cm, &rootConfig)
}

// makeSecret returns a byte slice with 32 random bytes.
func makeSecret() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// loadDerivedConfig loads the derivedConfig object from its ConfigMap, if it
// exists.
func loadDerivedConfig() error {
	cm, err := kc.CoreV1().ConfigMaps(impexpNamespace).Get(derivedConfigName, metav1.GetOptions{})
	switch {
	case err == nil:
		return configmap.Unmarshal(cm, &derivedConfig)
	case kerrors.IsNotFound(err):
		return nil
	default:
		return err
	}
}

// defaultDerivedConfig populates non-existent entries in the derivedConfig
// object.
func defaultDerivedConfig() error {
	var err error

	derivedConfig.RootConfig = &rootConfig

	if derivedConfig.RegistryServiceIP == nil {
		derivedConfig.RegistryServiceIP = net.ParseIP("172.30.190.177") // TODO: choose a particular IP address?
	}
	if derivedConfig.RegistryHTTPSecret == nil {
		if derivedConfig.RegistryHTTPSecret, err = makeSecret(); err != nil {
			return err
		}
	}
	if derivedConfig.AlertManagerProxySessionSecret == nil {
		if derivedConfig.AlertManagerProxySessionSecret, err = makeSecret(); err != nil {
			return err
		}
	}
	if derivedConfig.AlertsProxySessionSecret == nil {
		if derivedConfig.AlertsProxySessionSecret, err = makeSecret(); err != nil {
			return err
		}
	}
	if derivedConfig.PrometheusProxySessionSecret == nil {
		if derivedConfig.PrometheusProxySessionSecret, err = makeSecret(); err != nil {
			return err
		}
	}
	if derivedConfig.ServiceCatalogClusterID == uuid.Nil {
		if derivedConfig.ServiceCatalogClusterID, err = uuid.NewV4(); err != nil {
			return err
		}
	}
	// TODO: get the service catalog to use
	// service.alpha.openshift.io/serving-cert-secret-name.
	if derivedConfig.ServiceCatalogCAKey == nil || derivedConfig.ServiceCatalogCACert == nil {
		derivedConfig.ServiceCatalogCAKey, derivedConfig.ServiceCatalogCACert, err =
			tls.NewCA("service-catalog-signer")
		if err != nil {
			return err
		}
	}
	if derivedConfig.ServiceCatalogAPIServerKey == nil || derivedConfig.ServiceCatalogAPIServerCert == nil {
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
	}
	// TODO: is it possible for the registry to use
	// service.alpha.openshift.io/serving-cert-secret-name?
	if derivedConfig.RegistryKey == nil || derivedConfig.RegistryCert == nil {
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
	}
	// TODO: the router CN and SANs should be configurables.
	if derivedConfig.RouterKey == nil || derivedConfig.RouterCert == nil {
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
	}

	return nil
}

// saveDerivedConfig persists the derivedConfig to its ConfigMap.
func saveDerivedConfig() error {
	cm, err := configmap.Marshal(&derivedConfig)
	if err != nil {
		return err
	}
	cm.ObjectMeta = metav1.ObjectMeta{
		Name:      derivedConfigName,
		Namespace: impexpNamespace,
	}

	_, err = kc.CoreV1().ConfigMaps(impexpNamespace).Create(cm)
	if kerrors.IsAlreadyExists(err) {
		err = retry.RetryOnConflict(retry.DefaultRetry, func() (err error) {
			existing, err := kc.CoreV1().ConfigMaps(impexpNamespace).Get(derivedConfigName, metav1.GetOptions{})
			if err != nil {
				return
			}

			cm.ObjectMeta = existing.ObjectMeta
			_, err = kc.CoreV1().ConfigMaps(impexpNamespace).Update(cm)
			return
		})
	}

	return err
}

// readDB reads previously exported objects into a map via go-bindata as well as
// populating configuration items via translate.Translate().
func readDB() (map[string]unstructured.Unstructured, error) {
	db := map[string]unstructured.Unstructured{}

	for _, asset := range templates.AssetNames() {
		b, err := templates.Asset(asset)
		if err != nil {
			return nil, err
		}

		// can't use straight yaml.Unmarshal() because it universally mangles
		// yaml integers into float64s, whereas the Kubernetes client library
		// uses int64s wherever it can.  Such a difference can cause us to
		// update objects when we don't actually need to.
		json, err := yaml.YAMLToJSON(b)
		if err != nil {
			return nil, err
		}
		var o unstructured.Unstructured
		_, _, err = unstructured.UnstructuredJSONScheme.Decode(json, nil, &o)
		if err != nil {
			return nil, err
		}

		ts := translate.Translations[translate.KeyFunc(o.GroupVersionKind().GroupKind(), o.GetNamespace(), o.GetName())]
		for _, tr := range ts {
			t := template.New("")
			t = t.Funcs(template.FuncMap{
				"Base64Encode":      base64.StdEncoding.EncodeToString,
				"CertAsBytes":       tls.CertAsBytes,
				"PrivateKeyAsBytes": tls.PrivateKeyAsBytes,
				"String":            func(b []byte) string { return string(b) },
				"Bytes":             func(s string) []byte { return []byte(s) },
				"JoinBytes":         func(b ...[]byte) []byte { return bytes.Join(b, []byte("\n")) },
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

// contains returns true if haystack contains needle.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// getDynamicClient returns the server API group resource information and a
// dynamic client pool.
func getDynamicClient(cli *discovery.DiscoveryClient) (dynamic.ClientPool, []*discovery.APIGroupResources, error) {
	grs, err := discovery.GetAPIGroupResources(cli)
	if err != nil {
		return nil, nil, err
	}

	rm := discovery.NewRESTMapper(grs, meta.InterfacesForUnstructured)
	dyn := dynamic.NewClientPool(restconfig, rm, dynamic.LegacyAPIPathResolverFunc)

	return dyn, grs, nil
}

// writeDB uses the discovery and dynamic clients to synchronise an API server's
// objects with db.
// TODO: this needs substantial refactoring.
func writeDB(db map[string]unstructured.Unstructured) error {
	cli, err := discovery.NewDiscoveryClientForConfig(restconfig)
	if err != nil {
		return err
	}

	dyn, grs, err := getDynamicClient(cli)
	if err != nil {
		return err
	}

	// impose an order to improve debuggability.
	var keys []string
	for k := range db {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// namespaces must exist before namespaced objects.
	for _, k := range keys {
		o := db[k]
		if o.GroupVersionKind().Kind == "Namespace" {
			err = write(dyn, grs, &o)
			if err != nil {
				return err
			}
		}
	}

	// don't try to handle groups which don't exist yet.
	for _, k := range keys {
		o := db[k]
		if o.GroupVersionKind().Group != "servicecatalog.k8s.io" &&
			o.GroupVersionKind().Kind != "Secret" &&
			o.GroupVersionKind().Kind != "Namespace" {
			err = write(dyn, grs, &o)
			if err != nil {
				return err
			}
		}
	}

	// it turns out that secrets of type `kubernetes.io/service-account-token`
	// must be created after the corresponding serviceaccount has been created.
	for _, k := range keys {
		o := db[k]
		if o.GroupVersionKind().Kind == "Secret" {
			err = write(dyn, grs, &o)
			if err != nil {
				return err
			}
		}
	}

	// wait for the service catalog api extension to arrive. TODO: we should do
	// this dynamically, and should not PollInfinite.
	err = wait.PollInfinite(time.Second, func() (bool, error) {
		svc, err := ac.ApiregistrationV1().APIServices().Get("v1beta1.servicecatalog.k8s.io", metav1.GetOptions{})
		switch {
		case kerrors.IsNotFound(err):
			return false, nil
		case err != nil:
			return false, err
		}
		for _, cond := range svc.Status.Conditions {
			if cond.Type == apiregistrationv1.Available &&
				cond.Status == apiregistrationv1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return err
	}

	// refresh dynamic client
	dyn, grs, err = getDynamicClient(cli)
	if err != nil {
		return err
	}

	// now write the servicecatalog configurables.
	for _, k := range keys {
		o := db[k]
		if o.GroupVersionKind().Group == "servicecatalog.k8s.io" {
			err = write(dyn, grs, &o)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// write synchronises a single object with the API server.
func write(dyn dynamic.ClientPool, grs []*discovery.APIGroupResources, o *unstructured.Unstructured) error {
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
	if gr == nil {
		return errors.New("couldn't find group " + o.GroupVersionKind().Group)
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
	if res == nil {
		return errors.New("couldn't find kind " + o.GroupVersionKind().Kind)
	}

	o = o.DeepCopy() // TODO: do this much earlier

	err = retry.RetryOnConflict(retry.DefaultRetry, func() (err error) {
		var existing *unstructured.Unstructured
		existing, err = dc.Resource(res, o.GetNamespace()).Get(o.GetName(), metav1.GetOptions{})
		if kerrors.IsNotFound(err) {
			log.Println("Create " + translate.KeyFunc(o.GroupVersionKind().GroupKind(), o.GetNamespace(), o.GetName()))
			_, err = dc.Resource(res, o.GetNamespace()).Create(o)
			return
		}
		if err != nil {
			return
		}

		rv := existing.GetResourceVersion()
		translate.Clean(*existing)

		if reflect.DeepEqual(*existing, *o) {
			return
		}

		o.SetResourceVersion(rv)
		log.Println("Update " + translate.KeyFunc(o.GroupVersionKind().GroupKind(), o.GetNamespace(), o.GetName()))
		_, err = dc.Resource(res, o.GetNamespace()).Update(o)
		return
	})

	return err
}

// getClients populates the Kubernetes client object(s).
func getClients() (err error) {
	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})

	restconfig, err = kubeconfig.ClientConfig()
	if err != nil {
		return
	}

	kc, err = kubernetes.NewForConfig(restconfig)
	if err != nil {
		return err
	}

	ac, err = kaggregator.NewForConfig(restconfig)
	return
}

func main() {
	err := getClients()
	if err != nil {
		panic(err)
	}

	err = loadRootConfig()
	if err != nil {
		panic(err)
	}

	err = loadDerivedConfig()
	if err != nil {
		panic(err)
	}

	err = defaultDerivedConfig()
	if err != nil {
		panic(err)
	}

	err = saveDerivedConfig()
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

	// TODO: need to implement deleting objects which we don't want any more.
}
