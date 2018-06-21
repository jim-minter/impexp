package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"sort"
	"text/template"
	"time"
	"unicode"

	"github.com/ghodss/yaml"
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
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api/v1"
	"k8s.io/client-go/util/retry"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	kaggregator "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

type config struct {
	PublicHostname                 string
	RouterIP                       net.IP
	EtcdHostname                   string
	RegistryStorageAccount         string
	RegistryAccountKey             string
	CaKey                          *rsa.PrivateKey
	CaCert                         *x509.Certificate
	ServiceSigningCaCert           *x509.Certificate
	FrontProxyCaCert               *x509.Certificate
	RegistryServiceIP              net.IP
	RegistryHTTPSecret             []byte
	AlertManagerProxySessionSecret []byte
	AlertsProxySessionSecret       []byte
	PrometheusProxySessionSecret   []byte
	ServiceCatalogClusterID        uuid.UUID
	ServiceCatalogCaKey            *rsa.PrivateKey
	ServiceCatalogCaCert           *x509.Certificate
	ServiceCatalogServerKey        *rsa.PrivateKey
	ServiceCatalogServerCert       *x509.Certificate
	RegistryKey                    *rsa.PrivateKey
	RegistryCert                   *x509.Certificate
	RouterKey                      *rsa.PrivateKey
	RouterCert                     *x509.Certificate
}

func (c *config) UnmarshalJSON(b []byte) error {
	m := map[string]interface{}{}
	err := json.Unmarshal(b, &m)
	if err != nil {
		return err
	}

	v := reflect.ValueOf(c).Elem()
	for i := 0; i < v.NumField(); i++ {
		k := v.Type().Field(i).Name
		k = string(unicode.ToLower(rune(k[0]))) + k[1:]

		if _, exists := m[k]; !exists {
			continue
		}

		switch v.Field(i).Type() {
		case reflect.TypeOf(net.IP{}):
			ip := net.ParseIP(m[k].(string))
			v.Field(i).Set(reflect.ValueOf(ip))

		case reflect.TypeOf(&rsa.PrivateKey{}):
			key, err := tls.ParseBase64PrivateKey(m[k].(string))
			if err != nil {
				return err
			}
			v.Field(i).Set(reflect.ValueOf(key))

		case reflect.TypeOf(&rsa.PublicKey{}):
			key, err := tls.ParseBase64PublicKey(m[k].(string))
			if err != nil {
				return err
			}
			v.Field(i).Set(reflect.ValueOf(key))

		case reflect.TypeOf(uuid.UUID{}):
			u, err := uuid.FromString(m[k].(string))
			if err != nil {
				return err
			}
			v.Field(i).Set(reflect.ValueOf(u))

		case reflect.TypeOf(&v1.Config{}):
			b, err := base64.StdEncoding.DecodeString(m[k].(string))
			if err != nil {
				return err
			}

			var c v1.Config
			err = yaml.Unmarshal(b, &c)
			if err != nil {
				return err
			}

			v.Field(i).Set(reflect.ValueOf(&c))

		case reflect.TypeOf(&x509.Certificate{}):
			cert, err := tls.ParseBase64Cert(m[k].(string))
			if err != nil {
				return err
			}
			v.Field(i).Set(reflect.ValueOf(cert))

		case reflect.TypeOf([]byte{}):
			b, err := base64.StdEncoding.DecodeString(m[k].(string))
			if err != nil {
				return err
			}

			v.Field(i).Set(reflect.ValueOf(b))

		default:
			v.Field(i).Set(reflect.ValueOf(m[k]))
		}
	}

	return nil
}

var c config

var (
	restconfig *rest.Config
	ac         *kaggregator.Clientset
)

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
			err = t.Execute(b, c)
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

	ac, err = kaggregator.NewForConfig(restconfig)
	return
}

func main() {
	err := getClients()
	if err != nil {
		panic(err)
	}

	b, err := ioutil.ReadFile("/tmp/config/config")
	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(b, &c)
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
