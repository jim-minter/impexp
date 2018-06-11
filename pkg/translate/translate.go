package translate

import (
	"encoding/base64"

	"github.com/ghodss/yaml"
	"github.com/jim-minter/impexp/pkg/jsonpath"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func KeyFunc(gk schema.GroupKind, namespace, name string) string {
	s := gk.String()
	if namespace != "" {
		s += "/" + namespace
	}
	s += "/" + name

	return s
}

type NestedFlags int

const (
	NestedFlagsBase64 NestedFlags = (1 << iota)
)

func Translate(o interface{}, path jsonpath.Path, nestedPath jsonpath.Path, nestedFlags NestedFlags, v string) error {
	var err error

	if nestedPath == nil {
		path.Set(o, v)
		return nil
	}

	nestedBytes := []byte(path.MustGetString(o))

	if nestedFlags&NestedFlagsBase64 != 0 {
		nestedBytes, err = base64.StdEncoding.DecodeString(string(nestedBytes))
		if err != nil {
			return err
		}
	}

	var nestedObject interface{}
	err = yaml.Unmarshal(nestedBytes, &nestedObject)
	if err != nil {
		panic(err)
	}

	nestedPath.Set(nestedObject, v)

	nestedBytes, err = yaml.Marshal(nestedObject)
	if err != nil {
		panic(err)
	}

	if nestedFlags&NestedFlagsBase64 != 0 {
		nestedBytes = []byte(base64.StdEncoding.EncodeToString(nestedBytes))
		if err != nil {
			panic(err)
		}
	}

	path.Set(o, string(nestedBytes))

	return nil
}

var Translations = map[string][]struct {
	Path        jsonpath.Path
	NestedPath  jsonpath.Path
	NestedFlags NestedFlags
	Template    string
}{
	"APIService.apiregistration.k8s.io/v1beta1.servicecatalog.k8s.io": {
		{
			Path:     jsonpath.MustCompile("$.spec.caBundle"),
			Template: "{{ Base64Encode (CertsAsBytes .ServiceCatalogCACert) }}",
		},
	},
	"ClusterServiceBroker.servicecatalog.k8s.io/ansible-service-broker": {
		{
			Path:     jsonpath.MustCompile("$.spec.caBundle"),
			Template: "{{ Base64Encode (CertsAsBytes .AnsibleServiceBrokerCACert) }}",
		},
	},
	"ClusterServiceBroker.servicecatalog.k8s.io/template-service-broker": {
		{
			Path:     jsonpath.MustCompile("$.spec.caBundle"),
			Template: "{{ Base64Encode (CertsAsBytes .RootConfig.ServiceSignerCACert) }}",
		},
	},
	"ConfigMap/kube-service-catalog/cluster-info": {
		{
			Path:     jsonpath.MustCompile("$.data.id"),
			Template: "{{ .ServiceCatalogClusterID }}",
		},
	},
	"ConfigMap/kube-system/extension-apiserver-authentication": {
		{
			Path:     jsonpath.MustCompile("$.data.'client-ca-file'"),
			Template: "{{ String (CertsAsBytes .RootConfig.CACert) }}",
		},
		{
			Path:     jsonpath.MustCompile("$.data.'requestheader-client-ca-file'"),
			Template: "{{ String (CertsAsBytes .RootConfig.FrontProxyCACert) }}",
		},
	},
	"ConfigMap/openshift-web-console/webconsole-config": {
		{
			Path:       jsonpath.MustCompile("$.data.'webconsole-config.yaml'"),
			NestedPath: jsonpath.MustCompile("$.clusterInfo.consolePublicURL"),
			Template:   "https://{{ .RootConfig.DNSPrefix }}.{{ .RootConfig.Location }}.cloudapp.azure.com:8443/console/",
		},
		{
			Path:       jsonpath.MustCompile("$.data.'webconsole-config.yaml'"),
			NestedPath: jsonpath.MustCompile("$.clusterInfo.masterPublicURL"),
			Template:   "https://{{ .RootConfig.DNSPrefix }}.{{ .RootConfig.Location }}.cloudapp.azure.com:8443",
		},
	},
	"DaemonSet.apps/kube-service-catalog/apiserver": {
		{
			Path:     jsonpath.MustCompile("$.spec.template.spec.containers[0].args[6]"),
			Template: "https://{{ .RootConfig.MasterHostname }}:2379",
		},
	},
	"DeploymentConfig.apps.openshift.io/default/docker-registry": {
		{
			Path:     jsonpath.MustCompile("$.spec.template.spec.containers[0].env[?(@.name='REGISTRY_HTTP_SECRET')].value"),
			Template: "{{ Base64Encode .RegistryHTTPSecret }}",
		},
	},
	"DeploymentConfig.apps.openshift.io/default/registry-console": {
		{
			Path:     jsonpath.MustCompile("$.spec.template.spec.containers[0].env[?(@.name='OPENSHIFT_OAUTH_PROVIDER_URL')].value"),
			Template: "https://{{ .RootConfig.DNSPrefix }}.{{ .RootConfig.Location }}.cloudapp.azure.com:8443",
		},
		{
			Path:     jsonpath.MustCompile("$.spec.template.spec.containers[0].env[?(@.name='REGISTRY_HOST')].value"),
			Template: "docker-registry-default.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"OAuthClient.oauth.openshift.io/cockpit-oauth-client": {
		{
			Path:     jsonpath.MustCompile("$.redirectURIs[0]"),
			Template: "https://registry-console-default.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Route.route.openshift.io/default/docker-registry": {
		{
			Path:     jsonpath.MustCompile("$.spec.host"),
			Template: "docker-registry-default.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Route.route.openshift.io/default/registry-console": {
		{
			Path:     jsonpath.MustCompile("$.spec.host"),
			Template: "registry-console-default.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Route.route.openshift.io/kube-service-catalog/apiserver": {
		{
			Path:     jsonpath.MustCompile("$.spec.host"),
			Template: "apiserver-kube-service-catalog.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Route.route.openshift.io/openshift-ansible-service-broker/asb-1338": {
		{
			Path:     jsonpath.MustCompile("$.spec.host"),
			Template: "asb-1338-openshift-ansible-service-broker.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Route.route.openshift.io/openshift-metrics/alertmanager": {
		{
			Path:     jsonpath.MustCompile("$.spec.host"),
			Template: "alertmanager-openshift-metrics.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Route.route.openshift.io/openshift-metrics/alerts": {
		{
			Path:     jsonpath.MustCompile("$.spec.host"),
			Template: "alerts-openshift-metrics.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Route.route.openshift.io/openshift-metrics/prometheus": {
		{
			Path:     jsonpath.MustCompile("$.spec.host"),
			Template: "prometheus-openshift-metrics.{{ .RootConfig.RouterIP }}.nip.io",
		},
	},
	"Secret/default/registry-certificates": {
		{
			Path:     jsonpath.MustCompile("$.data.'registry.crt'"),
			Template: "{{ Base64Encode (CertsAsBytes .RegistryCert .RootConfig.CACert) }}",
		},
		{
			Path:     jsonpath.MustCompile("$.data.'registry.key'"),
			Template: "{{ Base64Encode (PrivateKeyAsBytes .RegistryKey) }}",
		},
	},
	"Secret/default/registry-config": {
		{
			Path:        jsonpath.MustCompile("$.data.'config.yml'"),
			NestedPath:  jsonpath.MustCompile("$.storage.azure.accountname"),
			NestedFlags: NestedFlagsBase64,
			Template:    "{{ .RootConfig.RegistryStorageAccount }}",
		},
		{
			Path:        jsonpath.MustCompile("$.data.'config.yml'"),
			NestedPath:  jsonpath.MustCompile("$.storage.azure.accountkey"),
			NestedFlags: NestedFlagsBase64,
			Template:    "{{ .RootConfig.RegistryAccountKey }}",
		},
	},
	"Secret/default/router-certs": {
		{
			Path:     jsonpath.MustCompile("$.data.'tls.crt'"),
			Template: "{{ Base64Encode (CertsAsBytes .RouterCert .RootConfig.CACert) }}",
		},
		{
			Path:     jsonpath.MustCompile("$.data.'tls.key'"),
			Template: "{{ Base64Encode (PrivateKeyAsBytes .RouterKey) }}",
		},
	},
	"Secret/kube-service-catalog/apiserver-ssl": {
		{
			Path:     jsonpath.MustCompile("$.data.'tls.crt'"),
			Template: "{{ Base64Encode (CertsAsBytes .ServiceCatalogAPIServerCert .ServiceCatalogCACert) }}",
		},
		{
			Path:     jsonpath.MustCompile("$.data.'tls.key'"),
			Template: "{{ Base64Encode (PrivateKeyAsBytes .ServiceCatalogAPIServerKey) }}",
		},
	},
	"Secret/openshift-metrics/alertmanager-proxy": {
		{
			Path:     jsonpath.MustCompile("$.data.'session_secret'"),
			Template: "{{ Base64Encode (Bytes (Base64Encode .AlertManagerProxySessionSecret)) }}",
		},
	},
	"Secret/openshift-metrics/alerts-proxy": {
		{
			Path:     jsonpath.MustCompile("$.data.'session_secret'"),
			Template: "{{ Base64Encode (Bytes (Base64Encode .AlertsProxySessionSecret)) }}",
		},
	},
	"Secret/openshift-metrics/prometheus-proxy": {
		{
			Path:     jsonpath.MustCompile("$.data.'session_secret'"),
			Template: "{{ Base64Encode (Bytes (Base64Encode .PrometheusProxySessionSecret)) }}",
		},
	},
	"Service/default/docker-registry": {
		{
			Path:     jsonpath.MustCompile("$.spec.clusterIP"),
			Template: "{{ .RegistryServiceIP }}",
		},
	},
}
