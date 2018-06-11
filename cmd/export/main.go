package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/jim-minter/impexp/pkg/jsonpath"
	"github.com/jim-minter/impexp/pkg/translate"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

func readDB() (map[string]unstructured.Unstructured, error) {
	db := map[string]unstructured.Unstructured{}

	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{})

	restconfig, err := kubeconfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	cli, err := discovery.NewDiscoveryClientForConfig(restconfig)
	if err != nil {
		return nil, err
	}

	grs, err := discovery.GetAPIGroupResources(cli)
	if err != nil {
		return nil, err
	}

	rm := discovery.NewRESTMapper(grs, meta.InterfacesForUnstructured)
	dyn := dynamic.NewClientPool(restconfig, rm, dynamic.LegacyAPIPathResolverFunc)

	for _, gr := range grs {
		gv, err := schema.ParseGroupVersion(gr.Group.PreferredVersion.GroupVersion)
		if err != nil {
			return nil, err
		}

		for _, resource := range gr.VersionedResources[gr.Group.PreferredVersion.Version] {
			if strings.ContainsRune(resource.Name, '/') {
				continue
			}

			if !contains(resource.Verbs, "list") {
				continue
			}

			dc, err := dyn.ClientForGroupVersionKind(gv.WithKind(resource.Kind))
			if err != nil {
				return nil, err
			}

			o, err := dc.Resource(&resource, "").List(metav1.ListOptions{})
			if err != nil {
				return nil, err
			}

			l, ok := o.(*unstructured.UnstructuredList)
			if !ok {
				continue
			}

			for _, i := range l.Items {
				db[translate.KeyFunc(i.GroupVersionKind().GroupKind(), i.GetNamespace(), i.GetName())] = i
			}
		}
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

func wants(db map[string]unstructured.Unstructured, o unstructured.Unstructured) bool {
	gk := o.GroupVersionKind().GroupKind()
	ns := o.GetNamespace()

	switch gk.Group {
	case "authorization.openshift.io",
		"events.k8s.io",
		"extensions",
		"network.openshift.io",
		"project.openshift.io",
		"user.openshift.io":
		return false
	}

	switch ns {
	case "", "default", "openshift":
	default:
		if !strings.HasPrefix(ns, "kube-") && !strings.HasPrefix(ns, "openshift-") {
			return false
		}
	}

	switch gk.String() {
	case "CertificateSigningRequest.certificates.k8s.io",
		"ClusterServiceClass.servicecatalog.k8s.io",
		"ClusterServicePlan.servicecatalog.k8s.io",
		"ComponentStatus",
		"ControllerRevision.apps",
		"Endpoints",
		"Event",
		"Image.image.openshift.io",
		"ImageStreamTag.image.openshift.io",
		"Node",
		"OAuthAccessToken.oauth.openshift.io",
		"SecurityContextConstraints":
		return false

	case "APIService.apiregistration.k8s.io":
		if _, found := o.GetLabels()["kube-aggregator.kubernetes.io/automanaged"]; found {
			return false
		}

	case "ConfigMap":
		if _, found := o.GetAnnotations()["control-plane.alpha.kubernetes.io/leader"]; found {
			return false
		}

	case "Namespace":
		switch ns {
		case "", "default", "openshift":
		default:
			if !strings.HasPrefix(ns, "kube-") && !strings.HasPrefix(ns, "openshift-") {
				return false
			}
		}

	case "OAuthClient.oauth.openshift.io":
		switch o.GetName() {
		case "openshift-browser-client",
			"openshift-challenging-client",
			"openshift-web-console":
			return false
		}

	case "Pod":
		if ns == "kube-system" {
			return false
		}

		for _, ref := range o.GetOwnerReferences() {
			switch ref.Kind {
			case "DaemonSet",
				"ReplicaSet",
				"ReplicationController",
				"StatefulSet":
				return false
			}
		}

	case "ReplicaSet.apps":
		for _, ref := range o.GetOwnerReferences() {
			switch ref.Kind {
			case "Deployment":
				return false
			}
		}

	case "ReplicationController":
		for _, ref := range o.GetOwnerReferences() {
			switch ref.Kind {
			case "DeploymentConfig":
				return false
			}
		}

	case "Secret":
		switch jsonpath.MustCompile("$.type").MustGetString(o.Object) {
		case "kubernetes.io/dockercfg",
			"kubernetes.io/service-account-token":
			return false
		}
		if _, found := o.GetAnnotations()["service.alpha.openshift.io/originating-service-name"]; found {
			return false
		}

	case "ServiceAccount":
		wanted := false
		for _, field := range []string{"imagePullSecrets", "secrets"} {
			for _, secret := range jsonpath.MustCompile("$." + field + ".*.name").MustGetStrings(o.Object) {
				wanted = wanted || wants(db, db[translate.KeyFunc(schema.GroupKind{Kind: "Secret"}, ns, secret)])
			}
		}
		if wanted {
			return true
		}
		switch o.GetName() {
		case "builder",
			"default",
			"deployer":
			return false
		}

	case "Template.template.openshift.io":
		if ns != "openshift" {
			return false
		}
	}

	return true
}

func clean(db map[string]unstructured.Unstructured, o unstructured.Unstructured) unstructured.Unstructured {
	gk := o.GroupVersionKind().GroupKind()

	metadataClean := []string{
		".annotations.'kubectl.kubernetes.io/last-applied-configuration'",
		".annotations.'openshift.io/generated-by'",
		".creationTimestamp",
		".generation",
		".resourceVersion",
		".selfLink",
		".uid",
	}
	for _, k := range metadataClean {
		jsonpath.MustCompile("$.metadata" + k).Delete(o.Object)
	}

	jsonpath.MustCompile("$.status").Delete(o.Object)

	switch gk.String() {
	case "DaemonSet.apps":
		jsonpath.MustCompile("$.metadata.annotations.'deprecated.daemonset.template.generation'").Delete(o.Object)
		for _, k := range metadataClean {
			jsonpath.MustCompile("$.spec.template.metadata" + k).Delete(o.Object)
		}

	case "Deployment.apps":
		jsonpath.MustCompile("$.metadata.annotations.'deployment.kubernetes.io/revision'").Delete(o.Object)
		for _, k := range metadataClean {
			jsonpath.MustCompile("$.spec.template.metadata" + k).Delete(o.Object)
		}

	case "DeploymentConfig.apps.openshift.io":
		for _, k := range metadataClean {
			jsonpath.MustCompile("$.spec.template.metadata" + k).Delete(o.Object)
		}

	case "ImageStream.image.openshift.io":
		jsonpath.MustCompile("$.metadata.annotations.'openshift.io/image.dockerRepositoryCheck'").Delete(o.Object)

	case "Namespace":
		for _, k := range []string{
			"$.metadata.annotations.'openshift.io/sa.scc.mcs'",
			"$.metadata.annotations.'openshift.io/sa.scc.supplemental-groups'",
			"$.metadata.annotations.'openshift.io/sa.scc.uid-range'",
		} {
			jsonpath.MustCompile(k).Delete(o.Object)
		}

	case "Service":
		jsonpath.MustCompile("$.metadata.annotations.'service.alpha.openshift.io/serving-cert-signed-by'").Delete(o.Object)

	case "ServiceAccount":
		for _, field := range []string{"imagePullSecrets", "secrets"} {
			var newRefs []interface{}
			for _, ref := range jsonpath.MustCompile("$." + field + ".*").Get(o.Object) {
				if wants(db, db[translate.KeyFunc(schema.GroupKind{Kind: "Secret"}, o.GetNamespace(), jsonpath.MustCompile("$.name").MustGetString(ref))]) {
					newRefs = append(newRefs, ref)
				}
			}
			if len(newRefs) > 0 {
				jsonpath.MustCompile("$."+field).Set(o.Object, newRefs)
			} else {
				jsonpath.MustCompile("$." + field).Delete(o.Object)
			}
		}

	case "StatefulSet.apps":
		for _, k := range metadataClean {
			jsonpath.MustCompile("$.spec.template.metadata" + k).Delete(o.Object)
		}
	}

	path := jsonpath.MustCompile("$.metadata.annotations")
	annotations := path.Get(o.Object)
	if len(annotations) == 1 && len(annotations[0].(map[string]interface{})) == 0 {
		path.Delete(o.Object)
	}

	return o
}

func blank(db map[string]unstructured.Unstructured, o unstructured.Unstructured) (unstructured.Unstructured, error) {
	for _, t := range translate.Translations[translate.KeyFunc(o.GroupVersionKind().GroupKind(), o.GetNamespace(), o.GetName())] {
		err := translate.Translate(o.Object, t.Path, t.NestedPath, t.NestedFlags, "*** GENERATED ***")
		if err != nil {
			return unstructured.Unstructured{}, err
		}
	}

	return o, nil
}

func write(o unstructured.Unstructured) error {
	gk := o.GroupVersionKind().GroupKind()
	p := fmt.Sprintf("pkg/templates/data/%s/%s/%s", gk.String(), o.GetNamespace(), o.GetName())

	err := os.MkdirAll(filepath.Dir(p), 0777)
	if err != nil {
		return err
	}

	b, err := yaml.Marshal(o.Object)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(p, b, 0666)
}

func writeDB(db map[string]unstructured.Unstructured) error {
	for _, o := range db {
		if !wants(db, o) {
			continue
		}

		o = clean(db, o)

		o, err := blank(db, o)
		if err != nil {
			return err
		}

		err = write(o)
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	err := os.RemoveAll("pkg/templates/data")
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
