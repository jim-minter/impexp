package configmap

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"reflect"

	"github.com/jim-minter/impexp/pkg/tls"
	"github.com/satori/uuid"
	"k8s.io/api/core/v1"
)

// Marshal marshals a struct to a ConfigMap.  Nested structs are not allowed and
// a very limited set of field types is currently implemented.
func Marshal(i interface{}) (*v1.ConfigMap, error) {
	v := reflect.ValueOf(i)
	if v.Kind() != reflect.Ptr || v.Type().Elem().Kind() != reflect.Struct {
		return nil, errors.New("i must be pointer to struct")
	}
	return marshal(v.Elem())
}

func marshal(i reflect.Value) (*v1.ConfigMap, error) {
	m := &v1.ConfigMap{
		Data: map[string]string{},
	}

	for n := 0; n < i.NumField(); n++ {
		v := i.Field(n)

		// skip fields tagged `configmap:"-"`
		if i.Type().Field(n).Tag.Get("configmap") == "-" {
			continue
		}

		// skip nil fields
		switch v.Kind() {
		case reflect.Slice, reflect.Interface, reflect.Map, reflect.Ptr:
			if v.IsNil() {
				continue
			}
		}

		// serialise the field to a string to put it in the ConfigMap.
		// TODO: this switch ought to be extensible.
		key := i.Type().Field(n).Name
		switch v := v.Interface().(type) {
		case string:
			m.Data[key] = v

		case []byte:
			m.Data[key] = base64.StdEncoding.EncodeToString(v)

		case net.IP: // for convenience, we write the IP as a string, not base64 encoded.
			m.Data[key] = v.String()

		case uuid.UUID: // for convenience, we write the UUID as a string, not base64 encoded.
			m.Data[key] = v.String()

		case *rsa.PrivateKey:
			b, err := tls.PrivateKeyAsBytes(v)
			if err != nil {
				return nil, err
			}
			m.Data[key] = base64.StdEncoding.EncodeToString(b)

		case *x509.Certificate:
			b, err := tls.CertAsBytes(v)
			if err != nil {
				return nil, err
			}
			m.Data[key] = base64.StdEncoding.EncodeToString(b)

		default:
			return nil, errors.New("unimplemented type " + i.Field(n).Type().String())
		}
	}

	return m, nil
}

// Unmarshal unmarshals a ConfigMap to a struct.  Nested structs are not allowed
// and a very limited set of field types is currently implemented.
func Unmarshal(m *v1.ConfigMap, i interface{}) error {
	v := reflect.ValueOf(i)
	if v.Kind() != reflect.Ptr || v.Type().Elem().Kind() != reflect.Struct {
		return errors.New("i must be pointer to struct")
	}
	return unmarshal(m, v.Elem())
}

func unmarshal(m *v1.ConfigMap, i reflect.Value) error {
	for k, v := range m.Data {
		f := i.FieldByName(k)

		// if we can't find a corresponding field in the struct, skip.
		if !f.IsValid() {
			continue
		}

		t, _ := i.Type().FieldByName(k)

		// skip fields tagged `configmap:"-"`
		if t.Tag.Get("configmap") == "-" {
			continue
		}

		switch t.Type {
		case reflect.TypeOf(""):
			f.Set(reflect.ValueOf(v))

		case reflect.TypeOf([]byte{}):
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(b))

		case reflect.TypeOf(net.IP{}): // for convenience, we write the IP as a string, not base64 encoded.
			f.Set(reflect.ValueOf(net.ParseIP(v)))

		case reflect.TypeOf(uuid.UUID{}): // for convenience, we write the UUID as a string, not base64 encoded.
			u, err := uuid.FromString(v)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(u))

		case reflect.TypeOf(&rsa.PrivateKey{}):
			key, err := tls.ParseBase64PrivateKey(v)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(key))

		case reflect.TypeOf(&x509.Certificate{}):
			cert, err := tls.ParseBase64Cert(v)
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(cert))

		default:
			return errors.New("unimplemented type " + t.Type.String())
		}
	}

	return nil
}
