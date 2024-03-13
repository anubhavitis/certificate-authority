package authority

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

var ca *x509.Certificate

func GetCA() *x509.Certificate {
	if ca == nil {
		createCA()
	}
	return ca
}

// createCA generates a CA (Certificate Authority) certificate and its corresponding private key.
// The CA certificate is used to sign other certificates.
// It returns an error if there was a problem generating the CA certificate or private key.
func createCA() error {
	// First we'll start off by creating our CA certificate.
	// This is what we'll use to sign other certificates that we create:
	ca = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"sixhuman"},
			Country:      []string{"India"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// The IsCA field set to true will indicate that this is our CA certificate.
	// From here, we need to generate a public and private key for the certificate:
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// And then we'll generate the certificate:
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	caPEM := new(bytes.Buffer)
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	// Now in caBytes we have our generated certificate, which we can PEM encode for later use:
	caPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	return nil
}
