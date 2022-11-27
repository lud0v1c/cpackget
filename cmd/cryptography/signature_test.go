package cryptography_test

import (
	"os"
	"testing"

	"github.com/open-cmsis-pack/cpackget/cmd/cryptography"
	errs "github.com/open-cmsis-pack/cpackget/cmd/errors"
	"github.com/open-cmsis-pack/cpackget/cmd/utils"
	"github.com/stretchr/testify/assert"
)

func TestSignatureCreate(t *testing.T) {
	assert := assert.New(t)
	version := os.Getenv("VERSION")

	t.Run("test X509 signing a pack", func(t *testing.T) {
		localTestingDir := "test-signing-x509"
		err := utils.EnsureDir(localTestingDir)
		assert.Nil(err)
		defer os.RemoveAll(localTestingDir)

		err = cryptography.SignPack(packNotSigned, x509Certificate, x509PrivateRSA, localTestingDir, version, false, false, false)
		assert.Nil(err)
	})
	t.Run("test X509 signing a nonexisting pack", func(t *testing.T) {
		localTestingDir := "test-signing-nonexisting-x509"
		err := utils.EnsureDir(localTestingDir)
		assert.Nil(err)
		defer os.RemoveAll(localTestingDir)

		err = cryptography.SignPack(packThatDoesNotExist, x509Certificate, x509PrivateRSA, localTestingDir, version, false, false, false)
		assert.Equal(errs.ErrFileNotFound, err)
	})

	// PGP
	os.Setenv("TESTING_PASSPHRASE", "testing1")
	t.Run("test PGP signing a pack", func(t *testing.T) {
		localTestingDir := "test-signing-pgp"
		err := utils.EnsureDir(localTestingDir)
		assert.Nil(err)
		defer os.RemoveAll(localTestingDir)

		err = cryptography.SignPack(packNotSigned, "", pgpPrivateRSA, localTestingDir, version, false, false, false)
		assert.Nil(err)
	})
	t.Run("test PGP signing a nonexisting pack", func(t *testing.T) {
		localTestingDir := "test-signing-nonexisting-pgp"
		err := utils.EnsureDir(localTestingDir)
		assert.Nil(err)
		defer os.RemoveAll(localTestingDir)

		err = cryptography.SignPack(packThatDoesNotExist, "", pgpPrivateRSA, localTestingDir, version, false, false, false)
		assert.Equal(errs.ErrFileNotFound, err)
	})
	t.Run("test PGP signing a pack with wrong key passphrase", func(t *testing.T) {
		localTestingDir := "test-signing-pgp-wrong-passphrase"
		err := utils.EnsureDir(localTestingDir)
		assert.Nil(err)
		defer os.RemoveAll(localTestingDir)

		os.Setenv("TESTING_PASSPHRASE", "foo")
		err = cryptography.SignPack(packNotSigned, "", pgpPrivateRSA, localTestingDir, version, false, false, false)
		assert.NotNil(err)
		assert.Contains(err.Error(), "gopenpgp: error in unlocking sub key: openpgp: invalid data: private key checksum failure")
	})
}

func TestSignatureVerify(t *testing.T) {
	assert := assert.New(t)
	version := os.Getenv("VERSION")

	t.Run("verify X509 signed pack", func(t *testing.T) {
		err := cryptography.VerifyPackSignature(packSignedX509, x509Certificate, version, false, false, false)
		assert.Nil(err)
	})
	t.Run("verify PGP signed pack", func(t *testing.T) {
		err := cryptography.VerifyPackSignature(packSignedPGP, pgpPublicRSA, version, false, false, false)
		assert.Nil(err)
	})
}
