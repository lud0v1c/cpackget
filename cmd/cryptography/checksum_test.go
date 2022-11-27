package cryptography_test

import (
	"os"
	"testing"

	"github.com/open-cmsis-pack/cpackget/cmd/cryptography"
	"github.com/open-cmsis-pack/cpackget/cmd/utils"
	"github.com/stretchr/testify/assert"
)

func TestChecksumCreate(t *testing.T) {
	assert := assert.New(t)

	t.Run("test checksum creation", func(t *testing.T) {
		localTestingDir := "test-checksum-create"
		err := utils.EnsureDir(localTestingDir)
		assert.Nil(err)
		defer os.RemoveAll(localTestingDir)

		err = cryptography.GenerateChecksum(packNotSigned, localTestingDir, "sha256")
		assert.Nil(err)
	})
}

func TestChecksumVerify(t *testing.T) {
	assert := assert.New(t)

	t.Run("verify checksum", func(t *testing.T) {
		err := cryptography.VerifyChecksum(packNotSigned, packChecksum)
		assert.Nil(err)
	})
}
