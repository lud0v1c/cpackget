/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Contributors to the cpackget project. */

package cryptography_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Copy of cmd/log.go
type LogFormatter struct{}

func (s *LogFormatter) Format(entry *log.Entry) ([]byte, error) {
	level := strings.ToUpper(entry.Level.String())
	msg := fmt.Sprintf("%s: %s\n", level[0:1], entry.Message)
	return []byte(msg), nil
}

var (
	// Available testing packs
	testDir = filepath.Join("..", "..", "testdata", "cryptography")

	packNotSigned        = filepath.Join(testDir, "TheVendor.UnsignedPack.1.2.3.pack")
	packSignedX509       = filepath.Join(testDir, "TheVendor.X509Pack.1.2.3.pack.signed")
	packSignedPGP        = filepath.Join(testDir, "TheVendor.PGPPack.1.2.3.pack.signed")
	packThatDoesNotExist = "ThisPack.DoesNotExist.0.0.1.pack"

	packChecksum = filepath.Join(testDir, "TheVendor.UnsignedPack.1.2.3.sha256.checksum")
	// Created with
	// $ openssl req -x509 -newkey rsa:3072 -keyout x509_private_rsa.pem -out x509_certificate.pem -nodes
	x509Certificate = filepath.Join(testDir, "certificate.pem")
	x509PrivateRSA  = filepath.Join(testDir, "private_rsa.pem")

	pgpPrivateRSA = filepath.Join(testDir, "private_rsa.pgp")
	pgpPublicRSA  = filepath.Join(testDir, "public_rsa.pgp")
)

func init() {
	logLevel := log.InfoLevel
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = log.DebugLevel
	}
	log.SetLevel(logLevel)
	log.SetFormatter(new(LogFormatter))
}
