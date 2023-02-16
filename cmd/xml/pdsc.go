/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Contributors to the cpackget project. */

package xml

import (
	"encoding/xml"

	"github.com/open-cmsis-pack/cpackget/cmd/utils"
	log "github.com/sirupsen/logrus"
)

// PdscXML maps few tags of a PDSC file.
// Ref: https://github.com/Open-CMSIS-Pack/Open-CMSIS-Pack-Spec/blob/main/schema/PACK.xsd
type PdscXML struct {
	XMLName xml.Name `xml:"package"`
	Vendor  string   `xml:"vendor"`
	URL     string   `xml:"url"`
	Name    string   `xml:"name"`
	License string   `xml:"license"`

	ReleasesTag struct {
		XMLName  xml.Name     `xml:"releases"`
		Releases []ReleaseTag `xml:"release"`
	} `xml:"releases"`

	RequirementsTag struct {
		XMLName  xml.Name      `xml:"requirements"`
		Packages []PackagesTag `xml:"packages"`
	} `xml:"requirements"`

	FileName string
}

// ReleaseTag maps the <release> tag of a PDSC file.
type ReleaseTag struct {
	XMLName xml.Name `xml:"release"`
	Version string   `xml:"version,attr"`
	Date    string   `xml:"Date,attr"`
	URL     string   `xml:"url,attr"`
}

// PackagesTag only has one possible child, which is <package>
type PackagesTag struct {
	XMLName  xml.Name     `xml:"packages"`
	Packages []PackageTag `xml:"package"`
}

// Package represents a direct dependency/requirement of this package
type PackageTag struct {
	XMLName xml.Name `xml:"package"`
	Vendor  string   `xml:"vendor,attr"`
	Name    string   `xml:"name,attr"`
	Version string   `xml:"version,attr"`
}

// NewPdscXML receives a PDSC file name to be later read into the PdscXML struct
func NewPdscXML(fileName string) *PdscXML {
	log.Debugf("Initializing PdscXML object for \"%s\"", fileName)
	p := new(PdscXML)
	p.FileName = fileName
	return p
}

// LatestVersion returns a string containing version of the first tag within
// the <releases> tag.
func (p *PdscXML) LatestVersion() string {
	releases := p.ReleasesTag.Releases
	if len(releases) > 0 {
		return releases[0].Version
	}
	return ""
}

// AllReleases returns a slice of strings containing all available releases in this Pdsc file
func (p *PdscXML) AllReleases() []string {
	allReleases := []string{}
	if len(p.ReleasesTag.Releases) > 0 {
		for _, releaseTag := range p.ReleasesTag.Releases {
			allReleases = append(allReleases, releaseTag.Version)
		}
	}

	return allReleases
}

// FindReleaseTagByVersion iterates over the PDSC file's releases tag and returns
// the release that matching version.
func (p *PdscXML) FindReleaseTagByVersion(version string) *ReleaseTag {
	releases := p.ReleasesTag.Releases
	if len(releases) > 0 {
		if version == "" {
			return &releases[0]
		}

		for _, releaseTag := range releases {
			if releaseTag.Version == version {
				return &releaseTag
			}
		}
	}
	return nil
}

// Tag returns a PdscTag representation of a PDSC file.
func (p *PdscXML) Tag() PdscTag {
	return PdscTag{
		Vendor:  p.Vendor,
		URL:     p.URL,
		Name:    p.Name,
		Version: p.LatestVersion(),
	}
}

// Read reads the PDSC file specified in p.FileName into the PdscXML struct
func (p *PdscXML) Read() error {
	log.Debugf("Reading pdsc from file \"%s\"", p.FileName)
	return utils.ReadXML(p.FileName, p)
}

// PackURL returns a url for the Pack described in this PDSC file
func (p *PdscXML) PackURL(version string) string {
	baseURL := p.URL
	lenBaseURL := len(baseURL)
	if lenBaseURL > 0 && baseURL[len(baseURL)-1] != '/' {
		baseURL += "/"
	}

	if version == "" {
		version = p.LatestVersion()
	}

	return baseURL + p.Vendor + "." + p.Name + "." + version + ".pack"
}

// Dependencies returns all the listed packs that need to be installed
// alongside, as per the <requirements> section. It returns a [][]string
// array containing the packs in [<Name>, <Vendor>, <Version>] format.
func (p *PdscXML) Dependencies() [][]string {
	dependencies := [][]string{}
	if p.RequirementsTag.Packages == nil {
		return nil
	}
	for i, pack := range p.RequirementsTag.Packages {
		for _, pk := range pack.Packages {
			dependencies = append(dependencies, []string{pk.Name, pk.Vendor, pk.Version})
			log.Debugf("found %v dependency", dependencies[i])
		}
	}
	return dependencies
}
