package commons

import (
	"encoding/json"
	"fmt"
	"runtime"
)

var (
	serviceVersion string
	gitCommit      string
	buildDate      string
)

// VersionInfo object contains version related info
type VersionInfo struct {
	ServiceVersion string `json:"serviceVersion"`
	GitCommit      string `json:"gitCommit"`
	BuildDate      string `json:"buildDate"`
	GoVersion      string `json:"goVersion"`
	Compiler       string `json:"compiler"`
	Platform       string `json:"platform"`
}

// GetVersion returns VersionInfo object
func GetVersion() VersionInfo {
	return VersionInfo{
		ServiceVersion: serviceVersion,
		GitCommit:      gitCommit,
		BuildDate:      buildDate,
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

// GetServiceVersion returns service version in string
func GetServiceVersion() string {
	return serviceVersion
}

// GetVersionJSON returns VersionInfo object in JSON string
func GetVersionJSON() (string, error) {
	info := GetVersion()
	marshalled, err := json.MarshalIndent(&info, "", "  ")
	if err != nil {
		return "", err
	}
	return string(marshalled), nil
}
