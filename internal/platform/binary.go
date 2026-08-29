package platform

import "runtime"

// InstalledName is the filename gitshield uses when copied onto PATH.
func InstalledName() string {
	if runtime.GOOS == "windows" {
		return "gitshield.exe"
	}
	return "gitshield"
}

// ReleaseBinaryName is the executable name inside a release archive.
func ReleaseBinaryName(goos, goarch string) string {
	name := "gitshield-" + goos + "-" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// ReleaseArchiveName is the downloadable release archive for goos/goarch.
func ReleaseArchiveName(goos, goarch string) string {
	base := "gitshield-" + goos + "-" + goarch
	if goos == "windows" {
		return base + ".zip"
	}
	return base + ".tar.gz"
}
