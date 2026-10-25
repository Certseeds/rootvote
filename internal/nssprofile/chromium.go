package nssprofile

import "path/filepath"

func DiscoverChromium(dataDir string, extra []string) ([]Profile, []string, error) {
	var discovered []Profile
	if dataDir != "" {
		discovered = append(discovered, newProfile(AppChromium, filepath.Join(dataDir, "cert9.db")))
	}
	var explicit []Profile
	for _, db := range extra {
		explicit = append(explicit, newProfile(AppChromium, db))
	}
	return mergeExisting(discovered, explicit)
}
