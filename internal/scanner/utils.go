package scanner

import (
	"vulnora/internal/core"
)

// convertLocationToEnum converts string location to VulnerabilityLocation enum
func convertLocationToEnum(location string) core.VulnerabilityLocation {
	switch location {
	case "url", "URL":
		return core.LocationURL
	case "header", "Header":
		return core.LocationHeader
	case "body", "Body":
		return core.LocationBody
	case "parameter", "Parameter":
		return core.LocationParameter
	case "cookie", "Cookie":
		return core.LocationCookie
	case "path", "Path":
		return core.LocationPath
	default:
		return core.LocationParameter
	}
}
