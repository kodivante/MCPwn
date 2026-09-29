package supplychain

import "strings"

var popularPackages = map[string][]string{
	"PyPI": {"requests", "numpy", "flask", "fastapi", "django", "pillow", "sqlalchemy", "pyyaml", "httpx", "aiohttp", "boto3", "celery", "redis", "pandas", "crypto", "cryptogr", "bcrypt"},
	"npm":  {"express", "lodash", "react", "axios", "chalk", "commander", "dotenv", "jsonwebtoken", "moment", "uuid", "typescript", "eslint", "webpack", "babel", "mocha", "ws"},
}

func looksTyposquat(name string) bool {
	if isPopular(name) {
		return false
	}
	return closestPopular(name) != ""
}

func closestPopular(name string) string {
	bestDistance := 2
	best := ""
	for _, group := range popularPackages {
		for _, candidate := range group {
			if candidate == name {
				return ""
			}
			distance := editDistance(strings.ToLower(name), candidate)
			if distance < bestDistance {
				bestDistance = distance
				best = candidate
			}
		}
	}
	if bestDistance > 1 || len(best) < 4 {
		return ""
	}
	return best
}

func isPopular(name string) bool {
	for _, group := range popularPackages {
		for _, candidate := range group {
			if strings.EqualFold(candidate, name) {
				return true
			}
		}
	}
	return false
}

func editDistance(a, b string) int {
	lengthA, lengthB := len(a), len(b)
	if lengthA == 0 {
		return lengthB
	}
	if lengthB == 0 {
		return lengthA
	}
	previous2 := make([]int, lengthB+1)
	previous := make([]int, lengthB+1)
	current := make([]int, lengthB+1)
	for j := 0; j <= lengthB; j++ {
		previous[j] = j
	}
	for i := 1; i <= lengthA; i++ {
		current[0] = i
		for j := 1; j <= lengthB; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = minInt(minInt(current[j-1]+1, previous[j]+1), previous[j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				current[j] = minInt(current[j], previous2[j-2]+1)
			}
		}
		previous2, previous, current = previous, current, previous2
	}
	return previous[lengthB]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
