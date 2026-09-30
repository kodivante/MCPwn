package taint

import "strings"

var sinkTable = map[string]string{
	"os.system":               "exec",
	"os.popen":                "exec",
	"subprocess.run":          "exec",
	"subprocess.Popen":        "exec",
	"subprocess.call":         "exec",
	"subprocess.check_output": "exec",
	"subprocess.check_call":   "exec",
	"eval":                    "exec",
	"exec":                    "exec",
	"execSync":                "exec",
	"spawn":                   "exec",
	"spawnSync":               "exec",
	"requests.get":            "network",
	"requests.post":           "network",
	"requests.put":            "network",
	"requests.delete":         "network",
	"requests.head":           "network",
	"urllib.request.urlopen":  "network",
	"urlopen":                 "network",
	"httpx.get":               "network",
	"httpx.post":              "network",
	"fetch":                   "network",
	"axios":                   "network",
	"axios.get":               "network",
	"axios.post":              "network",
	"open":                    "filesystem",
	"readFile":                "filesystem",
	"readFileSync":            "filesystem",
	"writeFile":               "filesystem",
	"writeFileSync":           "filesystem",
	"pickle.loads":            "deserialization",
	"pickle.load":             "deserialization",
	"marshal.loads":           "deserialization",
	"yaml.load":               "deserialization",
	"deserialize":             "deserialization",
	"cursor.execute":          "database",
	"conn.execute":            "database",
	"connection.execute":      "database",
	"db.execute":              "database",
	"query":                   "database",
}

func sinkClass(callee string) (string, bool) {
	parts := strings.Split(callee, ".")
	for index := range parts {
		candidate := strings.Join(parts[index:], ".")
		if class, ok := sinkTable[candidate]; ok {
			return class, true
		}
	}
	return "", false
}
