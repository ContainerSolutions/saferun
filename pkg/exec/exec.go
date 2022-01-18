package exec

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
)

func Run(command string) {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Env = MutateEnv(os.Environ())
	cmd.Run()
}

func MutateEnv(env []string) []string {
	ans := make([]string, len(env))
	re := regexp.MustCompile(`SAFE_RUN_.*=.*`)
	var nv string
	for _, v := range env {
		if re.MatchString(v) {
			kv := strings.Split(v, "=")
			kv[0] = strings.Replace(kv[0], "SAFE_RUN_", "", 1)
			kv[1] = env_decrypt(kv[1])
			nv = strings.Join(kv, "=")
		} else {
			nv = v
		}
		ans = append(ans, nv)
	}
	return ans
}
func env_decrypt(text string) string {
	return "mock-" + text
}
