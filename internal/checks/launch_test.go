package checks

import "testing"

func TestStripFlags(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"listen with address",
			`python main.py --listen 0.0.0.0 --windows-standalone-build`,
			`python main.py --windows-standalone-build`,
		},
		{
			// The flag sits immediately after a quote, with no space before it.
			"flags inside a quoted argument string",
			`export COMMANDLINE_ARGS="--listen --share --xformers --api"`,
			`export COMMANDLINE_ARGS="--xformers --api"`,
		},
		{
			"share alone",
			`./webui.sh --share`,
			`./webui.sh`,
		},
		{
			"bare listen without an address",
			`python main.py --listen --port 8188`,
			`python main.py --port 8188`,
		},
		{
			"host wildcard",
			`uvicorn app:api --host 0.0.0.0 --port 8000`,
			`uvicorn app:api --port 8000`,
		},
		{
			// A deliberate specific bind address is the user's decision, not ours.
			"specific host is left alone",
			`uvicorn app:api --host 192.168.1.5 --port 8000`,
			`uvicorn app:api --host 192.168.1.5 --port 8000`,
		},
		{
			"nothing to strip",
			`python main.py --port 8188 --cpu`,
			`python main.py --port 8188 --cpu`,
		},
		{
			// --listen-only-safe must not be mistaken for --listen.
			"similar flag names are not touched",
			`python main.py --listen-timeout 30 --sharemem`,
			`python main.py --listen-timeout 30 --sharemem`,
		},
		{
			"equals form",
			`python main.py --server-name=0.0.0.0 --port=7860`,
			`python main.py --port=7860`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stripFlags(c.in); got != c.want {
				t.Errorf("stripFlags(%q)\n got %q\nwant %q", c.in, got, c.want)
			}
		})
	}
}
