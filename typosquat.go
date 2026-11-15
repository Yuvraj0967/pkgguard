package pkgguard

import (
	"regexp"
	"strings"
)

// Well-known package names per ecosystem. A name one edit away from one of
// these (and not itself on the list) is a typosquat candidate. The list is a
// seed, not the whole registry: the registry lookup decides how worrying a
// candidate really is (age, existence).
var popularNames = map[string][]string{
	"npm": strings.Fields(`react react-dom react-router react-router-dom next vue nuxt angular svelte express koa fastify nestjs lodash underscore
		axios request node-fetch got superagent moment dayjs date-fns chalk commander yargs inquirer debug dotenv uuid async bluebird
		webpack vite rollup esbuild babel typescript eslint prettier jest mocha chai sinon vitest cypress puppeteer playwright
		mongoose mongodb sequelize prisma typeorm redis pg mysql mysql2 sqlite3 knex socket.io ws body-parser cors helmet morgan
		passport jsonwebtoken bcrypt bcryptjs cookie-parser multer nodemailer winston pino rxjs redux mobx zustand tailwindcss postcss
		autoprefixer sass less styled-components classnames prop-types immutable ramda cheerio jquery bootstrap three d3 chart.js
		glob rimraf mkdirp fs-extra semver minimist ora execa cross-env nodemon concurrently husky lint-staged zod joi yup ajv
		openai anthropic langchain firebase aws-sdk stripe graphql apollo-server @angular/core @babel/core @types/node`),
	"pypi": strings.Fields(`requests urllib3 numpy pandas scipy matplotlib seaborn scikit-learn tensorflow torch keras transformers pillow
		django flask fastapi uvicorn gunicorn pydantic sqlalchemy alembic psycopg2 psycopg2-binary pymysql redis celery boto3 botocore
		awscli click typer rich pytest tox black flake8 pylint mypy isort setuptools wheel pip virtualenv poetry pipenv
		beautifulsoup4 lxml scrapy selenium aiohttp httpx httplib2 certifi idna chardet charset-normalizer six python-dateutil pytz tzdata
		pyyaml toml tomli jinja2 markupsafe werkzeug cryptography pyopenssl paramiko pyjwt bcrypt passlib opencv-python tqdm colorama
		openai anthropic langchain jupyter ipython notebook sympy networkx nltk spacy gensim xgboost lightgbm joblib packaging attrs
		typing-extensions pyparsing decorator cffi pycparser grpcio protobuf google-api-python-client gitpython docker kubernetes
		fabric ansible pexpect psutil pyserial openpyxl xlrd xlsxwriter python-dotenv`),
	"crates.io": strings.Fields(`serde serde_json tokio rand clap regex reqwest hyper syn quote anyhow thiserror log env_logger chrono
		futures once_cell lazy_static rayon itertools bytes uuid tracing axum actix-web diesel sqlx openssl`),
}

// normalizeName canonicalises a package name for comparison.
func normalizeName(eco, name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	if eco == "pypi" {
		n = sepRun.ReplaceAllString(n, "-")
	}
	if eco == "crates.io" {
		n = strings.ReplaceAll(n, "_", "-")
	}
	return n
}

var sepRun = regexp.MustCompile(`[-_.]+`)

var popularSet = func() map[string]map[string]bool {
	m := map[string]map[string]bool{}
	for eco, names := range popularNames {
		m[eco] = map[string]bool{}
		for _, n := range names {
			m[eco][normalizeName(eco, n)] = true
		}
	}
	return m
}()

// typosquatOf returns the popular package that name imitates within one edit, or "".
func typosquatOf(eco, name string) string {
	p, d := typosquatMatch(eco, name)
	if d == 1 {
		return p
	}
	return ""
}

// typosquatMatch returns the closest popular package and the edit distance (1 or 2).
// Distance 2 is only considered for names of 7+ characters, where real typosquats
// often stack a transposition on a dropped letter; callers must confirm those
// with registry evidence (new or unused package) before flagging.
func typosquatMatch(eco, name string) (string, int) {
	list, ok := popularNames[eco]
	if !ok {
		return "", 0
	}
	n := normalizeName(eco, name)
	if popularSet[eco][n] || len(n) < 4 {
		return "", 0
	}
	bare := sepRun.ReplaceAllString(n, "")
	best, bestD := "", 3
	for _, p := range list {
		pn := normalizeName(eco, p)
		if len(pn) < 4 {
			continue
		}
		// same letters, different separators: reactdom vs react-dom
		if bare == sepRun.ReplaceAllString(pn, "") && n != pn {
			return p, 1
		}
		// scope impersonation: @evil/react looks like react
		if i := strings.LastIndex(n, "/"); i > 0 && n[i+1:] == pn {
			return p, 1
		}
		if absInt(len(n)-len(pn)) > 2 {
			continue
		}
		d := damerau(n, pn)
		if d == 1 {
			return p, 1
		}
		if d == 2 && len(pn) >= 7 && len(n) >= 7 && d < bestD {
			best, bestD = p, d
		}
	}
	if best != "" {
		return best, bestD
	}
	return "", 0
}

func absInt(a int) int {
	if a < 0 {
		return -a
	}
	return a
}

// damerau is the optimal-string-alignment edit distance (insert, delete,
// substitute, adjacent transposition).
func damerau(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := 0; j <= len(rb); j++ {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
