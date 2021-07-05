package cli

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Root command (entrypoint) of the CLI.
var Root *cobra.Command

// GlobalFlags contains all the fixed up front flags
// This allows us to parse them before we hand over control
// to cobra
var GlobalFlags *pflag.FlagSet

// Cache is used to store temporary data between runs.
var Cache *viper.Viper

// Formatter is the currently configured response output formatter.
var Formatter ResponseFormatter

// Stdout is a cross-platform, color-safe writer if colors are enabled,
// otherwise it defaults to `os.Stdout`.
var Stdout io.Writer = os.Stdout

// Stderr is a cross-platform, color-safe writer if colors are enabled,
// otherwise it defaults to `os.Stderr`.
var Stderr io.Writer = os.Stderr

// Ugh, see https://github.com/spf13/cobra/issues/836
var usageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if (not .Parent)}}{{if (gt (len .Commands) 9)}}

Available API Commands:{{range .Commands}}{{if (not (or (eq .Name "help") (eq .Name "get") (eq .Name "put") (eq .Name "post") (eq .Name "patch") (eq .Name "delete") (eq .Name "head") (eq .Name "options") (eq .Name "cert") (eq .Name "api") (eq .Name "links")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Generic Commands:{{range .Commands}}{{if (or (eq .Name "help") (eq .Name "get") (eq .Name "put") (eq .Name "post") (eq .Name "patch") (eq .Name "delete") (eq .Name "head") (eq .Name "options") (eq .Name "cert") (eq .Name "api") (eq .Name "links"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{else}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

var tty bool
var au aurora.Aurora

func generic(method string, addr string, args []string) {
	var body io.Reader

	d, err := GetBody("application/json", args)
	if err != nil {
		panic(err)
	}
	if len(d) > 0 {
		body = strings.NewReader(d)
	}

	req, _ := http.NewRequest(method, fixAddress(addr), body)
	MakeRequestAndFormat(req)
}

// Init will set up the CLI.
func Init(name string, version string) {
	initConfig(name, "")
	initCache(name)

	// Reset registries.
	authHandlers = map[string]AuthHandler{}
	contentTypes = []contentTypeEntry{}
	encodings = map[string]ContentEncoding{}
	linkParsers = []LinkParser{}
	loaders = []Loader{}

	// Determine if we are using a TTY or colored output is forced-on.
	tty = false
	if isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd()) || viper.GetBool("color") {
		tty = true
	}

	if viper.GetBool("nocolor") {
		// If forced off, ignore all of the above!
		tty = false
	}

	if tty {
		// Support colored output across operating systems.
		Stdout = colorable.NewColorableStdout()
		Stderr = colorable.NewColorableStderr()
	}

	au = aurora.NewAurora(tty)

	Formatter = NewDefaultFormatter(tty)

	Root = &cobra.Command{
		Use:     filepath.Base(os.Args[0]),
		Long:    "A generic client for REST-ish APIs <https://rest.sh/>",
		Version: version,
		Example: fmt.Sprintf(`  # Get a URI
  $ %s google.com

  # Specify verb, header, and body shorthand
  $ %s post :8888/users -H authorization:abc123 name: Kari, role: admin`, name, name),
		Args: cobra.MinimumNArgs(1),
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			settings := viper.AllSettings()
			LogDebug("Configuration: %v", settings)
		},
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodGet, args[0], args[1:])
		},
	}
	Root.SetUsageTemplate(usageTemplate)

	head := &cobra.Command{
		Use:   "head uri",
		Short: "Head a URI",
		Long:  "Perform an HTTP HEAD on the given URI",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodHead, args[0], args[1:])
		},
	}
	Root.AddCommand(head)

	options := &cobra.Command{
		Use:   "options uri",
		Short: "Options a URI",
		Long:  "Perform an HTTP OPTIONS on the given URI",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodOptions, args[0], args[1:])
		},
	}
	Root.AddCommand(options)

	get := &cobra.Command{
		Use:   "get uri",
		Short: "Get a URI",
		Long:  "Perform an HTTP GET on the given URI",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodGet, args[0], args[1:])
		},
	}
	Root.AddCommand(get)

	post := &cobra.Command{
		Use:   "post uri [body...]",
		Short: "Post a URI",
		Long:  "Perform an HTTP POST on the given URI",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodPost, args[0], args[1:])
		},
	}
	Root.AddCommand(post)

	put := &cobra.Command{
		Use:   "put uri [body...]",
		Short: "Put a URI",
		Long:  "Perform an HTTP PUT on the given URI",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodPut, args[0], args[1:])
		},
	}
	Root.AddCommand(put)

	patch := &cobra.Command{
		Use:   "patch uri [body...]",
		Short: "Patch a URI",
		Long:  "Perform an HTTP PATCH on the given URI",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodPatch, args[0], args[1:])
		},
	}
	Root.AddCommand(patch)

	delete := &cobra.Command{
		Use:   "delete uri [body...]",
		Short: "Delete a URI",
		Long:  "Perform an HTTP DELETE on the given URI",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			generic(http.MethodDelete, args[0], args[1:])
		},
	}
	Root.AddCommand(delete)

	cert := &cobra.Command{
		Use:   "cert uri",
		Short: "Get cert info",
		Long:  "Get TLS certificate information including expiration date",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			addr := args[0]

			if !strings.Contains(addr, ":") {
				addr += ":443"
			}

			conn, err := tls.Dial("tcp", addr, nil)
			if err != nil {
				panic(err)
			}

			chains := conn.ConnectionState().VerifiedChains
			if chains != nil && len(chains) > 0 && len(chains[0]) > 0 {
				// The first cert in the first chain should represent the domain.
				c := chains[0][0]

				expiresRelative := ""
				days := c.NotAfter.Sub(time.Now()).Hours() / 24
				if days > 0 {
					expiresRelative = fmt.Sprintf("in %.1f days", days)
				} else {
					expiresRelative = fmt.Sprintf("%.1f days ago", -days)
				}

				info := fmt.Sprintf(`Issuer: %s
Subject: %s
Signature Algorithm: %s
Not before: %s
Not after (expires): %s (%s)
`, c.Issuer.String(), c.Subject.String(), c.SignatureAlgorithm.String(), c.NotBefore.String(), c.NotAfter.String(), expiresRelative)

				if len(c.DNSNames) > 0 {
					info += "DNS names:\n  " + strings.Join(c.DNSNames, "\n  ") + "\n"
				}

				fmt.Print(info)
			}
		},
	}
	Root.AddCommand(cert)

	linkCmd := &cobra.Command{
		Use:   "links uri [rel1 rel2...]",
		Short: "Get link relations from the given URI, with optional filtering",
		Long:  "Returns a list of resolved references to the link relations after making an HTTP GET request to the given URI. Additional arguments filter down the set of returned relationship names.",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			req, _ := http.NewRequest(http.MethodGet, fixAddress(args[0]), nil)
			resp, err := GetParsedResponse(req)
			if err != nil {
				panic(err)
			}

			var output interface{} = resp.Links

			if len(args) > 1 {
				tmp := []*Link{}
				for _, rel := range args[1:] {
					for _, link := range resp.Links[rel] {
						tmp = append(tmp, link)
					}
				}
				output = tmp
			}

			encoded, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				panic(err)
			}

			if tty {
				encoded, err = Highlight("json", encoded)
				if err != nil {
					panic(err)
				}
			}

			fmt.Fprintln(Stdout, string(encoded))
		},
	}
	Root.AddCommand(linkCmd)

	GlobalFlags = pflag.NewFlagSet("eager-flags", pflag.ContinueOnError)
	GlobalFlags.ParseErrorsWhitelist.UnknownFlags = true
	// GlobalFlags are 'hidden', don't print anything on error
	GlobalFlags.Usage = func() {}
	// Ensure parsing doesn't stop if the help flag is set
	// (help seems to be special cased from ParseErrorsWhitelist.UnknownFlags)
	GlobalFlags.BoolP("help", "h", false, "")

	AddGlobalFlag("rsh-verbose", "v", "Enable verbose log output", false, false)
	AddGlobalFlag("rsh-output-format", "o", "Output format [auto, json, yaml]", "auto", false)
	AddGlobalFlag("rsh-filter", "f", "Filter / project results using JMESPath Plus", "", false)
	AddGlobalFlag("rsh-raw", "r", "Output result of query as raw rather than an escaped JSON string or list", false, false)
	AddGlobalFlag("rsh-server", "s", "Override scheme://server:port for an API", "", false)
	AddGlobalFlag("rsh-header", "H", "Add custom header", []string{}, true)
	AddGlobalFlag("rsh-query", "q", "Add custom query param", []string{}, true)
	AddGlobalFlag("rsh-no-paginate", "", "Disable auto-pagination", false, false)
	AddGlobalFlag("rsh-profile", "p", "API auth profile", "default", false)
	AddGlobalFlag("rsh-no-cache", "", "Disable HTTP cache", false, false)
	AddGlobalFlag("rsh-insecure", "", "Disable SSL verification", false, false)
	AddGlobalFlag("rsh-client-cert", "", "Path to a PEM encoded client certificate", "", false)
	AddGlobalFlag("rsh-client-key", "", "Path to a PEM encoded private key", "", false)
	AddGlobalFlag("rsh-ca-cert", "", "Path to a PEM encoded CA cert", "", false)
	AddGlobalFlag("rsh-table", "t", "Enable table formatted output for array of objects", false, false)

	initAPIConfig()
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func cacheDir() string {
	return path.Join(userHomeDir(), "."+viper.GetString("app-name"))
}

func initConfig(appName, envPrefix string) {
	// One-time setup to ensure the path exists so we can write files into it
	// later as needed.
	configDir := path.Join(userHomeDir(), "."+appName)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		panic(err)
	}

	// Load configuration from file(s) if provided.
	viper.SetConfigName("config")
	viper.AddConfigPath("/etc/" + appName + "/")
	viper.AddConfigPath("$HOME/." + appName + "/")
	viper.ReadInConfig()

	// Load configuration from the environment if provided. Flags below get
	// transformed automatically, e.g. `client-id` -> `PREFIX_CLIENT_ID`.
	viper.SetEnvPrefix(envPrefix)
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	// Save a few things that will be useful elsewhere.
	viper.Set("app-name", appName)
	viper.Set("config-directory", configDir)
	viper.SetDefault("server-index", 0)
}

func initCache(appName string) {
	Cache = viper.New()
	Cache.SetConfigName("cache")
	Cache.AddConfigPath("$HOME/." + appName + "/")

	// Write a blank cache if no file is already there. Later you can use
	// cli.Cache.SaveConfig() to write new values.
	filename := path.Join(viper.GetString("config-directory"), "cache.json")
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		if err := ioutil.WriteFile(filename, []byte("{}"), 0600); err != nil {
			panic(err)
		}
	}

	Cache.ReadInConfig()
}

// Defaults adds the default encodings, content types, and link parsers to
// the CLI.
func Defaults() {
	// Register content encodings
	AddEncoding("gzip", &GzipEncoding{})
	AddEncoding("br", &BrotliEncoding{})

	// Register content type marshallers
	AddContentType("application/cbor", 0.9, &CBOR{})
	AddContentType("application/msgpack", 0.8, &MsgPack{})
	AddContentType("application/ion", 0.6, &Ion{})
	AddContentType("application/json", 0.5, &JSON{})
	AddContentType("application/yaml", 0.5, &YAML{})
	AddContentType("text/*", 0.2, &Text{})

	// Add link relation parsers
	AddLinkParser(&LinkHeaderParser{})
	AddLinkParser(&HALParser{})
	AddLinkParser(&TerrificallySimpleJSONParser{})
	AddLinkParser(&JSONAPIParser{})

	// Register auth schemes
	AddAuth("http-basic", &BasicAuth{})
	AddAuth("api-key-header", &ApiKeyHeaderFromShellAuth{})
}

// Run the CLI! Parse arguments, make requests, print responses.
func Run() {
	// We need to register new commands at runtime based on the selected API
	// so that we don't have to potentially refresh and parse every single
	// registered API just to run. So this is a little hacky, but we hijack
	// the input args to find non-option arguments, get the first arg, and
	// if it isn't from a well-known set try to load that API.
	args := []string{}
	for _, arg := range os.Args {
		if !strings.HasPrefix(arg, "-") {
			args = append(args, arg)
		}
	}

	// Because we may be doing HTTP calls before cobra has parsed the flags
	// we parse the GlobalFlags here and already set some config values
	// to ensure they are available
	if err := GlobalFlags.Parse(os.Args[1:]); err != nil {
		if err != pflag.ErrHelp {
			panic(err)
		}
	}
	if verbose, _ := GlobalFlags.GetBool("rsh-verbose"); verbose {
		viper.Set("rsh-verbose", true)
	}
	if insecure, _ := GlobalFlags.GetBool("rsh-insecure"); insecure {
		viper.Set("rsh-insecure", true)
	}
	if cert, _ := GlobalFlags.GetString("rsh-client-cert"); cert != "" {
		viper.Set("rsh-client-cert", cert)
	}
	if key, _ := GlobalFlags.GetString("rsh-client-key"); key != "" {
		viper.Set("rsh-client-key", key)
	}
	if caCert, _ := GlobalFlags.GetString("rsh-ca-cert"); caCert != "" {
		viper.Set("rsh-ca-cert", caCert)
	}
	if query, _ := GlobalFlags.GetStringSlice("rsh-query"); len(query) > 0 {
		viper.Set("rsh-query", query)
	}
	if headers, _ := GlobalFlags.GetStringSlice("rsh-header"); len(headers) > 0 {
		viper.Set("rsh-header", headers)
	}

	// Now that global flags are parsed we can enable verbose mode if requested.
	if viper.GetBool("rsh-verbose") {
		enableVerbose = true
	}

	// Load the API commands if we can.
	if len(args) > 1 {
		apiName := args[1]

		if apiName == "help" && len(args) > 2 {
			// The explicit `help` command is followed by the actual commands
			// you want help with. The first one is the API name.
			apiName = args[2]
		}

		if apiName != "help" && apiName != "head" && apiName != "options" && apiName != "get" && apiName != "post" && apiName != "put" && apiName != "patch" && apiName != "delete" && apiName != "api" && apiName != "links" {
			// Try to find the registered config for this API. If not found,
			// there is no need to do anything since the normal flow will catch
			// the command being missing and print help.
			if cfg, ok := configs[apiName]; ok {
				for _, cmd := range Root.Commands() {
					if cmd.Use == apiName {
						if _, err := Load(cfg.Base, cmd); err != nil {
							panic(err)
						}
						break
					}
				}
			}
		}
	}

	// Phew, we made it. Execute the command now that everything is loaded
	// and all the relevant sub-commands are registered.
	defer func() {
		if err := recover(); err != nil {
			LogError("Caught error: %v", err)
			LogDebug("%s", string(debug.Stack()))
		}
	}()
	if err := Root.Execute(); err != nil {
		LogError("Error: %v", err)
	}
}
