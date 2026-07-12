## semver-trust policy validate

Parse the policy file and print its digest and summary

### Synopsis

validate loads the policy from the working tree, runs the strict §9 parser
(unknown keys and out-of-vocabulary values are errors — the config is the root
of trust, §5.4), and prints the digest and a summary. Parse errors are printed
verbatim and exit non-zero.

```
semver-trust policy validate [flags]
```

### Options

```
  -h, --help            help for validate
      --policy string   policy file path (relative to --repo unless absolute) (default ".semver-trust/policy.toml")
      --repo string     repository whose working tree holds the policy (default ".")
```

### SEE ALSO

* [semver-trust policy](semver-trust_policy.md)	 - Validate and explain the repository policy (§9)

