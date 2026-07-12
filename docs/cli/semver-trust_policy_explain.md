## semver-trust policy explain

Print the decision table in effect (§6.4) and the policy summary

### Synopsis

explain renders the release decision machinery the policy configures: the
threshold and §6.3 strategy, the §6.4 default decision table Decide runs
(rows T0-T3 by blast score low/moderate/high), and the scope map, weights,
meta-paths, and derivation rules.

```
semver-trust policy explain [flags]
```

### Options

```
  -h, --help            help for explain
      --policy string   policy file path (relative to --repo unless absolute) (default ".semver-trust/policy.toml")
      --repo string     repository whose working tree holds the policy (default ".")
```

### SEE ALSO

* [semver-trust policy](semver-trust_policy.md)	 - Validate and explain the repository policy (§9)

