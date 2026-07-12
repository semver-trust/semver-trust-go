## semver-trust list

List the repository's tags as versions (zero configuration)

### Synopsis

list enumerates the repository's git tags and prints each with its parsed
form, sorted ascending by SemVer precedence. The default view is lenient
(donor parity): short and v-less forms are coerced (2.1 -> 2.1.0), build
metadata is tolerated and flagged as out of grammar (§7.1), and invalid tags —
including malformed trust shapes, which fail closed — are listed with their
reason rather than silently dropped. --strict shows only §7.1-valid tags.

```
semver-trust list [flags]
```

### Options

```
  -h, --help          help for list
      --repo string   repository whose tags to list (default ".")
      --strict        only §7.1-valid tags, in canonical tag form
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning

