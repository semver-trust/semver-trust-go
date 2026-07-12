## semver-trust latest

Print the highest version among the repository's tags (zero configuration)

### Synopsis

latest picks the SemVer-precedence maximum of the lenient-valid tag set the
donor accepted. Trust-suffixed tags participate in the selection (a trust
pre-release above every clean tag IS the repository's newest release); invalid
tags are ignored with a count on stderr, never silently.

```
semver-trust latest [flags]
```

### Options

```
  -h, --help          help for latest
      --repo string   repository whose tags to inspect (default ".")
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning

