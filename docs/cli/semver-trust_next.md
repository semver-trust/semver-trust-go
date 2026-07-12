## semver-trust next

Print the version that follows the latest tag (zero configuration)

### Synopsis

next increments the latest lenient-valid version by the given level with
node-semver semantics (the donor's increment). A repository with no valid
tags bootstraps from 0.0.0, so a fresh repo's first patch bump is 0.0.1;
--default seeds a different candidate. A trust-suffixed latest is refused
with guidance — a trust re-cut is a release operation (§7.2), not a bump.

```
semver-trust next [flags]
```

### Options

```
  -d, --default string[="0.0.0"]     seed version to add as a candidate when set (bare -d seeds 0.0.0)
  -h, --help                         help for next
  -i, --increment string[="patch"]   increment level: major, minor, patch, premajor, preminor, prepatch, or prerelease (use -i=level) (default "patch")
      --preid string                 identifier prefixing premajor, preminor, prepatch, or prerelease increments
      --repo string                  repository whose tags to inspect (default ".")
```

### SEE ALSO

* [semver-trust](semver-trust.md)	 - Provenance-scoped trust levels for semantic versioning

