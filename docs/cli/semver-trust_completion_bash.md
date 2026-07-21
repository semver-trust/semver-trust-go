## semver-trust completion bash

Generate the autocompletion script for bash

### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(semver-trust completion bash)

To load completions for every new session, execute once:

#### Linux:

	semver-trust completion bash > /etc/bash_completion.d/semver-trust

#### macOS:

	semver-trust completion bash > $(brew --prefix)/etc/bash_completion.d/semver-trust

You will need to start a new shell for this setup to take effect.


```
semver-trust completion bash
```

### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

### SEE ALSO

* [semver-trust completion](semver-trust_completion.md)	 - Generate the autocompletion script for the specified shell
