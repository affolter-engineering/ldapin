# ldapin

A CLI tool that discovers valid LDAP fields by querying an LDAP server's subschema. It reads `attributeTypes` and `objectClasses` directly from the server, so the results always reflect what the server actually supports.

## Features

- Lists all attribute types with OID, syntax, cardinality, aliases and description
- Lists all object classes with kind (structural/auxiliary/abstract), required/optional attributes and superclass chain
- Substring filter on name or description
- Three output formats: table, JSON, CSV
- Anonymous and authenticated (simple) bind
- Plain LDAP, LDAPS and STARTTLS

## Installation

### Nix (recommended)

```bash
# Run directly without installing
nix run github:your-user/ldapin

# Or build and link into ./result/bin/ldapin
nix build github:your-user/ldapin
```

From a local checkout:

```bash
nix run .
nix build .
```

### Cargo

```bash
cargo install --path .
```

Requires OpenSSL development headers and `pkg-config` at build time.

## Usage

```text
ldapin [OPTIONS]

Options:
  -H, --host <HOST>           LDAP server URL [default: ldap://localhost:389]
  -D, --bind-dn <BIND_DN>     Bind DN (omit for anonymous bind)
  -w, --password <PASSWORD>   Bind password
  -W, --prompt-password       Prompt for bind password interactively
  -f, --filter <FILTER>       Substring filter on name or description
  -c, --object-class <NAME>   Limit to a specific object class (with -m object-classes)
  -m, --mode <MODE>           What to show: attributes, object-classes, both [default: attributes]
  -o, --output <OUTPUT>       Output format: table, json, csv [default: table]
      --starttls              Upgrade connection with STARTTLS
      --insecure              Skip TLS certificate verification
  -h, --help                  Print help
  -V, --version               Print version
```

### Examples

List all attribute types on a local server:

```bash
ldapin
```

Authenticate and list all object classes:

```bash
ldapin -H ldap://ldap.example.org -D 'cn=admin,dc=example,dc=org' -W -m object-classes
```

Find all attributes related to mail:

```bash
ldapin -H ldap://ldap.example.org -f mail
```

Show everything in JSON:

```bash
ldapin -H ldaps://ldap.example.org -m both -o json
```

Export all attributes to CSV:

```bash
ldapin -H ldap://ldap.example.org -o csv > attributes.csv
```

Show the `inetOrgPerson` object class entry:

```bash
ldapin -H ldap://ldap.example.org -m object-classes -c inetOrgPerson
```

Connect with STARTTLS:

```bash
ldapin -H ldap://ldap.example.org --starttls -D 'cn=admin,dc=example,dc=org' -W
```

## Testing with the ForumSys public LDAP server

[ForumSys](https://www.forumsys.com/2022/05/10/online-ldap-test-server/) provides a free, read-only LDAP server suitable for testing.

| Parameter | Value |
|---|---|
| Host | `ldap.forumsys.com` |
| Port | `389` |
| Bind DN | `cn=read-only-admin,dc=example,dc=com` |
| Password | `password` |
| Base DN | `dc=example,dc=com` |

List all attribute types (anonymous bind):

```bash
ldapin -H ldap://ldap.forumsys.com
```

List all attribute types (authenticated):

```bash
ldapin -H ldap://ldap.forumsys.com -D 'cn=read-only-admin,dc=example,dc=com' -w password
```

List all object classes:

```bash
ldapin -H ldap://ldap.forumsys.com -m object-classes
```

Show the `inetOrgPerson` object class:

```bash
ldapin -H ldap://ldap.forumsys.com -m object-classes -c inetOrgPerson
```

Filter attributes by name:

```bash
ldapin -H ldap://ldap.forumsys.com -f mail
```

Export everything to JSON:

```bash
ldapin -H ldap://ldap.forumsys.com -m both -o json
```

## Development

Enter a shell with Rust tooling, rust-analyzer, rustfmt and clippy:

```bash
nix develop
```

Then build and run normally:

```bash
cargo build
cargo run -- --help
```

## Autor

- Fabian Affolter (@fabaff)

## License

MIT
