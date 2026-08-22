use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

use crate::json::JsonValue;
use crate::release::governance::{
    TomlDocument, boolean, member, quoted, require_identifier, require_keys, string_array,
};
use crate::release::manifest::{read_regular, write_json_new};
use crate::release::schema::{number, object, string};

const MAX_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_SOURCE_FILES: usize = 4096;
const MAX_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Clone, Debug)]
struct Policy {
    id: String,
    deny_broad_allow: bool,
    capabilities: Vec<Capability>,
    compile_time_names: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct Capability {
    id: String,
    crate_name: String,
    item: String,
    methods: BTreeSet<String>,
    reason: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Site {
    capability_id: String,
    crate_name: String,
    file: String,
    item: String,
    method: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Violation {
    code: &'static str,
    file: String,
    item: String,
    message: String,
}

pub(crate) fn recognizes(arguments: &[OsString]) -> bool {
    arguments.first().is_some_and(|value| value == "policy")
        && arguments
            .get(1)
            .is_some_and(|value| value == "rust-capabilities")
}

pub(crate) fn run(arguments: &[OsString]) -> Result<String, String> {
    let options = Options::parse(&arguments[2..])?;
    let repository_root = options
        .repository_root
        .ok_or_else(|| "rust-capabilities requires --repository-root".to_owned())?;
    let policy_path = options
        .policy
        .ok_or_else(|| "rust-capabilities requires --policy".to_owned())?;
    let output = options
        .output
        .ok_or_else(|| "rust-capabilities requires --output".to_owned())?;
    let policy = Policy::read(&policy_path)?;
    let result = audit(&repository_root, &policy);
    let (sites, violations, files_scanned) = match &result {
        Ok(result) => (&result.sites, &result.violations, result.files_scanned),
        Err(failure) => (&failure.sites, &failure.violations, failure.files_scanned),
    };
    let admitted = violations.is_empty();
    let diagnostic = violations.first().map_or(JsonValue::Null, |violation| {
        object([
            ("code", string(violation.code)),
            ("message", string(&bounded(&violation.message))),
        ])
    });
    let report = object([
        ("admitted", JsonValue::Bool(admitted)),
        ("diagnostic", diagnostic),
        ("filesScanned", number(files_scanned as u64)),
        ("policyId", string(&policy.id)),
        ("schemaVersion", number(1)),
        (
            "sites",
            JsonValue::Array(sites.iter().map(Site::json).collect()),
        ),
        (
            "state",
            string(if admitted { "audited" } else { "rejected" }),
        ),
        (
            "violations",
            JsonValue::Array(violations.iter().map(Violation::json).collect()),
        ),
    ]);
    write_json_new(&output, &report)?;
    if admitted {
        Ok(format!(
            "audited {files_scanned} Rust files and {} capability sites",
            sites.len()
        ))
    } else {
        let first = violations.first().expect("nonempty rejected violations");
        Err(format!("{}: {}", first.code, first.message))
    }
}

struct AuditResult {
    files_scanned: usize,
    sites: Vec<Site>,
    violations: Vec<Violation>,
}

struct AuditFailure {
    files_scanned: usize,
    sites: Vec<Site>,
    violations: Vec<Violation>,
}

fn audit(repository_root: &Path, policy: &Policy) -> Result<AuditResult, AuditFailure> {
    let mut files = Vec::new();
    let crate_names = policy
        .capabilities
        .iter()
        .map(|capability| capability.crate_name.as_str())
        .collect::<BTreeSet<_>>();
    for crate_name in crate_names {
        let crate_root = repository_root.join("crates").join(crate_name);
        let source_root = crate_root.join("src");
        if let Err(message) = collect_rust_files(&source_root, &mut files) {
            return Err(single_failure(
                files.len(),
                "capability.source.inventory",
                crate_name,
                message,
            ));
        }
    }
    files.sort();
    if files.len() > MAX_SOURCE_FILES {
        return Err(single_failure(
            files.len(),
            "capability.source.oversize",
            "repository",
            "Rust source inventory exceeds the file limit".to_owned(),
        ));
    }
    let mut parsed = Vec::new();
    for file in &files {
        let bytes = match read_bounded_source(file) {
            Ok(bytes) => bytes,
            Err(message) => {
                return Err(single_failure(
                    parsed.len(),
                    "capability.source.input",
                    &relative(repository_root, file),
                    message,
                ));
            }
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            return Err(single_failure(
                parsed.len(),
                "capability.source.utf8",
                &relative(repository_root, file),
                "Rust source is not UTF-8".to_owned(),
            ));
        };
        let syntax = match syn::parse_file(text) {
            Ok(syntax) => syntax,
            Err(error) => {
                return Err(single_failure(
                    parsed.len(),
                    "capability.source.syntax",
                    &relative(repository_root, file),
                    format!("cannot parse Rust syntax: {error}"),
                ));
            }
        };
        parsed.push((file.clone(), syntax));
    }
    let mut sites = BTreeSet::new();
    let mut violations = BTreeSet::new();
    for (file, syntax) in &parsed {
        let crate_name = crate_name(repository_root, file).unwrap_or("unknown");
        let module = module_path(repository_root, file, crate_name);
        let mut visitor =
            CapabilityVisitor::new(policy, crate_name, relative(repository_root, file), module);
        visitor.visit_file(syntax);
        sites.extend(visitor.sites);
        violations.extend(visitor.violations);
    }
    for capability in &policy.capabilities {
        if !sites.iter().any(|site| site.capability_id == capability.id) {
            violations.insert(Violation {
                code: "capability.site.missing",
                file: capability.crate_name.clone(),
                item: capability.item.clone(),
                message: format!("approved capability site {} is absent", capability.id),
            });
        }
    }
    let mut violations = violations.into_iter().collect::<Vec<_>>();
    violations.sort_by(|left, right| {
        left.priority()
            .cmp(&right.priority())
            .then_with(|| left.cmp(right))
    });
    let result = AuditResult {
        files_scanned: parsed.len(),
        sites: sites.into_iter().collect(),
        violations,
    };
    Ok(result)
}

fn single_failure(
    files_scanned: usize,
    code: &'static str,
    file: &str,
    message: String,
) -> AuditFailure {
    AuditFailure {
        files_scanned,
        sites: Vec::new(),
        violations: vec![Violation {
            code,
            file: file.to_owned(),
            item: String::new(),
            message,
        }],
    }
}

struct CapabilityVisitor<'a> {
    aliases: BTreeMap<String, Vec<String>>,
    crate_name: &'a str,
    file: String,
    item: Vec<String>,
    policy: &'a Policy,
    sites: BTreeSet<Site>,
    violations: BTreeSet<Violation>,
}

impl<'a> CapabilityVisitor<'a> {
    fn new(policy: &'a Policy, crate_name: &'a str, file: String, module: Vec<String>) -> Self {
        Self {
            aliases: BTreeMap::new(),
            crate_name,
            file,
            item: module,
            policy,
            sites: BTreeSet::new(),
            violations: BTreeSet::new(),
        }
    }

    fn item_path(&self) -> String {
        self.item.join("::")
    }

    fn enter(&mut self, component: String, operation: impl FnOnce(&mut Self)) {
        self.item.push(component);
        operation(self);
        self.item.pop();
    }

    fn inspect_access(&mut self, method: String) {
        let item = self.item_path();
        if let Some(capability) = self.policy.capabilities.iter().find(|capability| {
            capability.crate_name == self.crate_name
                && capability.item == item
                && capability.methods.contains(&method)
        }) {
            self.sites.insert(Site {
                capability_id: capability.id.clone(),
                crate_name: self.crate_name.to_owned(),
                file: self.file.clone(),
                item,
                method,
            });
        } else {
            self.violations.insert(Violation {
                code: "capability.access.unapproved",
                file: self.file.clone(),
                item,
                message: format!("unapproved semantic capability access {method}"),
            });
        }
    }

    fn resolve_path(&self, path: &syn::Path) -> Vec<String> {
        let components = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if components.is_empty() {
            return components;
        }
        for scope_length in (0..=self.item.len()).rev() {
            let mut candidate = self.item[..scope_length].to_vec();
            candidate.extend(components.iter().cloned());
            for alias_length in (1..=candidate.len()).rev() {
                if let Some(prefix) = self.aliases.get(&candidate[..alias_length].join("::")) {
                    let mut resolved = prefix.clone();
                    resolved.extend(candidate.into_iter().skip(alias_length));
                    return resolved;
                }
            }
        }
        components
    }

    fn inspect_attributes(&mut self, attributes: &[syn::Attribute], scope: &str) {
        for attribute in attributes {
            if attribute.path().is_ident("allow") {
                self.violations.insert(Violation {
                    code: if self.policy.deny_broad_allow {
                        "capability.allow.forbidden"
                    } else {
                        "capability.allow.unlisted"
                    },
                    file: self.file.clone(),
                    item: scope.to_owned(),
                    message: "lint allow attributes are not an environment capability".to_owned(),
                });
            }
        }
    }

    fn inspect_macro(&mut self, mac: &syn::Macro) {
        let path = self.resolve_path(&mac.path).join("::");
        if !matches!(
            path.as_str(),
            "env" | "option_env" | "std::env" | "std::option_env"
        ) {
            return;
        }
        let name = syn::parse2::<syn::LitStr>(mac.tokens.clone())
            .map(|literal| literal.value())
            .ok();
        if name
            .as_ref()
            .is_none_or(|name| !self.policy.compile_time_names.contains(name))
        {
            self.violations.insert(Violation {
                code: "capability.macro.unapproved",
                file: self.file.clone(),
                item: self.item_path(),
                message: "compile-time environment macro is not policy-listed".to_owned(),
            });
        }
    }
}

impl<'ast> Visit<'ast> for CapabilityVisitor<'_> {
    fn visit_file(&mut self, node: &'ast syn::File) {
        self.inspect_attributes(&node.attrs, "crate");
        visit::visit_file(self, node);
    }

    fn visit_item_use(&mut self, node: &'ast syn::ItemUse) {
        let mut discovered = BTreeMap::new();
        collect_use_aliases(&node.tree, Vec::new(), &mut discovered);
        for (name, target) in discovered {
            if !matches!(node.vis, syn::Visibility::Inherited) {
                let method = target.join("::");
                if is_sensitive_method(&method) {
                    self.inspect_access(method);
                }
            }
            let mut scoped = self.item.clone();
            scoped.push(name);
            self.aliases.insert(scoped.join("::"), target);
        }
        visit::visit_item_use(self, node);
    }

    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let scope = self.item_path();
        self.inspect_attributes(&node.attrs, &scope);
        self.enter(node.ident.to_string(), |visitor| {
            if let Some((_, items)) = &node.content {
                for item in items {
                    visitor.visit_item(item);
                }
            }
        });
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let name = node.sig.ident.to_string();
        self.enter(name, |visitor| {
            let scope = visitor.item_path();
            visitor.inspect_attributes(&node.attrs, &scope);
            visit::visit_block(visitor, &node.block);
        });
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let component = type_component(&node.self_ty).unwrap_or_else(|| "<impl>".to_owned());
        self.enter(component, |visitor| {
            let scope = visitor.item_path();
            visitor.inspect_attributes(&node.attrs, &scope);
            for item in &node.items {
                visitor.visit_impl_item(item);
            }
        });
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.enter(node.sig.ident.to_string(), |visitor| {
            let scope = visitor.item_path();
            visitor.inspect_attributes(&node.attrs, &scope);
            visit::visit_block(visitor, &node.block);
        });
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref() {
            let resolved = self.resolve_path(&path.path);
            let method = resolved.join("::");
            let process_constructor = method == "std::process::Command::new";
            if process_constructor
                && self
                    .item
                    .first()
                    .is_none_or(|component| component != "command")
            {
                let item = self.item_path();
                if self.policy.capabilities.iter().any(|capability| {
                    capability.crate_name == self.crate_name
                        && capability.item == item
                        && capability.methods.contains(&method)
                }) {
                    self.inspect_access(method);
                } else {
                    self.violations.insert(Violation {
                        code: "capability.process.unapproved",
                        file: self.file.clone(),
                        item,
                        message: "native process construction occurs outside command authority"
                            .to_owned(),
                    });
                }
            } else if matches!(
                method.as_str(),
                "std::env::var"
                    | "std::env::var_os"
                    | "std::env::vars"
                    | "std::env::vars_os"
                    | "std::env::set_var"
                    | "std::env::remove_var"
            ) {
                self.inspect_access(method);
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if matches!(name.as_str(), "env" | "envs" | "env_clear") {
            let method = format!("std::process::Command::{name}");
            let exact_capability_item = self.policy.capabilities.iter().any(|capability| {
                capability.crate_name == self.crate_name
                    && capability.item == self.item_path()
                    && capability.methods.contains(&method)
            });
            if exact_capability_item || receiver_constructs_command(&node.receiver, self) {
                self.inspect_access(method);
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        self.inspect_macro(node);
        visit::visit_macro(self, node);
    }
}

fn receiver_constructs_command(receiver: &syn::Expr, visitor: &CapabilityVisitor<'_>) -> bool {
    match receiver {
        syn::Expr::Call(call) => match call.func.as_ref() {
            syn::Expr::Path(path) => {
                visitor.resolve_path(&path.path).join("::") == "std::process::Command::new"
            }
            _ => false,
        },
        syn::Expr::MethodCall(call) => receiver_constructs_command(&call.receiver, visitor),
        _ => false,
    }
}

fn collect_use_aliases(
    tree: &syn::UseTree,
    mut prefix: Vec<String>,
    aliases: &mut BTreeMap<String, Vec<String>>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_aliases(&path.tree, prefix, aliases);
        }
        syn::UseTree::Name(name) => {
            prefix.push(name.ident.to_string());
            aliases.insert(name.ident.to_string(), prefix);
        }
        syn::UseTree::Rename(rename) => {
            prefix.push(rename.ident.to_string());
            aliases.insert(rename.rename.to_string(), prefix);
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use_aliases(item, prefix.clone(), aliases);
            }
        }
        syn::UseTree::Glob(_) => {
            aliases.insert("*".to_owned(), prefix);
        }
    }
}

fn type_component(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => type_component(&reference.elem),
        _ => None,
    }
}

impl Policy {
    fn read(path: &Path) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect capability policy: {error}"))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_POLICY_BYTES
        {
            return Err("capability policy is not one bounded regular file".to_owned());
        }
        let bytes = read_regular(path)?;
        if !bytes.ends_with(b"\n") {
            return Err("capability policy lacks its trailing newline".to_owned());
        }
        let text =
            std::str::from_utf8(&bytes).map_err(|_| "capability policy is not UTF-8".to_owned())?;
        let document = TomlDocument::parse(text)?;
        document.require_table_inventory(&[""])?;
        document.require_array_inventory(&["capability", "compile-time-environment"])?;
        let root = document.table("")?;
        require_keys(
            root,
            &[
                "control-vector-manifest",
                "deny-broad-clippy-allow",
                "policy-id",
                "schema-version",
            ],
        )?;
        if member(root, "schema-version")? != "1" {
            return Err("unsupported capability policy schema".to_owned());
        }
        let id = quoted(member(root, "policy-id")?)?;
        require_identifier(&id, "capability policy ID")?;
        let deny_broad_allow = boolean(member(root, "deny-broad-clippy-allow")?)?;
        if !deny_broad_allow {
            return Err("capability policy must deny broad lint allows".to_owned());
        }
        let vector_manifest = quoted(member(root, "control-vector-manifest")?)?;
        if vector_manifest.is_empty() || Path::new(&vector_manifest).is_absolute() {
            return Err("capability vector manifest path is invalid".to_owned());
        }
        let mut capability_ids = BTreeSet::new();
        let mut site_ids = BTreeSet::new();
        let mut capabilities = Vec::new();
        for table in document.arrays("capability")? {
            require_keys(table, &["crate", "id", "item", "methods", "reason"])?;
            let capability = Capability {
                id: quoted(member(table, "id")?)?,
                crate_name: quoted(member(table, "crate")?)?,
                item: quoted(member(table, "item")?)?,
                methods: string_array(member(table, "methods")?)?
                    .into_iter()
                    .collect(),
                reason: quoted(member(table, "reason")?)?,
            };
            require_identifier(&capability.id, "capability ID")?;
            require_identifier(&capability.crate_name, "capability crate")?;
            if capability.item.is_empty()
                || capability.methods.is_empty()
                || capability.reason.is_empty()
                || !capability_ids.insert(capability.id.clone())
                || !site_ids.insert((capability.crate_name.clone(), capability.item.clone()))
            {
                return Err("capability policy has an empty or duplicate capability".to_owned());
            }
            for method in &capability.methods {
                if !is_sensitive_method(method) {
                    return Err(format!(
                        "capability {} lists unknown method {method}",
                        capability.id
                    ));
                }
            }
            capabilities.push(capability);
        }
        let mut compile_time_names = BTreeSet::new();
        for table in document.arrays("compile-time-environment")? {
            require_keys(table, &["name", "scope"])?;
            let name = quoted(member(table, "name")?)?;
            let scope = quoted(member(table, "scope")?)?;
            if name.is_empty() || scope.is_empty() || !compile_time_names.insert(name) {
                return Err("compile-time capability entry is empty or duplicate".to_owned());
            }
        }
        Ok(Self {
            id,
            deny_broad_allow,
            capabilities,
            compile_time_names,
        })
    }
}

fn is_sensitive_method(value: &str) -> bool {
    matches!(
        value,
        "std::env::var"
            | "std::env::var_os"
            | "std::env::vars"
            | "std::env::vars_os"
            | "std::env::set_var"
            | "std::env::remove_var"
            | "std::process::Command::env"
            | "std::process::Command::envs"
            | "std::process::Command::env_clear"
            | "std::process::Command::new"
    )
}

fn collect_rust_files(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect Rust source root: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Rust source root is not one real directory".to_owned());
    }
    let mut entries = std::fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate Rust source root: {error}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot read Rust source entry: {error}"))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let kind = entry
            .file_type()
            .map_err(|error| format!("cannot inspect Rust source entry: {error}"))?;
        if kind.is_symlink() {
            return Err("Rust source inventory contains a symlink".to_owned());
        }
        if kind.is_dir() {
            collect_rust_files(&entry.path(), files)?;
        } else if kind.is_file() && entry.path().extension() == Some(std::ffi::OsStr::new("rs")) {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn read_bounded_source(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect Rust source: {error}"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_SOURCE_BYTES
    {
        return Err("Rust source is not one bounded regular file".to_owned());
    }
    let bytes = read_regular(path)?;
    if !bytes.ends_with(b"\n") {
        return Err("Rust source lacks its trailing newline".to_owned());
    }
    Ok(bytes)
}

fn crate_name<'a>(repository_root: &Path, path: &'a Path) -> Option<&'a str> {
    let relative = path.strip_prefix(repository_root.join("crates")).ok()?;
    relative.components().next()?.as_os_str().to_str()
}

fn module_path(repository_root: &Path, file: &Path, crate_name: &str) -> Vec<String> {
    let source = repository_root.join("crates").join(crate_name).join("src");
    let relative = file.strip_prefix(source).unwrap_or(file);
    let mut components = relative
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .filter_map(|component| component.as_os_str().to_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if let Some(stem) = relative.file_stem().and_then(std::ffi::OsStr::to_str)
        && !matches!(stem, "lib" | "main" | "mod")
    {
        components.push(stem.to_owned());
    }
    components
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn bounded(value: &str) -> String {
    value.chars().take(MAX_DIAGNOSTIC_BYTES).collect()
}

impl Site {
    fn json(&self) -> JsonValue {
        object([
            ("capabilityId", string(&self.capability_id)),
            ("crate", string(&self.crate_name)),
            ("file", string(&self.file)),
            ("item", string(&self.item)),
            ("method", string(&self.method)),
        ])
    }
}

impl Violation {
    fn priority(&self) -> u8 {
        match self.code {
            "capability.allow.forbidden" | "capability.allow.unlisted" => 0,
            "capability.macro.unapproved" => 1,
            "capability.process.unapproved" => 2,
            "capability.access.unapproved" => 3,
            _ => 4,
        }
    }

    fn json(&self) -> JsonValue {
        object([
            ("code", string(self.code)),
            ("file", string(&self.file)),
            ("item", string(&self.item)),
            ("message", string(&bounded(&self.message))),
        ])
    }
}

#[derive(Default)]
struct Options {
    output: Option<PathBuf>,
    policy: Option<PathBuf>,
    repository_root: Option<PathBuf>,
}

impl Options {
    fn parse(arguments: &[OsString]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut index = 0;
        while index < arguments.len() {
            let flag = arguments[index]
                .to_str()
                .ok_or_else(|| "capability option name must be UTF-8".to_owned())?;
            index += 1;
            let value = arguments
                .get(index)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            index += 1;
            match flag {
                "--output" => set_path(&mut options.output, value, flag)?,
                "--policy" => set_path(&mut options.policy, value, flag)?,
                "--repository-root" => set_path(&mut options.repository_root, value, flag)?,
                _ => return Err(format!("unknown capability option {flag:?}")),
            }
        }
        Ok(options)
    }
}

fn set_path(target: &mut Option<PathBuf>, value: &OsString, flag: &str) -> Result<(), String> {
    if target.is_some() {
        return Err(format!("{flag} was provided more than once"));
    }
    *target = Some(PathBuf::from(value));
    Ok(())
}
