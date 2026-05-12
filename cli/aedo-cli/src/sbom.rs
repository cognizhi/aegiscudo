use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use aegiscudo_core::{PackageCoordinate, PackageEcosystem, PolicyDecision};
use anyhow::Context;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use chrono::{SecondsFormat, Utc};
use clap::ValueEnum;
use glob::Pattern;
use serde::{Deserialize, de::IgnoredAny};
use serde_json::{Map, Value, json};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum SbomFormat {
    #[value(name = "cyclonedx-json")]
    CyclonedxJson,
    #[value(name = "cyclonedx-1.6-json")]
    Cyclonedx16Json,
    #[value(name = "spdx-2.3-json", alias = "spdx-json")]
    Spdx23Json,
}

impl SbomFormat {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::CyclonedxJson => "CycloneDX 1.7 JSON",
            Self::Cyclonedx16Json => "CycloneDX 1.6 JSON",
            Self::Spdx23Json => "SPDX 2.3 JSON",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SbomDocument {
    source: String,
    root: SbomRoot,
    generated_at: String,
    serial_number: String,
    document_namespace: String,
    components: Vec<SbomComponent>,
    dependencies: Vec<SbomDependency>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SbomDecisionInput {
    pub coordinate: PackageCoordinate,
    pub integrity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SbomResolvedDecision {
    pub coordinate: PackageCoordinate,
    pub decision: PolicyDecision,
    pub decision_timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SbomRoot {
    name: String,
    namespace: Option<String>,
    version: Option<String>,
    purl: Option<String>,
    ecosystem: Option<PackageEcosystem>,
    bom_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SbomComponent {
    reference: String,
    coordinate: PackageCoordinate,
    source: Option<String>,
    integrity: Option<String>,
    hash: Option<SbomHash>,
    decision: Option<PolicyDecision>,
    decision_timestamp: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SbomDependency {
    from: String,
    to: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SbomHash {
    algorithm: SbomHashAlgorithm,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SbomHashAlgorithm {
    Sha256,
    Sha512,
}

impl SbomHashAlgorithm {
    fn cyclonedx_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
        }
    }

    fn spdx_name(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn integrity_name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    fn hex_length(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }
}

impl SbomComponent {
    fn bom_ref(&self) -> &str {
        &self.reference
    }
}

impl SbomDocument {
    pub(crate) fn supports_remote_decision_ecosystem(&self) -> bool {
        matches!(
            self.root.ecosystem,
            Some(PackageEcosystem::Npm | PackageEcosystem::Pypi)
        )
    }

    pub(crate) fn decision_inputs(&self) -> Vec<SbomDecisionInput> {
        self.components
            .iter()
            .map(|component| SbomDecisionInput {
                coordinate: component.coordinate.clone(),
                integrity: component.integrity.clone(),
            })
            .collect()
    }

    pub(crate) fn supports_remote_decision_enrichment(&self) -> bool {
        self.supports_remote_decision_ecosystem()
            && !self.components.is_empty()
            && self.components.iter().all(|component| {
                matches!(
                    component.coordinate.ecosystem,
                    PackageEcosystem::Npm | PackageEcosystem::Pypi
                )
            })
    }

    pub(crate) fn apply_resolved_decisions(
        &mut self,
        decisions: &[SbomResolvedDecision],
    ) -> anyhow::Result<()> {
        if self.components.len() != decisions.len() {
            anyhow::bail!(
                "SBOM decision count {} did not match component count {}",
                decisions.len(),
                self.components.len()
            );
        }

        for (component, decision) in self.components.iter().zip(decisions.iter()) {
            if component.coordinate != decision.coordinate {
                anyhow::bail!(
                    "SBOM decision response did not align with component order for {}",
                    component.coordinate.purl()
                );
            }
        }

        for (component, decision) in self.components.iter_mut().zip(decisions.iter()) {
            component.decision = Some(decision.decision.clone());
            component.decision_timestamp = decision.decision_timestamp.clone();
        }

        Ok(())
    }
}

pub(crate) fn load_sbom_document(
    lockfile: Option<&Path>,
    requirements: Option<&Path>,
) -> anyhow::Result<SbomDocument> {
    match (lockfile, requirements) {
        (Some(_), Some(_)) => {
            anyhow::bail!("choose either --lockfile or --requirements when generating an SBOM")
        }
        (Some(path), None) => load_lockfile_sbom(path),
        (None, Some(path)) => load_requirements_sbom(path),
        (None, None) => {
            anyhow::bail!("aedo sbom generate requires either --lockfile or --requirements")
        }
    }
}

pub(crate) fn render_sbom(document: &SbomDocument, format: SbomFormat) -> anyhow::Result<String> {
    let value = match format {
        SbomFormat::CyclonedxJson => render_cyclonedx(document, "1.7"),
        SbomFormat::Cyclonedx16Json => render_cyclonedx(document, "1.6"),
        SbomFormat::Spdx23Json => render_spdx(document),
    };

    serde_json::to_string_pretty(&value).context("serializing generated SBOM")
}

fn load_lockfile_sbom(path: &Path) -> anyhow::Result<SbomDocument> {
    match path.file_name().and_then(|value| value.to_str()) {
        Some("package-lock.json") => load_package_lock_sbom(path),
        Some("pnpm-lock.yaml") => load_pnpm_lock_sbom(path),
        Some("yarn.lock") => {
            anyhow::bail!("SBOM generation does not yet support yarn.lock")
        }
        Some("Cargo.lock") => load_cargo_lock_sbom(path),
        Some(other) => anyhow::bail!(
            "unsupported lockfile for SBOM generation: {other}; supported lockfile inputs are package-lock.json, pnpm-lock.yaml, and Cargo.lock; use --requirements for requirements.txt-style inputs"
        ),
        None => anyhow::bail!("unsupported lockfile path {}", path.display()),
    }
}

fn load_package_lock_sbom(path: &Path) -> anyhow::Result<SbomDocument> {
    #[derive(Debug, Deserialize)]
    struct PackageLock {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        packages: BTreeMap<String, PackageLockEntry>,
        #[serde(default)]
        dependencies: BTreeMap<String, LegacyPackageLockEntry>,
    }

    #[derive(Debug, Deserialize)]
    struct PackageLockEntry {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        integrity: Option<String>,
        #[serde(default)]
        dependencies: BTreeMap<String, String>,
    }

    #[derive(Debug, Deserialize)]
    struct LegacyPackageLockEntry {
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        integrity: Option<String>,
        #[serde(default)]
        dependencies: BTreeMap<String, LegacyPackageLockEntry>,
    }

    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lockfile: PackageLock = serde_json::from_str(&contents)
        .with_context(|| format!("parsing npm lockfile {}", path.display()))?;

    fn legacy_entry_to_shim(entry: &LegacyPackageLockEntry) -> LegacyPackageLockEntryShim {
        LegacyPackageLockEntryShim {
            version: entry.version.clone(),
            integrity: entry.integrity.clone(),
            dependencies: entry
                .dependencies
                .iter()
                .map(|(name, child)| (name.clone(), legacy_entry_to_shim(child)))
                .collect(),
        }
    }

    let root = if let Some(root_entry) = lockfile.packages.get("") {
        build_npm_root(
            path,
            root_entry.name.clone().or_else(|| lockfile.name.clone()),
            root_entry
                .version
                .clone()
                .or_else(|| lockfile.version.clone()),
        )
    } else {
        build_npm_root(path, lockfile.name.clone(), lockfile.version.clone())
    };

    if !lockfile.packages.is_empty() {
        let mut components = Vec::new();
        let mut references_by_path = BTreeMap::new();

        for (package_path, entry) in &lockfile.packages {
            if package_path.is_empty() || !package_path.contains("node_modules/") {
                continue;
            }
            let Some(raw_name) = package_lock_name_from_path(package_path) else {
                continue;
            };
            let component = build_npm_component(
                format!("npm:path:{}", sanitize_reference(package_path)),
                raw_name,
                entry.version.clone(),
                entry.integrity.clone(),
            );
            references_by_path.insert(package_path.clone(), component.bom_ref().to_owned());
            components.push(component);
        }

        let mut dependency_map = default_dependency_map(&root, &components);
        if let Some(root_entry) = lockfile.packages.get("") {
            if let Some(root_dependencies) = dependency_map.get_mut(&root.bom_ref) {
                for dependency_name in root_entry.dependencies.keys() {
                    if let Some(target) =
                        resolve_package_lock_dependency("", dependency_name, &references_by_path)
                    {
                        root_dependencies.insert(target);
                    }
                }
            }
        }

        for (package_path, entry) in &lockfile.packages {
            if package_path.is_empty() {
                continue;
            }
            let targets = if let Some(from_ref) = references_by_path.get(package_path) {
                dependency_map.get_mut(from_ref)
            } else {
                dependency_map.get_mut(&root.bom_ref)
            };
            let Some(targets) = targets else {
                continue;
            };
            for dependency_name in entry.dependencies.keys() {
                if let Some(target) = resolve_package_lock_dependency(
                    package_path,
                    dependency_name,
                    &references_by_path,
                ) {
                    targets.insert(target);
                }
            }
        }

        if dependency_map
            .get(&root.bom_ref)
            .is_some_and(BTreeSet::is_empty)
        {
            let root_dependencies = collect_root_dependencies(&dependency_map, &components);
            if let Some(targets) = dependency_map.get_mut(&root.bom_ref) {
                targets.extend(root_dependencies);
            }
        }

        return Ok(finalize_document(path, root, components, dependency_map));
    }

    let mut components = BTreeMap::new();
    let mut dependency_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    dependency_map.insert(root.bom_ref.clone(), BTreeSet::new());

    for (name, entry) in &lockfile.dependencies {
        let shim_entry = legacy_entry_to_shim(entry);
        let reference =
            collect_legacy_npm_component(name, &shim_entry, &mut components, &mut dependency_map);
        if let Some(root_targets) = dependency_map.get_mut(&root.bom_ref) {
            root_targets.insert(reference);
        }
    }

    Ok(finalize_document(
        path,
        root,
        components.into_values().collect(),
        dependency_map,
    ))
}

fn load_pnpm_lock_sbom(path: &Path) -> anyhow::Result<SbomDocument> {
    #[derive(Debug, Deserialize, Default)]
    struct PnpmLock {
        #[serde(default)]
        importers: BTreeMap<String, PnpmImporter>,
        #[serde(default)]
        packages: BTreeMap<String, PnpmPackage>,
        #[serde(default)]
        snapshots: BTreeMap<String, PnpmSnapshot>,
    }

    #[derive(Debug, Deserialize, Default)]
    struct PnpmImporter {
        #[serde(default)]
        dependencies: BTreeMap<String, PnpmImporterDependency>,
        #[serde(default, rename = "optionalDependencies")]
        optional_dependencies: BTreeMap<String, PnpmImporterDependency>,
        #[serde(default, rename = "devDependencies")]
        dev_dependencies: BTreeMap<String, PnpmImporterDependency>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum PnpmImporterDependency {
        Version(String),
        Object { version: String },
    }

    impl PnpmImporterDependency {
        fn version(&self) -> &str {
            match self {
                Self::Version(version) => version,
                Self::Object { version, .. } => version,
            }
        }
    }

    #[derive(Debug, Deserialize, Default)]
    struct PnpmPackage {
        #[serde(default)]
        resolution: Option<PnpmResolution>,
    }

    #[derive(Debug, Deserialize, Default)]
    struct PnpmResolution {
        #[serde(default)]
        integrity: Option<String>,
    }

    #[derive(Debug, Deserialize, Default)]
    struct PnpmSnapshot {
        #[serde(default)]
        dependencies: BTreeMap<String, PnpmVersionSpecifier>,
        #[serde(default, rename = "optionalDependencies")]
        optional_dependencies: BTreeMap<String, PnpmVersionSpecifier>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(untagged)]
    enum PnpmVersionSpecifier {
        Version(String),
        Object { version: String },
    }

    impl PnpmVersionSpecifier {
        fn version(&self) -> &str {
            match self {
                Self::Version(version) => version,
                Self::Object { version } => version,
            }
        }
    }

    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lockfile: PnpmLock = serde_yaml::from_str(&contents)
        .with_context(|| format!("parsing pnpm lockfile {}", path.display()))?;

    let root = build_generic_root(path, Some(PackageEcosystem::Npm));
    let mut components = Vec::new();
    let mut references_by_key = BTreeMap::new();
    let mut exact_keys = BTreeMap::new();
    let mut canonical_keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let package_keys = lockfile
        .packages
        .keys()
        .chain(lockfile.snapshots.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    for package_key in package_keys {
        let cleaned_key = normalize_pnpm_key(&package_key);
        let (raw_name, version) = split_pnpm_key(&cleaned_key);
        if raw_name.is_empty() || version.is_empty() {
            continue;
        }
        let integrity = lockfile
            .packages
            .get(&package_key)
            .and_then(|entry| entry.resolution.as_ref())
            .and_then(|resolution| resolution.integrity.clone());
        let reference = format!("pnpm:key:{}", sanitize_reference(&cleaned_key));
        let component = build_npm_component(reference, &raw_name, Some(version.clone()), integrity);
        references_by_key.insert(package_key.clone(), component.bom_ref().to_owned());
        exact_keys.insert(cleaned_key.clone(), package_key.clone());
        canonical_keys
            .entry(pnpm_canonical_key(&cleaned_key))
            .or_default()
            .push(package_key.clone());
        components.push(component);
    }

    let mut dependency_map = default_dependency_map(&root, &components);

    for (package_key, snapshot) in &lockfile.snapshots {
        let Some(from_ref) = references_by_key.get(package_key) else {
            continue;
        };
        let Some(targets) = dependency_map.get_mut(from_ref) else {
            continue;
        };
        for (dependency_name, dependency_version) in snapshot
            .dependencies
            .iter()
            .chain(snapshot.optional_dependencies.iter())
        {
            for target in resolve_pnpm_dependency(
                dependency_name,
                dependency_version.version(),
                &exact_keys,
                &canonical_keys,
                &references_by_key,
            ) {
                targets.insert(target);
            }
        }
    }

    let mut direct_root_dependencies = BTreeSet::new();
    for importer in lockfile.importers.values() {
        for (dependency_name, dependency_version) in importer
            .dependencies
            .iter()
            .chain(importer.optional_dependencies.iter())
            .chain(importer.dev_dependencies.iter())
        {
            for target in resolve_pnpm_dependency(
                dependency_name,
                dependency_version.version(),
                &exact_keys,
                &canonical_keys,
                &references_by_key,
            ) {
                direct_root_dependencies.insert(target);
            }
        }
    }

    if direct_root_dependencies.is_empty() {
        direct_root_dependencies = collect_root_dependencies(&dependency_map, &components);
    }

    if let Some(targets) = dependency_map.get_mut(&root.bom_ref) {
        targets.extend(direct_root_dependencies);
    }

    Ok(finalize_document(path, root, components, dependency_map))
}

fn load_cargo_lock_sbom(path: &Path) -> anyhow::Result<SbomDocument> {
    #[derive(Debug, Deserialize, Default)]
    struct CargoLock {
        #[serde(default)]
        package: Vec<CargoLockPackage>,
    }

    #[derive(Debug, Deserialize, Default)]
    struct CargoLockPackage {
        name: String,
        version: String,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        checksum: Option<String>,
        #[serde(default)]
        dependencies: Vec<String>,
    }

    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lockfile: CargoLock = toml::from_str(&contents)
        .with_context(|| format!("parsing Cargo.lock {}", path.display()))?;

    let manifest_package = load_cargo_manifest_package(path);
    let root_package_index = manifest_package.as_ref().and_then(|manifest| {
        let matching_indices = lockfile
            .package
            .iter()
            .enumerate()
            .filter_map(|(index, package)| {
                (manifest.name == package.name
                    && manifest
                        .version
                        .as_deref()
                        .map_or(true, |version| version == package.version.as_str())
                    && package.source.is_none())
                .then_some(index)
            })
            .collect::<Vec<_>>();
        (matching_indices.len() == 1).then(|| matching_indices[0])
    });
    let mut components = Vec::new();
    let mut dependency_map = BTreeMap::new();
    let mut exact_references = BTreeMap::new();
    let mut version_references: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    let mut name_references: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut dependencies_by_reference = BTreeMap::new();
    let mut root_dependency_specs = None;
    let mut root_package_version = None;

    for (index, package) in lockfile.package.into_iter().enumerate() {
        if root_package_index == Some(index) {
            root_package_version = Some(package.version.clone());
            root_dependency_specs = Some(package.dependencies);
            continue;
        }

        let reference =
            cargo_component_reference(&package.name, &package.version, package.source.as_deref());
        let component = build_cargo_component(
            reference.clone(),
            &package.name,
            &package.version,
            package.source.as_deref(),
            package.checksum.as_deref(),
        );
        exact_references.insert(
            cargo_dependency_key(&package.name, &package.version, package.source.as_deref()),
            reference.clone(),
        );
        version_references
            .entry((package.name.clone(), package.version.clone()))
            .or_default()
            .push(reference.clone());
        name_references
            .entry(package.name.clone())
            .or_default()
            .push(reference.clone());
        dependencies_by_reference.insert(reference.clone(), package.dependencies);
        dependency_map.insert(reference, BTreeSet::new());
        components.push(component);
    }

    let root = build_cargo_root(
        path,
        manifest_package.as_ref(),
        root_package_version.as_deref(),
    );
    dependency_map.insert(root.bom_ref.clone(), BTreeSet::new());

    for (reference, dependency_specs) in dependencies_by_reference {
        let Some(targets) = dependency_map.get_mut(&reference) else {
            continue;
        };
        for dependency_spec in dependency_specs {
            for target in resolve_cargo_dependencies(
                &dependency_spec,
                &exact_references,
                &version_references,
                &name_references,
            ) {
                targets.insert(target);
            }
        }
    }

    let mut direct_root_dependencies = BTreeSet::new();
    if let Some(root_dependency_specs) = root_dependency_specs {
        for dependency_spec in root_dependency_specs {
            for target in resolve_cargo_dependencies(
                &dependency_spec,
                &exact_references,
                &version_references,
                &name_references,
            ) {
                direct_root_dependencies.insert(target);
            }
        }
    }

    if direct_root_dependencies.is_empty() {
        direct_root_dependencies = collect_root_dependencies(&dependency_map, &components);
    }

    if let Some(targets) = dependency_map.get_mut(&root.bom_ref) {
        targets.extend(direct_root_dependencies);
    }

    Ok(finalize_document(path, root, components, dependency_map))
}

fn load_requirements_sbom(path: &Path) -> anyhow::Result<SbomDocument> {
    let root = build_generic_root(path, Some(PackageEcosystem::Pypi));
    let mut entry_visited = BTreeSet::new();
    let mut constraint_visited = BTreeSet::new();
    let mut constraints = BTreeMap::new();
    let entries = collect_requirements_entries(
        path,
        &mut entry_visited,
        &mut constraint_visited,
        &mut constraints,
    )?
    .into_iter()
    .map(|entry| apply_requirement_constraints(entry, &constraints))
    .collect::<anyhow::Result<Vec<_>>>()?;
    let entries = dedupe_requirements_entries(entries);
    let mut components = Vec::new();
    let mut dependency_map = BTreeMap::new();
    let mut root_dependencies = BTreeSet::new();

    for entry in entries {
        let base_name = entry.name.split('[').next().unwrap_or(&entry.name).trim();
        if base_name.is_empty() {
            continue;
        }
        let coordinate = PackageCoordinate::new(
            PackageEcosystem::Pypi,
            base_name.to_owned(),
            entry.version.clone(),
            None::<String>,
        );
        let reference = format!(
            "pypi:req:{}:{}",
            sanitize_reference(base_name),
            sanitize_reference(entry.version.as_deref().unwrap_or("unspecified"))
        );
        let component = SbomComponent {
            reference: reference.clone(),
            coordinate,
            source: None,
            integrity: entry.integrity,
            hash: entry.hash,
            decision: None,
            decision_timestamp: None,
        };
        dependency_map.insert(reference.clone(), BTreeSet::new());
        root_dependencies.insert(reference);
        components.push(component);
    }

    dependency_map.insert(root.bom_ref.clone(), root_dependencies);

    Ok(finalize_document(path, root, components, dependency_map))
}

fn dedupe_requirements_entries(entries: Vec<RequirementsEntry>) -> Vec<RequirementsEntry> {
    let mut merged: BTreeMap<(String, Option<String>), RequirementsEntry> = BTreeMap::new();

    for entry in entries {
        let key = (entry.name.clone(), entry.version.clone());
        if let Some(existing) = merged.get_mut(&key) {
            existing.hash = merge_optional_requirement_value(existing.hash.take(), entry.hash);
            existing.integrity =
                merge_optional_requirement_value(existing.integrity.take(), entry.integrity);
        } else {
            merged.insert(key, entry);
        }
    }

    merged.into_values().collect()
}

fn merge_optional_requirement_value<T: Eq>(current: Option<T>, next: Option<T>) -> Option<T> {
    match (current, next) {
        (Some(left), Some(right)) if left == right => Some(left),
        (Some(_), Some(_)) => None,
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn finalize_document(
    source: &Path,
    root: SbomRoot,
    mut components: Vec<SbomComponent>,
    dependency_map: BTreeMap<String, BTreeSet<String>>,
) -> SbomDocument {
    components.sort_by(|left, right| {
        left.coordinate
            .purl()
            .cmp(&right.coordinate.purl())
            .then_with(|| left.bom_ref().cmp(right.bom_ref()))
    });

    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let document_name = sanitize_reference(&root.name);
    let document_uuid = Uuid::new_v4();

    SbomDocument {
        source: source.display().to_string(),
        root,
        generated_at,
        serial_number: format!("urn:uuid:{}", document_uuid),
        document_namespace: format!(
            "https://aegiscudo.invalid/spdxdocs/{}-{}",
            if document_name.is_empty() {
                "sbom"
            } else {
                &document_name
            },
            document_uuid
        ),
        components,
        dependencies: finalize_dependencies(dependency_map),
    }
}

fn finalize_dependencies(
    dependency_map: BTreeMap<String, BTreeSet<String>>,
) -> Vec<SbomDependency> {
    dependency_map
        .into_iter()
        .map(|(from, to)| SbomDependency {
            from,
            to: to.into_iter().collect(),
        })
        .collect()
}

fn render_cyclonedx(document: &SbomDocument, spec_version: &str) -> Value {
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": document.serial_number,
        "version": 1,
        "metadata": {
            "timestamp": document.generated_at,
            "tools": [{
                "vendor": "Aegiscudo",
                "name": "aedo-cli",
                "version": env!("CARGO_PKG_VERSION")
            }],
            "component": render_cyclonedx_root(document),
        },
        "components": document
            .components
            .iter()
            .map(render_cyclonedx_component)
            .collect::<Vec<_>>(),
        "dependencies": document
            .dependencies
            .iter()
            .map(|dependency| json!({
                "ref": dependency.from,
                "dependsOn": dependency.to,
            }))
            .collect::<Vec<_>>(),
    })
}

fn render_cyclonedx_root(document: &SbomDocument) -> Value {
    let mut root = Map::new();
    root.insert("type".to_owned(), json!("application"));
    root.insert("bom-ref".to_owned(), json!(document.root.bom_ref));
    root.insert("name".to_owned(), json!(document.root.name));
    if let Some(namespace) = document.root.namespace.as_deref() {
        root.insert("group".to_owned(), json!(namespace));
    }
    if let Some(version) = document.root.version.as_deref() {
        root.insert("version".to_owned(), json!(version));
    }
    if let Some(purl) = document.root.purl.as_deref() {
        root.insert("purl".to_owned(), json!(purl));
    }
    root.insert(
        "properties".to_owned(),
        json!(root_properties(
            &document.root,
            &document.source,
            &document.generated_at,
        )),
    );
    Value::Object(root)
}

fn render_cyclonedx_component(component: &SbomComponent) -> Value {
    let mut rendered = Map::new();
    rendered.insert("type".to_owned(), json!("library"));
    rendered.insert("bom-ref".to_owned(), json!(component.bom_ref()));
    rendered.insert("name".to_owned(), json!(component.coordinate.name));
    if let Some(namespace) = component.coordinate.namespace.as_deref() {
        rendered.insert("group".to_owned(), json!(namespace));
    }
    if let Some(version) = component.coordinate.version.as_deref() {
        rendered.insert("version".to_owned(), json!(version));
    }
    rendered.insert("purl".to_owned(), json!(component.coordinate.purl()));
    if let Some(hash) = component.hash.as_ref() {
        rendered.insert(
            "hashes".to_owned(),
            json!([{
                "alg": hash.algorithm.cyclonedx_name(),
                "content": hash.value,
            }]),
        );
    }
    rendered.insert(
        "properties".to_owned(),
        json!(component_properties(component)),
    );
    Value::Object(rendered)
}

fn render_spdx(document: &SbomDocument) -> Value {
    let spdx_ids = assign_spdx_ids(document);
    let root_id = spdx_ids
        .get(&document.root.bom_ref)
        .expect("root SPDX identifier should exist");

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{} SBOM", document.root.name),
        "documentNamespace": document.document_namespace,
        "creationInfo": {
            "created": document.generated_at,
            "creators": [format!("Tool: aedo-cli-{}", env!("CARGO_PKG_VERSION"))],
            "comment": format!("Generated by aedo-cli from {}", document.source),
        },
        "documentDescribes": [root_id],
        "packages": std::iter::once(render_spdx_root_package(document, root_id))
            .chain(document.components.iter().map(|component| {
                let identifier = spdx_ids
                    .get(component.bom_ref())
                    .expect("component SPDX identifier should exist");
                render_spdx_component(component, identifier)
            }))
            .collect::<Vec<_>>(),
        "relationships": build_spdx_relationships(document, &spdx_ids),
    })
}

fn render_spdx_root_package(document: &SbomDocument, identifier: &str) -> Value {
    let mut rendered = Map::new();
    rendered.insert("name".to_owned(), json!(document.root.name));
    rendered.insert("SPDXID".to_owned(), json!(identifier));
    rendered.insert("downloadLocation".to_owned(), json!("NOASSERTION"));
    rendered.insert("filesAnalyzed".to_owned(), json!(false));
    rendered.insert("supplier".to_owned(), json!("NOASSERTION"));
    rendered.insert("licenseConcluded".to_owned(), json!("NOASSERTION"));
    rendered.insert("licenseDeclared".to_owned(), json!("NOASSERTION"));
    rendered.insert("copyrightText".to_owned(), json!("NOASSERTION"));
    rendered.insert("primaryPackagePurpose".to_owned(), json!("APPLICATION"));
    rendered.insert(
        "comment".to_owned(),
        json!(format!("Generated from {}", document.source)),
    );
    if let Some(version) = document.root.version.as_deref() {
        rendered.insert("versionInfo".to_owned(), json!(version));
    }
    if let Some(purl) = document.root.purl.as_deref() {
        rendered.insert(
            "externalRefs".to_owned(),
            json!([{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }]),
        );
    }
    Value::Object(rendered)
}

fn render_spdx_component(component: &SbomComponent, identifier: &str) -> Value {
    let mut rendered = Map::new();
    rendered.insert("name".to_owned(), json!(component.coordinate.name));
    rendered.insert("SPDXID".to_owned(), json!(identifier));
    rendered.insert("downloadLocation".to_owned(), json!("NOASSERTION"));
    rendered.insert("filesAnalyzed".to_owned(), json!(false));
    rendered.insert("supplier".to_owned(), json!("NOASSERTION"));
    rendered.insert("licenseConcluded".to_owned(), json!("NOASSERTION"));
    rendered.insert("licenseDeclared".to_owned(), json!("NOASSERTION"));
    rendered.insert("copyrightText".to_owned(), json!("NOASSERTION"));
    rendered.insert("primaryPackagePurpose".to_owned(), json!("LIBRARY"));
    rendered.insert("comment".to_owned(), json!(component_comment(component)));
    if let Some(version) = component.coordinate.version.as_deref() {
        rendered.insert("versionInfo".to_owned(), json!(version));
    }
    rendered.insert(
        "externalRefs".to_owned(),
        json!([{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": component.coordinate.purl(),
        }]),
    );
    if let Some(hash) = component.hash.as_ref() {
        rendered.insert(
            "checksums".to_owned(),
            json!([{
                "algorithm": hash.algorithm.spdx_name(),
                "checksumValue": hash.value,
            }]),
        );
    }
    Value::Object(rendered)
}

fn build_spdx_relationships(
    document: &SbomDocument,
    spdx_ids: &BTreeMap<String, String>,
) -> Vec<Value> {
    let mut relationships = Vec::new();
    let root_id = spdx_ids
        .get(&document.root.bom_ref)
        .expect("root SPDX identifier should exist");
    relationships.push(json!({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": root_id,
    }));

    for dependency in &document.dependencies {
        if dependency.to.is_empty() {
            continue;
        }
        let Some(from_id) = spdx_ids.get(&dependency.from) else {
            continue;
        };
        for target in &dependency.to {
            let Some(target_id) = spdx_ids.get(target) else {
                continue;
            };
            relationships.push(json!({
                "spdxElementId": from_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": target_id,
            }));
        }
    }

    relationships
}

fn assign_spdx_ids(document: &SbomDocument) -> BTreeMap<String, String> {
    let mut identifiers = BTreeMap::new();
    identifiers.insert(document.root.bom_ref.clone(), "SPDXRef-Root".to_owned());
    for (index, component) in document.components.iter().enumerate() {
        identifiers.insert(
            component.bom_ref().to_owned(),
            format!("SPDXRef-Package-{}", index + 1),
        );
    }
    identifiers
}

fn default_dependency_map(
    root: &SbomRoot,
    components: &[SbomComponent],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut dependency_map = BTreeMap::new();
    dependency_map.insert(root.bom_ref.clone(), BTreeSet::new());
    for component in components {
        dependency_map.insert(component.bom_ref().to_owned(), BTreeSet::new());
    }
    dependency_map
}

fn collect_root_dependencies(
    dependency_map: &BTreeMap<String, BTreeSet<String>>,
    components: &[SbomComponent],
) -> BTreeSet<String> {
    let mut incoming_counts = components
        .iter()
        .map(|component| (component.bom_ref().to_owned(), 0usize))
        .collect::<BTreeMap<_, _>>();

    for dependencies in dependency_map.values() {
        for target in dependencies {
            if let Some(count) = incoming_counts.get_mut(target) {
                *count += 1;
            }
        }
    }

    incoming_counts
        .into_iter()
        .filter_map(|(reference, count)| (count == 0).then_some(reference))
        .collect()
}

fn collect_legacy_npm_component(
    raw_name: &str,
    entry: &LegacyPackageLockEntryShim,
    components: &mut BTreeMap<String, SbomComponent>,
    dependency_map: &mut BTreeMap<String, BTreeSet<String>>,
) -> String {
    let reference = format!(
        "npm:legacy:{}:{}",
        sanitize_reference(raw_name),
        sanitize_reference(entry.version.as_deref().unwrap_or("unspecified"))
    );
    let component = build_npm_component(
        reference.clone(),
        raw_name,
        entry.version.clone(),
        entry.integrity.clone(),
    );
    components.entry(reference.clone()).or_insert(component);

    let mut child_references = BTreeSet::new();
    for (child_name, child_entry) in &entry.dependencies {
        let child_reference =
            collect_legacy_npm_component(child_name, child_entry, components, dependency_map);
        child_references.insert(child_reference);
    }
    dependency_map
        .entry(reference.clone())
        .or_default()
        .extend(child_references);

    reference
}

#[derive(Debug, Clone)]
struct LegacyPackageLockEntryShim {
    version: Option<String>,
    integrity: Option<String>,
    dependencies: BTreeMap<String, LegacyPackageLockEntryShim>,
}

fn resolve_package_lock_dependency(
    current_path: &str,
    dependency_name: &str,
    references_by_path: &BTreeMap<String, String>,
) -> Option<String> {
    let mut search_base = current_path;
    loop {
        let candidate = if search_base.is_empty() {
            format!("node_modules/{dependency_name}")
        } else {
            format!("{search_base}/node_modules/{dependency_name}")
        };

        if let Some(reference) = references_by_path.get(&candidate) {
            return Some(reference.clone());
        }

        if search_base.is_empty() {
            break;
        }

        search_base = package_lock_parent_path(search_base);
    }

    None
}

fn package_lock_parent_path(path: &str) -> &str {
    path.rsplit_once("/node_modules/")
        .map(|(parent, _)| parent)
        .unwrap_or("")
}

fn package_lock_name_from_path(path: &str) -> Option<&str> {
    let trimmed = path.trim_matches('/');
    let name = trimmed
        .rsplit("/node_modules/")
        .next()
        .unwrap_or(trimmed)
        .trim_start_matches("node_modules/")
        .trim();
    (!name.is_empty()).then_some(name)
}

fn resolve_pnpm_dependency(
    dependency_name: &str,
    dependency_version: &str,
    exact_keys: &BTreeMap<String, String>,
    canonical_keys: &BTreeMap<String, Vec<String>>,
    references_by_key: &BTreeMap<String, String>,
) -> Vec<String> {
    let exact_candidate =
        normalize_pnpm_key(&format!("{}@{}", dependency_name, dependency_version));
    if let Some(resolved_key) = exact_keys.get(&exact_candidate) {
        return references_by_key
            .get(resolved_key)
            .cloned()
            .into_iter()
            .collect();
    }

    let candidate = pnpm_canonical_key(&format!("{}@{}", dependency_name, dependency_version));
    canonical_keys
        .get(&candidate)
        .into_iter()
        .flat_map(|keys| keys.iter())
        .filter_map(|resolved_key| references_by_key.get(resolved_key).cloned())
        .collect()
}

fn normalize_pnpm_key(key: &str) -> String {
    key.trim_matches('/').to_owned()
}

fn pnpm_canonical_key(key: &str) -> String {
    normalize_pnpm_key(key)
        .split('(')
        .next()
        .unwrap_or(key)
        .to_owned()
}

fn split_pnpm_key(key: &str) -> (String, String) {
    let normalized = key.trim_matches('/');
    let base = normalized.split('(').next().unwrap_or(normalized);

    if base.starts_with('@') {
        if let Some(slash) = base.find('/') {
            if let Some(at) = base[slash + 1..].rfind('@') {
                let separator = slash + 1 + at;
                return (
                    base[..separator].to_owned(),
                    base[separator + 1..].to_owned(),
                );
            }
        }
    } else if let Some(at) = base.rfind('@') {
        return (base[..at].to_owned(), base[at + 1..].to_owned());
    }

    (base.to_owned(), String::new())
}

fn normalize_requirements_name(name: &str) -> Option<String> {
    let base = name.split('[').next().unwrap_or(name).trim();
    if base.is_empty() {
        return None;
    }

    let mut normalized = String::with_capacity(base.len());
    let mut previous_separator = false;
    for character in base.chars() {
        match character {
            '-' | '_' | '.' => {
                if !previous_separator {
                    normalized.push('-');
                    previous_separator = true;
                }
            }
            _ => {
                normalized.push(character.to_ascii_lowercase());
                previous_separator = false;
            }
        }
    }

    (!normalized.is_empty()).then_some(normalized)
}

fn parse_requirements_line(line: &str) -> Option<RequirementsEntry> {
    let content = requirements_parseable_content(line);
    if content.is_empty() || content.starts_with('-') {
        return None;
    }

    let content = content.split(';').next().unwrap_or(content).trim();
    if content.is_empty() {
        return None;
    }

    let tokens = content.split_whitespace().collect::<Vec<_>>();
    let package = *tokens.first()?;
    let hash = extract_requirements_hash(&tokens[1..]);
    let is_direct_reference = tokens.get(1) == Some(&"@");
    let (raw_name, version) = if is_direct_reference {
        (package.to_owned(), None)
    } else {
        package
            .split_once("==")
            .map(|(name, version)| (name.trim().to_owned(), Some(version.trim().to_owned())))
            .unwrap_or_else(|| {
                (
                    package
                        .split(['<', '>', '~', '='])
                        .next()
                        .unwrap_or(package)
                        .trim()
                        .to_owned(),
                    None,
                )
            })
    };
    let name = normalize_requirements_name(&raw_name)?;

    let integrity = hash
        .as_ref()
        .map(|hash| format!("{}:{}", hash.algorithm.integrity_name(), hash.value));

    Some(RequirementsEntry {
        name,
        version,
        hash,
        integrity,
        constraint_eligible: !is_direct_reference,
    })
}

fn extract_requirements_hash(tokens: &[&str]) -> Option<SbomHash> {
    let mut hashes = BTreeSet::new();

    for (index, token) in tokens.iter().enumerate() {
        if let Some(value) = token.strip_prefix("--hash=") {
            if let Some(hash) = parse_hash_spec(value) {
                hashes.insert(hash);
            }
            continue;
        }
        if *token == "--hash" {
            if let Some(next) = tokens.get(index + 1) {
                if let Some(hash) = parse_hash_spec(next) {
                    hashes.insert(hash);
                }
            }
        }
        if let Some(hash) = parse_requirements_fragment_hash(token) {
            hashes.insert(hash);
        }
    }

    (hashes.len() == 1)
        .then(|| hashes.into_iter().next())
        .flatten()
}

fn parse_requirements_fragment_hash(token: &str) -> Option<SbomHash> {
    let fragment = token.split('#').nth(1)?;

    fragment.split('&').find_map(|part| {
        if let Some(digest) = part.strip_prefix("sha256=") {
            parse_hash_spec(&format!("sha256:{digest}"))
        } else if let Some(digest) = part.strip_prefix("sha512=") {
            parse_hash_spec(&format!("sha512:{digest}"))
        } else {
            None
        }
    })
}

fn requirements_parseable_content(line: &str) -> &str {
    let trimmed = line.trim();
    if trimmed.contains(" @ ") || trimmed.starts_with("-e") || trimmed.starts_with("--editable") {
        trimmed
    } else {
        trimmed.split('#').next().unwrap_or(trimmed).trim()
    }
}

fn parse_hash_spec(value: &str) -> Option<SbomHash> {
    let (algorithm, digest) = value.split_once(':')?;
    match algorithm {
        "sha256" => normalize_hex_hash(SbomHashAlgorithm::Sha256, digest),
        "sha512" => normalize_hex_hash(SbomHashAlgorithm::Sha512, digest),
        _ => None,
    }
}

fn collect_requirements_entries(
    path: &Path,
    entry_visited: &mut BTreeSet<PathBuf>,
    constraint_visited: &mut BTreeSet<PathBuf>,
    constraints: &mut BTreeMap<String, RequirementsEntry>,
) -> anyhow::Result<Vec<RequirementsEntry>> {
    let visit_key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !entry_visited.insert(visit_key) {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    for line in read_requirements_logical_lines(path)? {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(include_path) = parse_requirements_include(trimmed) {
            let nested_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(include_path);
            entries.extend(
                collect_requirements_entries(
                    &nested_path,
                    entry_visited,
                    constraint_visited,
                    constraints,
                )
                .with_context(|| {
                    format!(
                        "reading included requirements {} from {}",
                        nested_path.display(),
                        path.display()
                    )
                })?,
            );
            continue;
        }
        if let Some(constraint_path) = parse_requirements_constraint(trimmed) {
            let nested_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(constraint_path);
            collect_requirement_constraints(&nested_path, constraint_visited, constraints)
                .with_context(|| {
                    format!(
                        "reading constraint requirements {} from {}",
                        nested_path.display(),
                        path.display()
                    )
                })?;
            continue;
        }
        if let Some(name) = parse_requirements_editable_name(trimmed) {
            entries.push(RequirementsEntry {
                name,
                version: None,
                hash: None,
                integrity: None,
                constraint_eligible: false,
            });
            continue;
        }
        if trimmed.starts_with('-') {
            continue;
        }
        let Some(entry) = parse_requirements_line(trimmed) else {
            continue;
        };
        entries.push(entry);
    }

    Ok(entries)
}

fn collect_requirement_constraints(
    path: &Path,
    visited: &mut BTreeSet<PathBuf>,
    constraints: &mut BTreeMap<String, RequirementsEntry>,
) -> anyhow::Result<()> {
    let visit_key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    if !visited.insert(visit_key) {
        return Ok(());
    }

    for line in read_requirements_logical_lines(path)? {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(include_path) =
            parse_requirements_include(trimmed).or_else(|| parse_requirements_constraint(trimmed))
        {
            let nested_path = path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(include_path);
            collect_requirement_constraints(&nested_path, visited, constraints).with_context(
                || {
                    format!(
                        "reading nested constraint requirements {} from {}",
                        nested_path.display(),
                        path.display()
                    )
                },
            )?;
            continue;
        }
        if trimmed.starts_with('-') {
            continue;
        }
        let Some(constraint) = parse_requirements_line(trimmed) else {
            continue;
        };
        insert_requirement_constraint(constraints, constraint, path)?;
    }

    Ok(())
}

fn insert_requirement_constraint(
    constraints: &mut BTreeMap<String, RequirementsEntry>,
    constraint: RequirementsEntry,
    path: &Path,
) -> anyhow::Result<()> {
    if !constraint.constraint_eligible {
        anyhow::bail!(
            "requirements constraint {} from {} uses an unsupported direct reference",
            constraint.name,
            path.display()
        );
    }

    if let Some(existing) = constraints.get_mut(&constraint.name) {
        merge_requirement_constraint_value(
            &mut existing.version,
            constraint.version,
            &constraint.name,
            path,
            "version",
        )?;
        merge_requirement_constraint_value(
            &mut existing.hash,
            constraint.hash,
            &constraint.name,
            path,
            "hash",
        )?;
        merge_requirement_constraint_value(
            &mut existing.integrity,
            constraint.integrity,
            &constraint.name,
            path,
            "hash",
        )?;
        return Ok(());
    }

    constraints.insert(constraint.name.clone(), constraint);
    Ok(())
}

fn merge_requirement_constraint_value<T: Eq>(
    current: &mut Option<T>,
    next: Option<T>,
    name: &str,
    path: &Path,
    field: &str,
) -> anyhow::Result<()> {
    let Some(next_value) = next else {
        return Ok(());
    };

    match current {
        Some(existing) if existing != &next_value => anyhow::bail!(
            "requirements constraint {} from {} conflicts on {}",
            name,
            path.display(),
            field
        ),
        None => *current = Some(next_value),
        _ => {}
    }

    Ok(())
}

fn apply_requirement_constraints(
    mut entry: RequirementsEntry,
    constraints: &BTreeMap<String, RequirementsEntry>,
) -> anyhow::Result<RequirementsEntry> {
    if !entry.constraint_eligible {
        return Ok(entry);
    }

    let Some(constraint) = constraints.get(&entry.name) else {
        return Ok(entry);
    };

    ensure_requirement_constraint_compatible(&entry, constraint)?;

    if entry.version.is_none() {
        entry.version = constraint.version.clone();
    }
    if entry.hash.is_none() && (constraint.version.is_none() || constraint.version == entry.version)
    {
        entry.hash = constraint.hash.clone();
    }
    if entry.integrity.is_none()
        && (constraint.version.is_none() || constraint.version == entry.version)
    {
        entry.integrity = constraint.integrity.clone();
    }

    Ok(entry)
}

fn ensure_requirement_constraint_compatible(
    entry: &RequirementsEntry,
    constraint: &RequirementsEntry,
) -> anyhow::Result<()> {
    if let (Some(version), Some(constraint_version)) = (&entry.version, &constraint.version) {
        if version != constraint_version {
            anyhow::bail!(
                "requirement {} version {} conflicts with constraint version {}",
                entry.name,
                version,
                constraint_version
            );
        }
    }

    if let (Some(hash), Some(constraint_hash)) = (&entry.hash, &constraint.hash) {
        if hash != constraint_hash {
            anyhow::bail!(
                "requirement {} hash conflicts with constraint hash",
                entry.name
            );
        }
    }

    if let (Some(integrity), Some(constraint_integrity)) = (&entry.integrity, &constraint.integrity)
    {
        if integrity != constraint_integrity {
            anyhow::bail!(
                "requirement {} hash {} conflicts with constraint hash {}",
                entry.name,
                integrity,
                constraint_integrity
            );
        }
    }

    Ok(())
}

fn read_requirements_logical_lines(path: &Path) -> anyhow::Result<Vec<String>> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut logical_lines = Vec::new();
    let mut current = String::new();

    for raw_line in contents.lines() {
        let trimmed = raw_line.trim();
        if !current.is_empty() && trimmed.is_empty() {
            continue;
        }
        if current.is_empty() {
            current.push_str(trimmed);
        } else {
            current.push(' ');
            current.push_str(trimmed);
        }

        if current.ends_with('\\') {
            current.pop();
            current = current.trim_end().to_owned();
            continue;
        }

        if !current.trim().is_empty() {
            logical_lines.push(current.trim().to_owned());
        }
        current.clear();
    }

    if !current.trim().is_empty() {
        logical_lines.push(current.trim().to_owned());
    }

    Ok(logical_lines)
}

fn parse_requirements_include(line: &str) -> Option<&str> {
    let include = if let Some(value) = line.strip_prefix("-r") {
        value
    } else if let Some(value) = line.strip_prefix("--requirement") {
        value
    } else {
        return None;
    };

    let include = include.trim_start_matches('=').trim();
    let include = include.split('#').next().unwrap_or(include).trim();
    (!include.is_empty()).then_some(include)
}

fn parse_requirements_constraint(line: &str) -> Option<&str> {
    let include = if let Some(value) = line.strip_prefix("-c") {
        value
    } else if let Some(value) = line.strip_prefix("--constraint") {
        value
    } else {
        return None;
    };

    let include = include.trim_start_matches('=').trim();
    let include = include.split('#').next().unwrap_or(include).trim();
    (!include.is_empty()).then_some(include)
}

fn parse_requirements_editable_name(line: &str) -> Option<String> {
    let spec = if let Some(value) = line.strip_prefix("-e") {
        value
    } else if let Some(value) = line.strip_prefix("--editable") {
        value
    } else {
        return None;
    };

    let spec = spec.trim_start_matches('=').trim();
    let egg = spec
        .split("#egg=")
        .nth(1)
        .or_else(|| spec.split("&egg=").nth(1))?;
    let egg = egg.split(['&', ' ', '\t']).next().unwrap_or(egg).trim();
    normalize_requirements_name(egg)
}

fn build_npm_root(path: &Path, raw_name: Option<String>, version: Option<String>) -> SbomRoot {
    match raw_name {
        Some(name) => {
            let (namespace, package_name) = split_npm_name(&name);
            let coordinate = PackageCoordinate::new(
                PackageEcosystem::Npm,
                package_name,
                version.clone(),
                namespace.clone(),
            );
            let purl = coordinate.purl();
            build_root(
                coordinate.name,
                coordinate.namespace,
                coordinate.version,
                Some(purl),
                Some(PackageEcosystem::Npm),
                path,
            )
        }
        None => build_generic_root(path, Some(PackageEcosystem::Npm)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CargoManifestPackageInfo {
    name: String,
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CargoManifest {
    package: Option<CargoManifestPackage>,
    #[serde(default)]
    workspace: Option<CargoManifestWorkspace>,
}

#[derive(Debug, Deserialize)]
struct CargoManifestPackage {
    name: String,
    #[serde(default)]
    version: Option<CargoManifestVersion>,
}

#[derive(Debug, Deserialize, Default)]
struct CargoManifestWorkspace {
    #[serde(default)]
    members: Vec<String>,
    #[serde(default, rename = "default-members")]
    default_members: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    package: CargoManifestWorkspacePackage,
}

#[derive(Debug, Deserialize, Default)]
struct CargoManifestWorkspacePackage {
    #[serde(default)]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CargoManifestVersion {
    Literal(String),
    Workspace(IgnoredAny),
}

fn cargo_manifest_package_info(
    package: CargoManifestPackage,
    workspace_version: Option<&str>,
) -> CargoManifestPackageInfo {
    CargoManifestPackageInfo {
        name: package.name,
        version: match package.version {
            Some(CargoManifestVersion::Literal(version)) => Some(version),
            Some(CargoManifestVersion::Workspace(_)) => workspace_version.map(str::to_owned),
            None => None,
        },
    }
}

fn load_cargo_manifest(path: &Path) -> Option<CargoManifest> {
    let contents = fs::read_to_string(path).ok()?;
    toml::from_str(&contents).ok()
}

fn load_cargo_workspace_member_package(
    workspace_root: &Path,
    member: &str,
    excludes: &[String],
) -> Vec<PathBuf> {
    let is_glob_member = member.contains(['*', '?', '[']);
    let member_paths = if is_glob_member {
        let Some(workspace_root) = workspace_root.to_str() else {
            return Vec::new();
        };
        let pattern = format!("{}/{}", Pattern::escape(workspace_root), member);
        let Ok(paths) = glob::glob(&pattern) else {
            return Vec::new();
        };
        let mut paths = paths.filter_map(Result::ok).collect::<Vec<_>>();
        paths.sort();
        paths
    } else {
        vec![workspace_root.join(member)]
    };

    member_paths
        .into_iter()
        .map(|member_path| {
            if member_path.file_name().and_then(|value| value.to_str()) == Some("Cargo.toml") {
                member_path
            } else {
                member_path.join("Cargo.toml")
            }
        })
        .filter(|manifest_path| {
            !is_glob_member
                || !cargo_workspace_member_is_excluded(workspace_root, manifest_path, excludes)
        })
        .collect()
}

fn normalize_cargo_workspace_path(path: &Path) -> String {
    let mut prefix = None;
    let mut has_root = false;
    let mut segments = Vec::new();

    for component in path.components() {
        match component {
            Component::Prefix(value) => {
                prefix = Some(value.as_os_str().to_string_lossy().into_owned());
            }
            Component::RootDir => {
                has_root = true;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if segments
                    .last()
                    .is_some_and(|segment: &String| segment != "..")
                {
                    segments.pop();
                } else if !has_root {
                    segments.push("..".to_owned());
                }
            }
            Component::Normal(value) => {
                segments.push(value.to_string_lossy().into_owned());
            }
        }
    }

    let mut normalized = String::new();
    if let Some(prefix) = prefix {
        normalized.push_str(&prefix);
        if has_root {
            normalized.push('/');
        }
    } else if has_root {
        normalized.push('/');
    }
    normalized.push_str(&segments.join("/"));

    if normalized.is_empty() {
        ".".to_owned()
    } else {
        normalized
    }
}

fn cargo_workspace_member_is_excluded(
    workspace_root: &Path,
    manifest_path: &Path,
    excludes: &[String],
) -> bool {
    let Some(member_path) = manifest_path.parent() else {
        return false;
    };
    let normalized_member_path = normalize_cargo_workspace_path(member_path);

    excludes.iter().any(|exclude| {
        let normalized_exclude_path = normalize_cargo_workspace_path(&workspace_root.join(exclude));
        if exclude.contains(['*', '?', '[']) {
            Pattern::new(&normalized_exclude_path)
                .map(|pattern| pattern.matches(&normalized_member_path))
                .unwrap_or(false)
        } else {
            let normalized_exclude_path = normalized_exclude_path.trim_end_matches('/');
            normalized_member_path == normalized_exclude_path
                || normalized_member_path
                    .strip_prefix(normalized_exclude_path)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        }
    })
}

fn load_cargo_workspace_package(
    workspace_root: &Path,
    workspace: &CargoManifestWorkspace,
) -> Option<CargoManifestPackageInfo> {
    let workspace_version = workspace.package.version.as_deref();
    let member_manifest_paths = workspace
        .members
        .iter()
        .flat_map(|member| {
            load_cargo_workspace_member_package(workspace_root, member, &workspace.exclude)
        })
        .collect::<Vec<_>>();
    let effective_member_paths = member_manifest_paths
        .iter()
        .map(|path| normalize_cargo_workspace_path(path))
        .collect::<BTreeSet<_>>();
    let candidate_manifest_paths = if workspace.default_members.is_empty() {
        member_manifest_paths
    } else {
        workspace
            .default_members
            .iter()
            .flat_map(|member| {
                load_cargo_workspace_member_package(workspace_root, member, &workspace.exclude)
            })
            .filter(|manifest_path| {
                effective_member_paths.contains(&normalize_cargo_workspace_path(manifest_path))
            })
            .collect::<Vec<_>>()
    };

    let mut candidates = candidate_manifest_paths
        .into_iter()
        .filter_map(|manifest_path| {
            let manifest = load_cargo_manifest(&manifest_path)?;
            manifest
                .package
                .map(|package| cargo_manifest_package_info(package, workspace_version))
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.version.cmp(&right.version))
    });
    candidates.dedup();

    (candidates.len() == 1).then(|| candidates.remove(0))
}

fn load_cargo_manifest_package(lockfile_path: &Path) -> Option<CargoManifestPackageInfo> {
    let manifest_path = lockfile_path.parent()?.join("Cargo.toml");
    let CargoManifest { package, workspace } = load_cargo_manifest(&manifest_path)?;

    if let Some(workspace) = workspace.as_ref() {
        if !workspace.default_members.is_empty() {
            return load_cargo_workspace_package(manifest_path.parent()?, workspace);
        }
    }

    if let Some(package) = package {
        let workspace_version = workspace
            .as_ref()
            .and_then(|workspace| workspace.package.version.as_deref());
        return Some(cargo_manifest_package_info(package, workspace_version));
    }

    load_cargo_workspace_package(manifest_path.parent()?, &workspace?)
}

fn build_cargo_root(
    path: &Path,
    manifest_package: Option<&CargoManifestPackageInfo>,
    lockfile_root_version: Option<&str>,
) -> SbomRoot {
    let Some(manifest_package) = manifest_package else {
        return build_generic_root(path, Some(PackageEcosystem::Cargo));
    };

    let coordinate = PackageCoordinate::new(
        PackageEcosystem::Cargo,
        manifest_package.name.clone(),
        manifest_package
            .version
            .clone()
            .or_else(|| lockfile_root_version.map(str::to_owned)),
        None::<String>,
    );
    let purl = coordinate.purl();
    build_root(
        coordinate.name,
        coordinate.namespace,
        coordinate.version,
        Some(purl),
        Some(PackageEcosystem::Cargo),
        path,
    )
}

fn build_generic_root(path: &Path, ecosystem: Option<PackageEcosystem>) -> SbomRoot {
    build_root(
        fallback_source_name(path),
        None,
        None,
        None,
        ecosystem,
        path,
    )
}

fn build_root(
    name: String,
    namespace: Option<String>,
    version: Option<String>,
    purl: Option<String>,
    ecosystem: Option<PackageEcosystem>,
    source: &Path,
) -> SbomRoot {
    let fallback_ref = format!(
        "aegiscudo-root:{}",
        sanitize_reference(&fallback_source_name(source))
    );
    SbomRoot {
        name,
        namespace,
        version,
        purl: purl.clone(),
        ecosystem,
        bom_ref: purl.unwrap_or(fallback_ref),
    }
}

fn build_npm_component(
    reference: String,
    raw_name: &str,
    version: Option<String>,
    integrity: Option<String>,
) -> SbomComponent {
    let (namespace, name) = split_npm_name(raw_name);
    let coordinate = PackageCoordinate::new(PackageEcosystem::Npm, name, version, namespace);
    let hash = parse_standard_hash(integrity.as_deref());

    SbomComponent {
        reference,
        coordinate,
        source: None,
        integrity,
        hash,
        decision: None,
        decision_timestamp: None,
    }
}

fn build_cargo_component(
    reference: String,
    name: &str,
    version: &str,
    source: Option<&str>,
    checksum: Option<&str>,
) -> SbomComponent {
    let coordinate = PackageCoordinate::new(
        PackageEcosystem::Cargo,
        name.to_owned(),
        Some(version.to_owned()),
        None::<String>,
    );
    let hash = parse_standard_hash(checksum);
    let integrity = hash
        .as_ref()
        .map(|hash| format!("{}:{}", hash.algorithm.integrity_name(), hash.value));

    SbomComponent {
        reference,
        coordinate,
        source: source.map(str::to_owned),
        integrity,
        hash,
        decision: None,
        decision_timestamp: None,
    }
}

fn cargo_component_reference(name: &str, version: &str, source: Option<&str>) -> String {
    let source_suffix = source
        .map(|value| {
            format!(
                ":src-{}",
                Uuid::new_v5(&Uuid::NAMESPACE_URL, value.as_bytes()).simple()
            )
        })
        .unwrap_or_default();
    format!(
        "cargo:pkg:{}:{}{}",
        sanitize_reference(name),
        sanitize_reference(version),
        source_suffix
    )
}

fn cargo_dependency_key(name: &str, version: &str, source: Option<&str>) -> String {
    format!("{name}@{version}|{}", source.unwrap_or(""))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CargoDependencySpec {
    name: String,
    version: Option<String>,
    source: Option<String>,
}

fn parse_cargo_dependency_spec(dependency: &str) -> Option<CargoDependencySpec> {
    let trimmed = dependency.trim();
    if trimmed.is_empty() {
        return None;
    }

    let (package_id, source) = match trimmed.rsplit_once(" (") {
        Some((package_id, source)) => (
            package_id.trim(),
            source
                .strip_suffix(')')
                .map(|value| value.trim().to_owned()),
        ),
        None => (trimmed, None),
    };

    let mut parts = package_id.split_whitespace();
    let name = parts.next()?.to_owned();
    let version = parts.next().map(str::to_owned);

    Some(CargoDependencySpec {
        name,
        version,
        source,
    })
}

fn resolve_cargo_dependencies(
    dependency: &str,
    exact_references: &BTreeMap<String, String>,
    version_references: &BTreeMap<(String, String), Vec<String>>,
    name_references: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    let Some(parsed) = parse_cargo_dependency_spec(dependency) else {
        return Vec::new();
    };

    if let Some(version) = parsed.version.as_deref() {
        if let Some(source) = parsed.source.as_deref() {
            if let Some(reference) =
                exact_references.get(&cargo_dependency_key(&parsed.name, version, Some(source)))
            {
                return vec![reference.clone()];
            }

            return Vec::new();
        }

        if let Some(references) = version_references.get(&(parsed.name.clone(), version.to_owned()))
        {
            return references.clone();
        }

        return Vec::new();
    }

    name_references
        .get(&parsed.name)
        .cloned()
        .unwrap_or_default()
}

fn split_npm_name(raw_name: &str) -> (Option<String>, String) {
    if let Some(stripped) = raw_name.strip_prefix('@') {
        if let Some((scope, name)) = stripped.split_once('/') {
            return (Some(scope.to_owned()), name.to_owned());
        }
    }

    (None, raw_name.to_owned())
}

fn parse_standard_hash(raw: Option<&str>) -> Option<SbomHash> {
    let raw = raw?.trim();
    if let Some(value) = raw.strip_prefix("sha256-") {
        return decode_sri_hash(SbomHashAlgorithm::Sha256, value);
    }
    if let Some(value) = raw.strip_prefix("sha512-") {
        return decode_sri_hash(SbomHashAlgorithm::Sha512, value);
    }
    if let Some(value) = raw.strip_prefix("sha256:") {
        return normalize_hex_hash(SbomHashAlgorithm::Sha256, value);
    }
    if let Some(value) = raw.strip_prefix("sha512:") {
        return normalize_hex_hash(SbomHashAlgorithm::Sha512, value);
    }

    match raw.len() {
        64 => normalize_hex_hash(SbomHashAlgorithm::Sha256, raw),
        128 => normalize_hex_hash(SbomHashAlgorithm::Sha512, raw),
        _ => None,
    }
}

fn decode_sri_hash(algorithm: SbomHashAlgorithm, value: &str) -> Option<SbomHash> {
    let decoded = BASE64_STANDARD.decode(value).ok()?;
    (decoded.len() * 2 == algorithm.hex_length()).then(|| SbomHash {
        algorithm,
        value: hex::encode(decoded),
    })
}

fn normalize_hex_hash(algorithm: SbomHashAlgorithm, value: &str) -> Option<SbomHash> {
    let normalized = value.trim().to_ascii_lowercase();
    (normalized.len() == algorithm.hex_length()
        && normalized
            .chars()
            .all(|character| character.is_ascii_hexdigit()))
    .then_some(SbomHash {
        algorithm,
        value: normalized,
    })
}

fn fallback_source_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("sbom")
        .to_owned()
}

fn sanitize_reference(value: &str) -> String {
    let mut sanitized = String::new();
    let mut last_was_dash = false;

    for character in value.chars() {
        let normalized = if character.is_ascii_alphanumeric() {
            last_was_dash = false;
            Some(character.to_ascii_lowercase())
        } else if matches!(character, '.' | '_' | '-') {
            last_was_dash = false;
            Some(character)
        } else if !last_was_dash {
            last_was_dash = true;
            Some('-')
        } else {
            None
        };

        if let Some(character) = normalized {
            sanitized.push(character);
        }
    }

    sanitized.trim_matches('-').to_owned()
}

fn root_properties(root: &SbomRoot, source: &str, generated_at: &str) -> Vec<Value> {
    let mut properties = vec![
        json!({ "name": "aegiscudo:source", "value": source }),
        json!({ "name": "aegiscudo:generated_at", "value": generated_at }),
    ];

    if let Some(ecosystem) = root.ecosystem.as_ref() {
        properties.push(json!({
            "name": "aegiscudo:ecosystem",
            "value": ecosystem.to_string(),
        }));
    }

    properties
}

fn component_properties(component: &SbomComponent) -> Vec<Value> {
    let mut properties = vec![json!({
        "name": "aegiscudo:ecosystem",
        "value": component.coordinate.ecosystem.to_string(),
    })];

    if let Some(decision) = component.decision.as_ref() {
        properties.push(json!({
            "name": "aegiscudo:decision",
            "value": decision_name(decision),
        }));
        if let Some(decision_timestamp) = component.decision_timestamp.as_deref() {
            properties.push(json!({
                "name": "aegiscudo:decision_timestamp",
                "value": decision_timestamp,
            }));
        } else {
            properties.push(json!({
                "name": "aegiscudo:decision_timestamp_status",
                "value": "unavailable",
            }));
        }
    } else {
        properties.push(json!({
            "name": "aegiscudo:decision_status",
            "value": "unresolved",
        }));
    }

    if let Some(integrity) = component.integrity.as_deref() {
        properties.push(json!({
            "name": "aegiscudo:integrity",
            "value": integrity,
        }));
    }
    if let Some(source) = component.source.as_deref() {
        properties.push(json!({
            "name": "aegiscudo:cargo_source",
            "value": source,
        }));
    }

    properties
}

fn component_comment(component: &SbomComponent) -> String {
    let mut parts = vec![format!("ecosystem={}", component.coordinate.ecosystem)];

    if let Some(decision) = component.decision.as_ref() {
        parts.push(format!("Aegiscudo decision={}", decision_name(decision)));
        parts.push(format!(
            "decision_timestamp={}",
            component
                .decision_timestamp
                .as_deref()
                .unwrap_or("unavailable")
        ));
    } else {
        parts.push("Aegiscudo decision unresolved".to_owned());
    }

    if let Some(hash) = component.hash.as_ref() {
        parts.push(format!(
            "{}={}",
            hash.algorithm.integrity_name(),
            hash.value
        ));
    }
    if let Some(integrity) = component.integrity.as_deref() {
        parts.push(format!("integrity={integrity}"));
    }
    if let Some(source) = component.source.as_deref() {
        parts.push(format!("cargo_source={source}"));
    }

    parts.join("; ")
}

fn decision_name(decision: &PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "ALLOW",
        PolicyDecision::AllowWithWarning => "ALLOW_WITH_WARNING",
        PolicyDecision::QuarantinePendingAnalysis => "QUARANTINE_PENDING_ANALYSIS",
        PolicyDecision::BlockKnownMalicious => "BLOCK_KNOWN_MALICIOUS",
        PolicyDecision::BlockPolicyViolation => "BLOCK_POLICY_VIOLATION",
        PolicyDecision::RequireHitlApproval => "REQUIRE_HITL_APPROVAL",
        PolicyDecision::FallbackToApprovedCandidate => "FALLBACK_TO_APPROVED_CANDIDATE",
    }
}

#[derive(Debug, Clone)]
struct RequirementsEntry {
    name: String,
    version: Option<String>,
    hash: Option<SbomHash>,
    integrity: Option<String>,
    constraint_eligible: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonschema::JSONSchema;
    use std::sync::OnceLock;
    use tempfile::tempdir;

    fn render_sample_requirements(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "requests==2.32.0 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let document = load_sbom_document(None, Some(path.as_path())).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_package_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        fs::write(
            &path,
            r#"{
    "name": "demo-app",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "demo-app",
            "version": "1.0.0",
            "dependencies": {
                "left-pad": "1.3.0"
            }
        },
        "node_modules/left-pad": {
            "version": "1.3.0",
            "integrity": "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }
    }
}"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_pnpm_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &path,
            r#"lockfileVersion: '9.0'
importers:
    .:
        dependencies:
            left-pad:
                version: 1.3.0
packages:
    left-pad@1.3.0:
        resolution:
            integrity: sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
snapshots:
    left-pad@1.3.0: {}
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true

[workspace]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "anyhow 1.0.100 (registry+https://github.com/rust-lang/crates.io-index)",
    "local-lib 0.2.0",
]

[[package]]
name = "anyhow"
version = "1.0.100"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

[[package]]
name = "local-lib"
version = "0.2.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_virtual_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let root_manifest = dir.path().join("Cargo.toml");
        let member_dir = dir.path().join("crates").join("demo-app");
        let member_manifest = member_dir.join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[workspace]
members = ["crates/demo-app"]
default-members = ["crates/demo-app"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_glob_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let root_manifest = dir.path().join("Cargo.toml");
        let member_dir = dir.path().join("crates").join("demo-app");
        let member_manifest = member_dir.join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[workspace]
members = ["crates/*"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_excluded_glob_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let root_manifest = dir.path().join("Cargo.toml");
        let member_dir = dir.path().join("crates").join("demo-app");
        let member_manifest = member_dir.join("Cargo.toml");
        let skipped_dir = dir.path().join("crates").join("skip-me");
        let skipped_manifest = skipped_dir.join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::create_dir_all(&member_dir).unwrap();
        fs::create_dir_all(&skipped_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[workspace]
members = ["crates/*"]
exclude = ["crates/skip-me"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &skipped_manifest,
            r#"[package]
name = "skip-me"
version = "9.9.9"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_explicit_member_exclude_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let root_manifest = dir.path().join("Cargo.toml");
        let member_dir = dir.path().join("pkg");
        let member_manifest = member_dir.join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[workspace]
members = ["pkg"]
default-members = ["pkg"]
exclude = ["pkg"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_excluded_default_member_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let root_manifest = dir.path().join("Cargo.toml");
        let skipped_dir = dir.path().join("crates").join("skip-me");
        let skipped_manifest = skipped_dir.join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::create_dir_all(&skipped_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[workspace]
members = ["crates/*"]
default-members = ["crates/skip-me"]
exclude = ["crates/skip-me"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &skipped_manifest,
            r#"[package]
name = "skip-me"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "skip-me"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_parent_glob_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let workspace_root = dir.path().join("workspace");
        let shared_crates_root = dir.path().join("crates");
        let root_manifest = workspace_root.join("Cargo.toml");
        let member_dir = shared_crates_root.join("demo-app");
        let member_manifest = member_dir.join("Cargo.toml");
        let skipped_dir = shared_crates_root.join("skip-me");
        let skipped_manifest = skipped_dir.join("Cargo.toml");
        let path = workspace_root.join("Cargo.lock");
        fs::create_dir_all(&workspace_root).unwrap();
        fs::create_dir_all(&member_dir).unwrap();
        fs::create_dir_all(&skipped_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[workspace]
members = ["../crates/*"]
exclude = ["../crates/skip-me"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &skipped_manifest,
            r#"[package]
name = "skip-me"
version = "9.9.9"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_parent_directory_excluded_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let root_manifest = dir.path().join("Cargo.toml");
        let member_dir = dir.path().join("crates").join("demo-app");
        let member_manifest = member_dir.join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[workspace]
members = ["crates/*"]
exclude = ["crates"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_non_virtual_default_member_workspace_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let root_manifest = dir.path().join("Cargo.toml");
        let root_src = dir.path().join("src").join("lib.rs");
        let member_dir = dir.path().join("crates").join("demo-app");
        let member_manifest = member_dir.join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::create_dir_all(root_src.parent().unwrap()).unwrap();
        fs::create_dir_all(&member_dir).unwrap();
        fs::write(
            &root_manifest,
            r#"[package]
name = "workspace-root"
version = "9.9.9"
edition = "2024"

[workspace]
members = ["crates/demo-app"]
default-members = ["crates/demo-app"]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(&root_src, "pub fn root() {}\n").unwrap();
        fs::write(
            &member_manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "workspace-root"
version = "9.9.9"

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn render_sample_same_name_local_dependency_cargo_lock(format: SbomFormat) -> Value {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version.workspace = true
edition.workspace = true

[workspace]

[workspace.package]
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "demo-app 2.0.0",
]

[[package]]
name = "demo-app"
version = "2.0.0"
dependencies = [
    "serde 1.0.228 (registry+https://github.com/rust-lang/crates.io-index)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        serde_json::from_str(&render_sbom(&document, format).unwrap()).unwrap()
    }

    fn validate_instance_against_schema(
        schema: &'static JSONSchema,
        instance: &Value,
        schema_name: &str,
    ) {
        if let Err(errors) = schema.validate(instance) {
            let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
            panic!(
                "rendered SBOM does not satisfy {schema_name}: {}",
                messages.join("; ")
            );
        }
    }

    fn cyclonedx_17_schema() -> &'static JSONSchema {
        static SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
        SCHEMA.get_or_init(|| {
            let schema_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/cyclonedx/1.7/bom-1.7.schema.json"
            ))
            .expect("CycloneDX 1.7 schema should parse");
            let spdx_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/cyclonedx/1.7/spdx.schema.json"
            ))
            .expect("CycloneDX SPDX companion schema should parse");
            let jsf_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/cyclonedx/1.7/jsf-0.82.schema.json"
            ))
            .expect("CycloneDX JSF companion schema should parse");
            let crypto_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/cyclonedx/1.7/cryptography-defs.schema.json"
            ))
            .expect("CycloneDX cryptography companion schema should parse");

            let mut options = JSONSchema::options();
            options
                .with_document(
                    "http://cyclonedx.org/schema/spdx.schema.json".to_owned(),
                    spdx_json,
                )
                .with_document(
                    "http://cyclonedx.org/schema/jsf-0.82.schema.json".to_owned(),
                    jsf_json,
                )
                .with_document(
                    "http://cyclonedx.org/schema/cryptography-defs.schema.json".to_owned(),
                    crypto_json,
                );
            options
                .compile(&schema_json)
                .expect("CycloneDX 1.7 schema should compile")
        })
    }

    fn cyclonedx_16_schema() -> &'static JSONSchema {
        static SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
        SCHEMA.get_or_init(|| {
            let schema_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/cyclonedx/1.6/bom-1.6.schema.json"
            ))
            .expect("CycloneDX 1.6 schema should parse");
            let spdx_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/cyclonedx/1.6/spdx.schema.json"
            ))
            .expect("CycloneDX SPDX companion schema should parse");
            let jsf_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/cyclonedx/1.6/jsf-0.82.schema.json"
            ))
            .expect("CycloneDX JSF companion schema should parse");

            let mut options = JSONSchema::options();
            options
                .with_document(
                    "http://cyclonedx.org/schema/spdx.schema.json".to_owned(),
                    spdx_json,
                )
                .with_document(
                    "http://cyclonedx.org/schema/jsf-0.82.schema.json".to_owned(),
                    jsf_json,
                );
            options
                .compile(&schema_json)
                .expect("CycloneDX 1.6 schema should compile")
        })
    }

    fn spdx_23_schema() -> &'static JSONSchema {
        static SCHEMA: OnceLock<JSONSchema> = OnceLock::new();
        SCHEMA.get_or_init(|| {
            let schema_json: Value = serde_json::from_str(include_str!(
                "../../../schemas/external/spdx/2.3/spdx-schema.json"
            ))
            .expect("SPDX 2.3 schema should parse");
            JSONSchema::compile(&schema_json).expect("SPDX 2.3 schema should compile")
        })
    }

    fn find_component_ref_by_purl<'a>(components: &'a [Value], purl: &str) -> &'a str {
        components
            .iter()
            .find(|component| component["purl"] == purl)
            .and_then(|component| component["bom-ref"].as_str())
            .expect("component ref should exist")
    }

    fn find_component_refs_by_purl(components: &[Value], purl: &str) -> Vec<String> {
        components
            .iter()
            .filter(|component| component["purl"] == purl)
            .filter_map(|component| component["bom-ref"].as_str().map(str::to_owned))
            .collect()
    }

    fn assert_dependency(dependencies: &[Value], from: &str, expected_targets: &[&str]) {
        let dependency = dependencies
            .iter()
            .find(|entry| entry["ref"] == from)
            .expect("dependency entry should exist");
        let depends_on = dependency["dependsOn"]
            .as_array()
            .expect("dependsOn should be an array")
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();
        assert_eq!(depends_on, expected_targets);
    }

    #[test]
    fn cyclonedx_preserves_nested_package_lock_relationships() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        fs::write(
            &path,
            r#"{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "demo-app",
      "version": "1.0.0",
      "dependencies": {
        "a": "1.0.0"
      }
    },
    "node_modules/a": {
      "version": "1.0.0",
      "integrity": "sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "dependencies": {
        "b": "2.0.0"
      }
    },
    "node_modules/a/node_modules/b": {
      "version": "2.0.0"
    }
  }
}"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();

        let components = rendered["components"].as_array().unwrap();
        let a_ref = find_component_ref_by_purl(components, "pkg:npm/a@1.0.0");
        let b_ref = find_component_ref_by_purl(components, "pkg:npm/b@2.0.0");
        let root_ref = rendered["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap();
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(rendered["specVersion"], "1.7");
        assert_dependency(dependencies, root_ref, &[a_ref]);
        assert_dependency(dependencies, a_ref, &[b_ref]);
    }

    #[test]
    fn cyclonedx_preserves_workspace_package_lock_relationships() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        fs::write(
            &path,
            r#"{
    "name": "demo-workspace",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "demo-workspace",
            "version": "1.0.0",
            "dependencies": {
                "eslint": "9.0.0"
            }
        },
        "node_modules/eslint": {
            "version": "9.0.0"
        },
        "packages/web": {
            "dependencies": {
                "react": "19.1.0"
            }
        },
        "packages/web/node_modules/react": {
            "version": "19.1.0"
        }
    }
}"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();

        let components = rendered["components"].as_array().unwrap();
        let eslint_ref = find_component_ref_by_purl(components, "pkg:npm/eslint@9.0.0");
        let react_ref = find_component_ref_by_purl(components, "pkg:npm/react@19.1.0");
        let root_ref = rendered["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap();
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_dependency(dependencies, root_ref, &[eslint_ref, react_ref]);
    }

    #[test]
    fn spdx_contains_required_document_and_package_fields() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("requirements.txt");
        fs::write(
            &path,
            "requests==2.32.0 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let document = load_sbom_document(None, Some(path.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::Spdx23Json).unwrap()).unwrap();

        assert_eq!(rendered["spdxVersion"], "SPDX-2.3");
        assert_eq!(rendered["dataLicense"], "CC0-1.0");
        assert!(
            rendered["documentNamespace"]
                .as_str()
                .unwrap()
                .starts_with("https://aegiscudo.invalid/spdxdocs/")
        );

        let packages = rendered["packages"].as_array().unwrap();
        let requests = packages
            .iter()
            .find(|package| package["name"] == "requests")
            .unwrap();
        assert_eq!(requests["externalRefs"][0]["referenceType"], "purl");
        assert_eq!(requests["checksums"][0]["algorithm"], "SHA256");
        assert!(
            requests["comment"]
                .as_str()
                .unwrap()
                .contains("Aegiscudo decision unresolved")
        );
    }

    #[test]
    fn cyclonedx_17_output_validates_against_official_schema() {
        let rendered = render_sample_requirements(SbomFormat::CyclonedxJson);

        validate_instance_against_schema(cyclonedx_17_schema(), &rendered, "CycloneDX 1.7");
    }

    #[test]
    fn cyclonedx_16_output_validates_against_official_schema() {
        let rendered = render_sample_requirements(SbomFormat::Cyclonedx16Json);

        validate_instance_against_schema(cyclonedx_16_schema(), &rendered, "CycloneDX 1.6");
    }

    #[test]
    fn spdx_23_output_validates_against_official_schema() {
        let rendered = render_sample_requirements(SbomFormat::Spdx23Json);

        validate_instance_against_schema(spdx_23_schema(), &rendered, "SPDX 2.3");
    }

    #[test]
    fn package_lock_output_validates_against_official_schemas() {
        let cyclonedx_17 = render_sample_package_lock(SbomFormat::CyclonedxJson);
        let cyclonedx_16 = render_sample_package_lock(SbomFormat::Cyclonedx16Json);
        let spdx_23 = render_sample_package_lock(SbomFormat::Spdx23Json);

        validate_instance_against_schema(cyclonedx_17_schema(), &cyclonedx_17, "CycloneDX 1.7");
        validate_instance_against_schema(cyclonedx_16_schema(), &cyclonedx_16, "CycloneDX 1.6");
        validate_instance_against_schema(spdx_23_schema(), &spdx_23, "SPDX 2.3");
    }

    #[test]
    fn pnpm_output_validates_against_official_schemas() {
        let cyclonedx_17 = render_sample_pnpm_lock(SbomFormat::CyclonedxJson);
        let cyclonedx_16 = render_sample_pnpm_lock(SbomFormat::Cyclonedx16Json);
        let spdx_23 = render_sample_pnpm_lock(SbomFormat::Spdx23Json);

        validate_instance_against_schema(cyclonedx_17_schema(), &cyclonedx_17, "CycloneDX 1.7");
        validate_instance_against_schema(cyclonedx_16_schema(), &cyclonedx_16, "CycloneDX 1.6");
        validate_instance_against_schema(spdx_23_schema(), &spdx_23, "SPDX 2.3");
    }

    #[test]
    fn pnpm_preserves_peer_qualified_keys_and_exact_root_dependencies() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("pnpm-lock.yaml");
        fs::write(
            &path,
            "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      react-dom:\n        version: 19.1.0(react@19.1.0)\n\npackages:\n  react@19.1.0:\n    resolution: {integrity: sha512-react-a==}\n  react@19.2.0:\n    resolution: {integrity: sha512-react-b==}\n  react-dom@19.1.0(react@19.1.0):\n    resolution: {integrity: sha512-rd-a==}\n  react-dom@19.1.0(react@19.2.0):\n    resolution: {integrity: sha512-rd-b==}\n\nsnapshots:\n  react-dom@19.1.0(react@19.1.0):\n    dependencies:\n      react:\n        version: 19.1.0\n  react-dom@19.1.0(react@19.2.0):\n    dependencies:\n      react:\n        version: 19.2.0\n",
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();

        let components = rendered["components"].as_array().unwrap();
        let react_dom_refs = find_component_refs_by_purl(components, "pkg:npm/react-dom@19.1.0");
        let root_ref = rendered["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap();
        let dependencies = rendered["dependencies"].as_array().unwrap();
        let root_depends_on = dependencies
            .iter()
            .find(|entry| entry["ref"] == root_ref)
            .unwrap()["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();

        assert_eq!(react_dom_refs.len(), 2);
        assert_eq!(
            root_depends_on
                .iter()
                .filter(|reference| react_dom_refs
                    .iter()
                    .any(|candidate| candidate == *reference))
                .count(),
            1
        );
    }

    #[test]
    fn cargo_lock_preserves_root_and_dependency_relationships() {
        let rendered = render_sample_cargo_lock(SbomFormat::CyclonedxJson);
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let dependencies = rendered["dependencies"].as_array().unwrap();
        let anyhow_ref = find_component_ref_by_purl(components, "pkg:cargo/anyhow@1.0.100");
        let local_lib_ref = find_component_ref_by_purl(components, "pkg:cargo/local-lib@0.2.0");
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .all(|component| component["purl"] != "pkg:cargo/demo-app@0.1.0")
        );
        assert_dependency(dependencies, root_ref, &[anyhow_ref, local_lib_ref]);
        assert_dependency(dependencies, local_lib_ref, &[serde_ref]);
        assert_eq!(
            components
                .iter()
                .find(|component| component["purl"] == "pkg:cargo/anyhow@1.0.100")
                .unwrap()["hashes"][0]["alg"],
            "SHA-256"
        );
    }

    #[test]
    fn cargo_lock_output_validates_against_official_schemas() {
        let cyclonedx_17 = render_sample_cargo_lock(SbomFormat::CyclonedxJson);
        let cyclonedx_16 = render_sample_cargo_lock(SbomFormat::Cyclonedx16Json);
        let spdx_23 = render_sample_cargo_lock(SbomFormat::Spdx23Json);

        validate_instance_against_schema(cyclonedx_17_schema(), &cyclonedx_17, "CycloneDX 1.7");
        validate_instance_against_schema(cyclonedx_16_schema(), &cyclonedx_16, "CycloneDX 1.6");
        validate_instance_against_schema(spdx_23_schema(), &spdx_23, "SPDX 2.3");
    }

    #[test]
    fn virtual_workspace_cargo_lock_output_validates_against_official_schemas() {
        let cyclonedx_17 = render_sample_virtual_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let cyclonedx_16 = render_sample_virtual_workspace_cargo_lock(SbomFormat::Cyclonedx16Json);
        let spdx_23 = render_sample_virtual_workspace_cargo_lock(SbomFormat::Spdx23Json);

        validate_instance_against_schema(cyclonedx_17_schema(), &cyclonedx_17, "CycloneDX 1.7");
        validate_instance_against_schema(cyclonedx_16_schema(), &cyclonedx_16, "CycloneDX 1.6");
        validate_instance_against_schema(spdx_23_schema(), &spdx_23, "SPDX 2.3");
    }

    #[test]
    fn cargo_lock_uses_default_member_for_virtual_workspace_root() {
        let rendered = render_sample_virtual_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .all(|component| component["purl"] != "pkg:cargo/demo-app@0.1.0")
        );
        assert_dependency(dependencies, root_ref, &[serde_ref]);
    }

    #[test]
    fn cargo_lock_uses_globbed_workspace_member_for_root() {
        let rendered = render_sample_glob_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .all(|component| component["purl"] != "pkg:cargo/demo-app@0.1.0")
        );
        assert_dependency(dependencies, root_ref, &[serde_ref]);
    }

    #[test]
    fn cargo_lock_ignores_excluded_glob_workspace_members_for_root() {
        let rendered = render_sample_excluded_glob_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .all(|component| component["purl"] != "pkg:cargo/demo-app@0.1.0")
        );
        assert_dependency(dependencies, root_ref, &[serde_ref]);
    }

    #[test]
    fn cargo_lock_preserves_explicit_workspace_member_root_despite_exclude() {
        let rendered =
            render_sample_explicit_member_exclude_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .all(|component| component["purl"] != "pkg:cargo/demo-app@0.1.0")
        );
        assert_dependency(dependencies, root_ref, &[serde_ref]);
    }

    #[test]
    fn cargo_lock_ignores_excluded_default_members_for_root() {
        let rendered =
            render_sample_excluded_default_member_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let root = &rendered["metadata"]["component"];
        let components = rendered["components"].as_array().unwrap();

        assert_eq!(root["name"], "Cargo");
        assert!(root["purl"].is_null());
        assert!(
            components
                .iter()
                .any(|component| component["purl"] == "pkg:cargo/skip-me@0.1.0")
        );
    }

    #[test]
    fn cargo_lock_ignores_excluded_parent_glob_workspace_members_for_root() {
        let rendered = render_sample_parent_glob_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .all(|component| component["purl"] != "pkg:cargo/demo-app@0.1.0")
        );
        assert_dependency(dependencies, root_ref, &[serde_ref]);
    }

    #[test]
    fn cargo_lock_excludes_parent_directory_members_from_root_inference() {
        let rendered =
            render_sample_parent_directory_excluded_workspace_cargo_lock(SbomFormat::CyclonedxJson);
        let root = &rendered["metadata"]["component"];

        assert_eq!(root["name"], "Cargo");
        assert_eq!(root["bom-ref"], "aegiscudo-root:cargo");
        assert!(root.get("purl").is_none_or(|value| value.is_null()));
    }

    #[test]
    fn cargo_lock_uses_default_member_for_non_virtual_workspace_root() {
        let rendered = render_sample_non_virtual_default_member_workspace_cargo_lock(
            SbomFormat::CyclonedxJson,
        );
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .any(|component| { component["purl"] == "pkg:cargo/workspace-root@9.9.9" })
        );
        assert_dependency(dependencies, root_ref, &[serde_ref]);
    }

    #[test]
    fn cargo_lock_uses_workspace_inherited_version_to_disambiguate_root() {
        let rendered =
            render_sample_same_name_local_dependency_cargo_lock(SbomFormat::CyclonedxJson);
        let components = rendered["components"].as_array().unwrap();
        let root = &rendered["metadata"]["component"];
        let root_ref = root["bom-ref"].as_str().unwrap();
        let renamed_local_dep_ref =
            find_component_ref_by_purl(components, "pkg:cargo/demo-app@2.0.0");
        let serde_ref = find_component_ref_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();

        assert_eq!(root["purl"], "pkg:cargo/demo-app@0.1.0");
        assert!(
            components
                .iter()
                .all(|component| component["purl"] != "pkg:cargo/demo-app@0.1.0")
        );
        assert_dependency(dependencies, root_ref, &[renamed_local_dep_ref]);
        assert_dependency(dependencies, renamed_local_dep_ref, &[serde_ref]);
    }

    #[test]
    fn cargo_lock_uses_distinct_references_for_colliding_source_names() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "serde 1.0.228",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "git+https://example.invalid/a-b?rev=deadbeef#deadbeef"

[[package]]
name = "serde"
version = "1.0.228"
source = "git+https://example.invalid/a/b?rev=deadbeef#deadbeef"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();

        let components = rendered["components"].as_array().unwrap();
        let root_ref = rendered["metadata"]["component"]["bom-ref"]
            .as_str()
            .unwrap();
        let dependencies = rendered["dependencies"].as_array().unwrap();
        let serde_refs = find_component_refs_by_purl(components, "pkg:cargo/serde@1.0.228");
        let unique_refs = serde_refs.iter().cloned().collect::<BTreeSet<_>>();
        let cargo_sources = components
            .iter()
            .filter(|component| component["purl"] == "pkg:cargo/serde@1.0.228")
            .map(|component| {
                component["properties"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|property| property["name"] == "aegiscudo:cargo_source")
                    .unwrap()["value"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        let dependency = dependencies
            .iter()
            .find(|entry| entry["ref"] == root_ref)
            .unwrap();
        let depends_on = dependency["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<BTreeSet<_>>();
        let expected_refs = serde_refs
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();

        assert_eq!(serde_refs.len(), 2);
        assert_eq!(unique_refs.len(), 2);
        assert_eq!(
            cargo_sources,
            BTreeSet::from([
                "git+https://example.invalid/a-b?rev=deadbeef#deadbeef".to_owned(),
                "git+https://example.invalid/a/b?rev=deadbeef#deadbeef".to_owned(),
            ])
        );
        assert_eq!(depends_on.len(), 2);
        assert_eq!(depends_on, expected_refs);

        let rendered_spdx: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::Spdx23Json).unwrap()).unwrap();
        let cargo_source_comments = rendered_spdx["packages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|package| package["name"] == "serde")
            .filter_map(|package| package["comment"].as_str())
            .filter_map(|comment| {
                comment
                    .split("; ")
                    .find_map(|part| part.strip_prefix("cargo_source="))
                    .map(str::to_owned)
            })
            .collect::<BTreeSet<_>>();

        assert_eq!(cargo_source_comments, cargo_sources);
    }

    #[test]
    fn cargo_lock_preserves_ambiguous_non_root_dependency_edges() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "local-lib 0.2.0",
]

[[package]]
name = "local-lib"
version = "0.2.0"
dependencies = [
    "serde 1.0.228",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

[[package]]
name = "serde"
version = "1.0.228"
source = "git+https://example.invalid/serde?rev=deadbeef#deadbeef"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();

        let components = rendered["components"].as_array().unwrap();
        let local_lib_ref = find_component_ref_by_purl(components, "pkg:cargo/local-lib@0.2.0");
        let serde_refs = find_component_refs_by_purl(components, "pkg:cargo/serde@1.0.228");
        let dependencies = rendered["dependencies"].as_array().unwrap();
        let local_lib_entry = dependencies
            .iter()
            .find(|entry| entry["ref"] == local_lib_ref)
            .unwrap();
        let depends_on = local_lib_entry["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();

        assert_eq!(serde_refs.len(), 2);
        assert_eq!(depends_on.len(), 2);
        assert!(
            serde_refs
                .iter()
                .all(|reference| depends_on.contains(&reference.as_str()))
        );
    }

    #[test]
    fn cyclonedx_emits_standard_hash_for_sha512_sri() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("package-lock.json");
        let sri = format!("sha512-{}", BASE64_STANDARD.encode([0_u8; 64]));
        fs::write(
            &path,
            format!(
                r#"{{
  "name": "demo-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
    "packages": {{
        "": {{
      "name": "demo-app",
      "version": "1.0.0",
            "dependencies": {{
        "left-pad": "1.3.0"
            }}
        }},
        "node_modules/left-pad": {{
      "version": "1.3.0",
            "integrity": "{}"
        }}
    }}
}}"#,
                sri
            ),
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let components = rendered["components"].as_array().unwrap();
        let component = components
            .iter()
            .find(|component| component["purl"] == "pkg:npm/left-pad@1.3.0")
            .unwrap();

        assert_eq!(component["hashes"][0]["alg"], "SHA-512");
    }

    #[test]
    fn requirements_includes_are_resolved_recursively() {
        let dir = tempdir().unwrap();
        let base = dir.path().join("base.txt");
        let root = dir.path().join("requirements.txt");
        fs::write(&base, "urllib3==2.2.1\n").unwrap();
        fs::write(
            &root,
            "-r base.txt\nrequests==2.32.0 \\\n+    --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
                .replace("\n+    ", "\n    "),
        )
        .unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let purls = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|component| component["purl"].as_str())
            .collect::<Vec<_>>();

        assert!(purls.contains(&"pkg:pypi/requests@2.32.0"));
        assert!(purls.contains(&"pkg:pypi/urllib3@2.2.1"));
    }

    #[test]
    fn requirements_constraints_are_applied_to_unversioned_entries() {
        let dir = tempdir().unwrap();
        let constraints = dir.path().join("constraints.txt");
        let root = dir.path().join("requirements.txt");
        fs::write(&constraints, "requests==2.32.0\n").unwrap();
        fs::write(&root, "requests\n-c constraints.txt\n").unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let purls = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|component| component["purl"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(purls, vec!["pkg:pypi/requests@2.32.0"]);
    }

    #[test]
    fn requirements_constraints_are_applied_across_normalized_names() {
        let dir = tempdir().unwrap();
        let constraints = dir.path().join("constraints.txt");
        let root = dir.path().join("requirements.txt");
        fs::write(&constraints, "friendly.bard==1.2.3\n").unwrap();
        fs::write(&root, "Friendly_Bard\n-c constraints.txt\n").unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let purls = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|component| component["purl"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(purls, vec!["pkg:pypi/friendly-bard@1.2.3"]);
    }

    #[test]
    fn requirements_constraints_reject_conflicting_pins() {
        let dir = tempdir().unwrap();
        let constraints = dir.path().join("constraints.txt");
        let root = dir.path().join("requirements.txt");
        fs::write(&constraints, "requests==2.32.0\n").unwrap();
        fs::write(&root, "requests==2.31.0\n-c constraints.txt\n").unwrap();

        let error = load_sbom_document(None, Some(root.as_path())).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("conflicts with constraint version")
        );
    }

    #[test]
    fn requirements_constraints_reject_direct_references() {
        let dir = tempdir().unwrap();
        let constraints = dir.path().join("constraints.txt");
        let root = dir.path().join("requirements.txt");
        fs::write(
            &constraints,
            "demo @ https://example.invalid/demo-1.0.0.tar.gz\n",
        )
        .unwrap();
        fs::write(&root, "demo\n-c constraints.txt\n").unwrap();

        let error = load_sbom_document(None, Some(root.as_path())).unwrap_err();
        let error_text = format!("{error:#}");

        assert!(error_text.contains("unsupported direct reference"));
    }

    #[test]
    fn requirements_non_package_directives_are_ignored() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        fs::write(
            &root,
            "--index-url https://example.invalid/simple\n--extra-index-url=https://mirror.invalid/simple\nrequests==2.32.0\n",
        )
        .unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let purls = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|component| component["purl"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(purls, vec!["pkg:pypi/requests@2.32.0"]);
    }

    #[test]
    fn requirements_pep_508_syntax_is_normalized() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        fs::write(
            &root,
            "requests[socks]==2.32.0\nurllib3==2.2.2; python_version < \"3.13\"\n",
        )
        .unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let purls = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|component| component["purl"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            purls,
            vec!["pkg:pypi/requests@2.32.0", "pkg:pypi/urllib3@2.2.2"]
        );
    }

    #[test]
    fn editable_requirements_are_included() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        fs::write(&root, "-e git+https://example.invalid/demo.git#egg=demo\n").unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let purls = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|component| component["purl"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(purls, vec!["pkg:pypi/demo"]);
    }

    #[test]
    fn requirements_direct_reference_hash_fragments_are_preserved() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        fs::write(
            &root,
            "demo @ https://example.invalid/demo-1.0.0.tar.gz#sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/demo")
            .unwrap();

        assert_eq!(component["hashes"][0]["alg"], "SHA-256");
        assert_eq!(
            component["hashes"][0]["content"],
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
    }

    #[test]
    fn duplicate_requirements_are_deduplicated() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        fs::write(&root, "requests==2.32.0\nrequests==2.32.0\n").unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let purls = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|component| component["purl"].as_str())
            .collect::<Vec<_>>();

        assert_eq!(purls, vec!["pkg:pypi/requests@2.32.0"]);
    }

    #[test]
    fn conflicting_duplicate_requirement_hashes_drop_hashes() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        fs::write(
            &root,
            "requests==2.32.0 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nrequests==2.32.0 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/requests@2.32.0")
            .unwrap();

        assert!(component["hashes"].is_null());
    }

    #[test]
    fn conflicting_duplicate_requirement_hashes_drop_hashes_across_name_spellings() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        fs::write(
            &root,
            "Friendly_Bard==1.2.3 --hash=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nfriendly-bard==1.2.3 --hash=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
        )
        .unwrap();

        let document = load_sbom_document(None, Some(root.as_path())).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();
        let component = rendered["components"]
            .as_array()
            .unwrap()
            .iter()
            .find(|component| component["purl"] == "pkg:pypi/friendly-bard@1.2.3")
            .unwrap();

        assert!(component["hashes"].is_null());
    }

    #[test]
    fn cargo_lock_leaves_unmatched_source_qualified_dependencies_unresolved() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("Cargo.toml");
        let path = dir.path().join("Cargo.lock");
        fs::write(
            &manifest,
            r#"[package]
name = "demo-app"
version = "0.1.0"
edition = "2024"
"#,
        )
        .unwrap();
        fs::write(
            &path,
            r#"version = 4

[[package]]
name = "demo-app"
version = "0.1.0"
dependencies = [
    "local-lib 0.2.0",
]

[[package]]
name = "local-lib"
version = "0.2.0"
dependencies = [
    "serde 1.0.228 (git+https://example.invalid/missing?rev=deadbeef#deadbeef)",
]

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"

[[package]]
name = "serde"
version = "1.0.228"
source = "git+https://example.invalid/serde?rev=facefeed#facefeed"
"#,
        )
        .unwrap();

        let document = load_sbom_document(Some(path.as_path()), None).unwrap();
        let rendered: Value =
            serde_json::from_str(&render_sbom(&document, SbomFormat::CyclonedxJson).unwrap())
                .unwrap();

        let components = rendered["components"].as_array().unwrap();
        let local_lib_ref = find_component_ref_by_purl(components, "pkg:cargo/local-lib@0.2.0");
        let dependencies = rendered["dependencies"].as_array().unwrap();
        let local_lib_entry = dependencies
            .iter()
            .find(|entry| entry["ref"] == local_lib_ref)
            .unwrap();
        let depends_on = local_lib_entry["dependsOn"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .collect::<Vec<_>>();

        assert!(depends_on.is_empty());
    }
}
