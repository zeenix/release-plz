use std::collections::{BTreeMap, HashMap, HashSet, hash_map::Entry};

use anyhow::Context;
use cargo::{
    GlobalContext,
    core::{
        Dependency, FeatureValue, PackageId, Resolve, SourceId, Workspace,
        dependency::{DepKind, Patch},
        resolver::ResolveBehavior,
    },
    util::{
        CanonicalUrl,
        interning::{INTERNED_DEFAULT, InternedString},
    },
};
use cargo_metadata::{Metadata, camino::Utf8Path, semver::Version};
use tracing::{debug, warn};

use crate::registry_packages::ReleasedWorkspace;

/// The dependency graph decoded from a workspace lockfile.
///
/// Cargo's `Resolve` uses `Rc` internally, so it cannot be shared by release workers.
/// Retain the package IDs, original edges and replacements in thread-safe collections.
#[derive(Debug)]
pub(crate) struct WorkspaceLockfile {
    dependencies: HashMap<PackageId, Vec<PackageId>>,
    replacements: HashMap<PackageId, PackageId>,
}

impl WorkspaceLockfile {
    pub(crate) fn from_resolve(resolve: &Resolve) -> Self {
        Self {
            dependencies: resolve
                .iter()
                .map(|id| {
                    let dependencies = resolve
                        .deps_not_replaced(id)
                        .map(|(dependency, _)| dependency)
                        .collect();
                    (id, dependencies)
                })
                .collect(),
            replacements: resolve.replacements().clone(),
        }
    }

    /// The package that replaces `id` through `[replace]`, or `id` itself.
    fn replaced(&self, id: PackageId) -> PackageId {
        self.replacements.get(&id).copied().unwrap_or(id)
    }
}

/// Compare the package's reachable locked dependencies in the local and registry workspaces.
/// Only version changes to previously released dependencies count.
pub fn are_lock_dependencies_updated(
    local_metadata: &Metadata,
    registry_package: &Utf8Path,
    package_name: &str,
) -> anyhow::Result<bool> {
    if !local_metadata.workspace_root.join("Cargo.lock").exists() {
        return Ok(false);
    }
    let registry_metadata = cargo_utils::cargo_metadata_command()
        .current_dir(registry_package)
        .no_deps()
        .manifest_path(registry_package.join("Cargo.toml"))
        .exec()
        .context("cannot load metadata of registry package")?;
    let registry_lock_path = registry_metadata.workspace_root.join("Cargo.lock");
    if !registry_lock_path.exists() {
        return Ok(false);
    }
    let local_context =
        crate::cargo::new_cargo_config(Some(local_metadata.workspace_root.clone()))?;
    let local_workspace = load_workspace(local_metadata, &local_context)?;
    let local_lock = local_lock_dependencies(&local_workspace, local_metadata, package_name)?;
    let registry_context =
        crate::cargo::new_cargo_config(Some(registry_metadata.workspace_root.clone()))?;
    let registry_workspace = load_workspace(&registry_metadata, &registry_context)?;
    let package = cargo_utils::workspace_package(&registry_metadata, package_name)?;
    let Some(registry_lock) =
        workspace_lock_dependencies(&registry_workspace, &registry_metadata, package, None)?
    else {
        warn!(
            "package {package_name} is not in the registry lockfile {registry_lock_path:?}: \
             the lockfile was stale when the package was released. \
             Assuming its dependencies changed."
        );
        return Ok(true);
    };
    Ok(are_dependencies_updated(&local_lock, &registry_lock))
}

/// Compare only dependencies reachable from a package in a released workspace lockfile.
///
/// The released workspace lockfile is the workspace-root `Cargo.lock` committed at the
/// git-only package's latest release tag, preserved in [`ReleasedWorkspace::lockfile`].
/// The local lockfile is read from disk.
pub(crate) fn are_workspace_lock_dependencies_updated(
    local_metadata: &Metadata,
    released_workspace: &ReleasedWorkspace,
    package_name: &str,
) -> anyhow::Result<bool> {
    let Some(lockfile) = released_workspace.lockfile() else {
        return Ok(false);
    };
    if !local_metadata.workspace_root.join("Cargo.lock").exists() {
        return Ok(false);
    }
    let local_context =
        crate::cargo::new_cargo_config(Some(local_metadata.workspace_root.clone()))?;
    let local_workspace = load_workspace(local_metadata, &local_context)?;
    let local = local_lock_dependencies(&local_workspace, local_metadata, package_name)?;
    let released_context =
        crate::cargo::new_cargo_config(Some(released_workspace.metadata.workspace_root.clone()))?;
    let cargo_workspace = load_workspace(&released_workspace.metadata, &released_context)?;
    let released_package =
        cargo_utils::workspace_package(&released_workspace.metadata, package_name)?;
    let Some(released) = workspace_lock_dependencies(
        &cargo_workspace,
        &released_workspace.metadata,
        released_package,
        Some(lockfile),
    )?
    else {
        // The old release’s lockfile is inconsistent, so we can’t reliably compare dependencies.
        // Warn and treat them as changed.
        warn!(
            "package {package_name} is not in the Cargo.lock committed at {}: \
             the lockfile was stale when the package was released. \
             Assuming its dependencies changed.",
            released_workspace.commit
        );
        return Ok(true);
    };
    Ok(are_dependencies_updated(&local, &released))
}

/// Load the workspace of `metadata` with the Cargo library bundled in release-plz.
fn load_workspace<'a>(
    metadata: &Metadata,
    context: &'a GlobalContext,
) -> anyhow::Result<Workspace<'a>> {
    let manifest = metadata.workspace_root.join("Cargo.toml");
    Workspace::new(manifest.as_std_path(), context).with_context(|| {
        format!(
            "cannot load workspace manifest {manifest:?} with the Cargo library bundled in release-plz"
        )
    })
}

/// Collect the local package's locked dependencies, with a hint if its lockfile is stale.
fn local_lock_dependencies(
    workspace: &Workspace<'_>,
    metadata: &Metadata,
    package_name: &str,
) -> anyhow::Result<LockedPackage> {
    let package = cargo_utils::workspace_package(metadata, package_name)?;
    // The user can fix the local lockfile.
    workspace_lock_dependencies(workspace, metadata, package, None)?.with_context(|| {
        format!(
            "cannot find package {package_name:?} {} in lockfile {:?}. Hint: run `cargo check` to update the lockfile and commit it.",
            package.version,
            metadata.workspace_root.join("Cargo.lock")
        )
    })
}

/// Find the workspace `package` in the workspace lockfile, with the dependencies its build can
/// reach.
///
/// Use the cached graph when provided; otherwise read the lockfile from disk.
/// Returns `None` when the lockfile is stale, i.e. it doesn't contain the package at
/// the version declared in its manifest.
fn workspace_lock_dependencies(
    workspace: &Workspace<'_>,
    metadata: &Metadata,
    package: &cargo_metadata::Package,
    lockfile: Option<&WorkspaceLockfile>,
) -> anyhow::Result<Option<LockedPackage>> {
    let lock_path = metadata.workspace_root.join("Cargo.lock");
    let loaded_lockfile;
    let lockfile = match lockfile {
        Some(lockfile) => lockfile,
        None => {
            // Decode the local lockfile without resolving or fetching dependencies.
            let resolve = cargo::ops::load_pkg_lockfile(workspace)
                .with_context(|| format!("cannot load workspace lockfile {lock_path:?}"))?
                .with_context(|| format!("workspace lockfile {lock_path:?} is missing"))?;
            loaded_lockfile = WorkspaceLockfile::from_resolve(&resolve);
            &loaded_lockfile
        }
    };
    let patches = workspace
        .root_patch()?
        .into_iter()
        .map(|(url, patches)| Ok((CanonicalUrl::new(&url)?, patches)))
        .collect::<anyhow::Result<HashMap<_, _>>>()?;
    let Some(root) = lockfile.dependencies.keys().copied().find(|id| {
        id.name().as_str() == package.name.as_str()
            && id.version() == &package.version
            && id.source_id().is_path()
    }) else {
        return Ok(None);
    };
    let (edges, members) = reachable_lock_dependencies(lockfile, workspace, root, &patches);
    Ok(Some(LockedPackage {
        root,
        edges,
        members,
    }))
}

/// Collect the lockfile edges that a build of `root`, with any of its features, uses.
///
/// A loaded lockfile has no dependency kinds or features: it records optional dependencies
/// whether or not a feature enables them, and dev-dependencies next to the others. Workspace
/// manifests tell these edges apart, so dev-dependencies of workspace members are skipped,
/// and so are their optional dependencies unless an enabled feature activates them. Every
/// edge of a package outside the workspace is followed, since its manifest isn't available.
///
/// Resolver 1 enables the features that dev-dependencies request in every build, so with it,
/// all the features of the members count.
///
/// Returns the dependencies, after `[replace]`, of each reached package, and the declarations
/// of each reached workspace member.
fn reachable_lock_dependencies(
    lockfile: &WorkspaceLockfile,
    workspace: &Workspace<'_>,
    root: PackageId,
    patches: &HashMap<CanonicalUrl, Vec<Patch>>,
) -> (
    HashMap<PackageId, HashSet<PackageId>>,
    HashMap<PackageId, MemberDeclarations>,
) {
    let members: HashMap<_, _> = workspace
        .members()
        .map(|package| (package.package_id(), package))
        .collect();
    let all_features = workspace.resolve_behavior() == ResolveBehavior::V1;
    // Features requested from each reached member. They are feature values, so the
    // `dependency/feature` syntax of a dependency declaration's features is kept.
    let mut requested: HashMap<PackageId, HashSet<InternedString>> = HashMap::new();
    let mut declarations = HashMap::new();
    let mut edges: HashMap<PackageId, HashSet<PackageId>> = HashMap::new();
    let mut member_declarations = HashMap::new();
    let mut pending = vec![(root, FeatureRequest::All)];
    while let Some((id, request)) = pending.pop() {
        let Some(&package) = members.get(&id) else {
            if let Entry::Vacant(entry) = edges.entry(id) {
                let dependencies = entry.insert(HashSet::new());
                for &dependency in &lockfile.dependencies[&id] {
                    let dependency = lockfile.replaced(dependency);
                    dependencies.insert(dependency);
                    pending.push((dependency, FeatureRequest::All));
                }
            }
            continue;
        };
        let features = requested.entry(id).or_default();
        let requested_count = features.len();
        match request {
            FeatureRequest::Features(request) if !all_features => features.extend(request),
            _ => features.extend(package.summary().features().keys()),
        }
        // A member is visited again only when more of its features are enabled.
        if edges.contains_key(&id) && features.len() == requested_count {
            continue;
        }
        let activation = Activation::new(package, features);
        let package_declarations = package.dependencies();
        member_declarations.insert(
            id,
            MemberDeclarations {
                declarations: package_declarations.to_vec(),
                active: (0..package_declarations.len())
                    .filter(|&i| activation.is_active(&package_declarations[i]))
                    .collect(),
            },
        );
        let declarations = declarations.entry(id).or_insert_with(|| {
            resolved_declarations(
                package_declarations,
                &lockfile.dependencies[&id],
                |declaration, edge| matches_edge(declaration, edge, patches),
            )
        });
        let package_edges = edges.entry(id).or_default();
        for &dependency in &lockfile.dependencies[&id] {
            // Classify the original edge before following `[replace]`, so its declared
            // source is not confused with a dev alias pointing at the replacement.
            let resolved = &declarations[&dependency];
            let request = if resolved.is_empty() {
                FeatureRequest::All
            } else {
                let mut active = false;
                let mut dependency_features = Vec::new();
                let resolved = resolved.iter().map(|&i| &package_declarations[i]);
                for declaration in resolved.filter(|d| activation.is_active(d)) {
                    active = true;
                    dependency_features.extend(declaration.features());
                    if declaration.uses_default_features() {
                        dependency_features.push(INTERNED_DEFAULT);
                    }
                    if let Some(features) = activation
                        .dependency_features
                        .get(&declaration.name_in_toml())
                    {
                        dependency_features.extend(features);
                    }
                }
                if !active {
                    continue;
                }
                FeatureRequest::Features(dependency_features)
            };
            let dependency = lockfile.replaced(dependency);
            package_edges.insert(dependency);
            pending.push((dependency, request));
        }
    }
    (edges, member_declarations)
}

/// The features requested from a package reached in the lockfile.
enum FeatureRequest {
    /// The package is the root, or it's reached from a package whose manifest isn't
    /// available, so any of its features can be enabled.
    All,
    Features(Vec<InternedString>),
}

/// The declarations of a workspace member that resolve each of its lockfile edges.
///
/// A lockfile doesn't record which declaration an edge comes from, and a requirement can match
/// more than one locked version: `>=1, <3` matches both `1.3.2` and `2.13.2`. Cargo resolves
/// each declaration to one edge, and every edge comes from a declaration, so the only
/// declaration matching an edge resolves that edge and no other. Declarations still matching
/// several edges count for each of them. Edges no declaration matches get none.
///
/// `matches` tells whether an edge can come from a declaration. Returns the indices of the
/// declarations resolving each edge.
fn resolved_declarations(
    declarations: &[Dependency],
    edges: &[PackageId],
    matches: impl Fn(&Dependency, PackageId) -> bool,
) -> HashMap<PackageId, Vec<usize>> {
    let mut candidates: Vec<Vec<PackageId>> = declarations
        .iter()
        .map(|declaration| {
            edges
                .iter()
                .copied()
                .filter(|&edge| matches(declaration, edge))
                .collect()
        })
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for &edge in edges {
            let mut matching = (0..candidates.len()).filter(|&i| candidates[i].contains(&edge));
            let only = match (matching.next(), matching.next()) {
                (Some(index), None) => Some(index),
                _ => None,
            };
            if let Some(index) = only
                && candidates[index].len() > 1
            {
                candidates[index] = vec![edge];
                changed = true;
            }
        }
    }
    let mut resolved: HashMap<_, Vec<_>> = edges.iter().map(|&edge| (edge, Vec::new())).collect();
    for (index, candidates) in candidates.into_iter().enumerate() {
        for edge in candidates {
            if let Some(resolved) = resolved.get_mut(&edge) {
                resolved.push(index);
            }
        }
    }
    resolved
}

/// Whether the lockfile edge to `id` can come from the declaration.
fn matches_edge(
    declaration: &Dependency,
    id: PackageId,
    patches: &HashMap<CanonicalUrl, Vec<Patch>>,
) -> bool {
    declaration.matches_id(id)
        // A patched normal/build declaration can resolve to the same package
        // as a dev declaration with a directly matching source. Include both.
        || (declaration.matches_ignoring_source(id)
            && patches
                .get(declaration.source_id().canonical_url())
                .is_some_and(|patches| patches.iter().any(|patch| patch.dep.matches_id(id))))
}

/// What the enabled features of a workspace member activate, following Cargo's feature rules.
struct Activation {
    /// The optional dependencies the features activate, by their name in the manifest.
    dependencies: HashSet<InternedString>,
    /// Features the features enable on dependencies (`dependency/feature`), by the
    /// dependency's name in the manifest.
    dependency_features: HashMap<InternedString, Vec<InternedString>>,
}

impl Activation {
    fn new(package: &cargo::core::Package, requested: &HashSet<InternedString>) -> Self {
        let feature_map = package.summary().features();
        let mut activation = Self {
            dependencies: HashSet::new(),
            dependency_features: HashMap::new(),
        };
        let mut enabled = HashSet::new();
        let mut pending: Vec<_> = requested.iter().copied().map(FeatureValue::new).collect();
        while let Some(value) = pending.pop() {
            match value {
                FeatureValue::Feature(feature) => {
                    if enabled.insert(feature)
                        && let Some(values) = feature_map.get(&feature)
                    {
                        pending.extend(values.iter().cloned());
                    }
                }
                FeatureValue::Dep { dep_name } => {
                    activation.dependencies.insert(dep_name);
                }
                FeatureValue::DepFeature {
                    dep_name,
                    dep_feature,
                    weak,
                } => {
                    // A weak feature (`dependency?/feature`) applies only if something else
                    // activates the dependency, and only active declarations are followed.
                    if !weak {
                        activation.dependencies.insert(dep_name);
                        // Like Cargo, also enable the feature named after an optional
                        // dependency, if the manifest doesn't hide it with `dep:`.
                        let is_optional = package
                            .dependencies()
                            .iter()
                            .any(|d| d.is_optional() && d.name_in_toml() == dep_name);
                        if is_optional {
                            pending.push(FeatureValue::Feature(dep_name));
                        }
                    }
                    activation
                        .dependency_features
                        .entry(dep_name)
                        .or_default()
                        .push(dep_feature);
                }
            }
        }
        activation
    }

    /// Whether a build of the package can use the dependency declaration.
    fn is_active(&self, declaration: &Dependency) -> bool {
        declaration.kind() != DepKind::Development
            && (!declaration.is_optional()
                || self.dependencies.contains(&declaration.name_in_toml()))
    }
}

/// Whether the local build uses different locked dependencies than the released one.
///
/// For every package that both builds use at the same version, its dependencies must have the
/// same versions, for each name and source. Walk both lockfiles from the package, comparing
/// the dependencies of each pair of packages and following those with the same version.
///
/// The lockfile of a published package has the workspace members it depends on as registry
/// packages, so the member's declarations classify their edges as the local build uses them.
fn are_dependencies_updated(local: &LockedPackage, released: &LockedPackage) -> bool {
    if local.root.version() != released.root.version() {
        debug!(
            "Version of package {} changed from {} to {}",
            local.root.name(),
            released.root.version(),
            local.root.version()
        );
        return true;
    }
    let mut visited = HashSet::new();
    let mut pending = vec![(local.root, released.root)];
    while let Some((local_id, released_id)) = pending.pop() {
        if !visited.insert((local_id, released_id)) {
            continue;
        }
        let local_dependencies = local.dependencies(local_id);
        let released_dependencies = match local.members.get(&local_id) {
            Some(member) if released_id.source_id().is_registry() => {
                member.published_edges(&released.dependencies(released_id))
            }
            _ => released.dependencies(released_id),
        };
        let local_groups = dependency_groups(&local_dependencies, &[]);
        let released_groups = dependency_groups(&released_dependencies, &local_dependencies);
        let same_versions = local_groups.len() == released_groups.len()
            && local_groups.iter().all(|(group, versions)| {
                released_groups.get(group).is_some_and(|released| {
                    released.len() == versions.len()
                        && versions.iter().all(|(version, packages)| {
                            released
                                .get(version)
                                .is_some_and(|released| released.len() == packages.len())
                        })
                })
            });
        if !same_versions {
            debug!("Dependencies of package {local_id} changed");
            return true;
        }
        for (group, versions) in local_groups {
            for (version, packages) in versions {
                let released = &released_groups[&group][&version];
                pending.extend(packages.into_iter().zip(released.iter().copied()));
            }
        }
    }
    false
}

/// The dependencies by name and source, then version.
///
/// `cargo package` turns path dependencies, and Git dependencies with a version requirement,
/// into registry dependencies. So a released registry dependency without a registry
/// counterpart among the `local` dependencies takes the source of a local path or Git
/// dependency with its name and version.
fn dependency_groups(
    dependencies: &[PackageId],
    local: &[PackageId],
) -> BTreeMap<DependencyGroup, DependencyVersions> {
    let mut groups: BTreeMap<_, DependencyVersions> = BTreeMap::new();
    for &dependency in dependencies {
        let published = || {
            local.iter().copied().find(|local| {
                local.name() == dependency.name()
                    && local.version() == dependency.version()
                    && (local.source_id().is_path() || local.source_id().is_git())
            })
        };
        let source = if dependency.source_id().is_registry() && !local.contains(&dependency) {
            published().map_or(DependencySource::of(dependency), DependencySource::of)
        } else {
            DependencySource::of(dependency)
        };
        groups
            .entry((dependency.name(), source))
            .or_default()
            .entry(dependency.version().clone())
            .or_default()
            .push(dependency);
    }
    groups
}

/// A workspace package in a lockfile, with the dependency edges that its build uses.
struct LockedPackage {
    root: PackageId,
    /// The dependencies, after `[replace]`, of each package the build reaches.
    edges: HashMap<PackageId, HashSet<PackageId>>,
    /// The declarations of each workspace member the build reaches.
    members: HashMap<PackageId, MemberDeclarations>,
}

impl LockedPackage {
    /// The locked dependencies of `id` that the build uses, in a stable order.
    fn dependencies(&self, id: PackageId) -> Vec<PackageId> {
        let mut dependencies: Vec<_> = self.edges.get(&id).into_iter().flatten().copied().collect();
        dependencies.sort();
        dependencies
    }
}

/// The declarations of a workspace member, and those that its build uses.
struct MemberDeclarations {
    declarations: Vec<Dependency>,
    /// The indices of the declarations that the build uses.
    active: HashSet<usize>,
}

impl MemberDeclarations {
    /// The `edges` of the member's published package that the local build uses.
    ///
    /// `cargo package` turns path dependencies, and Git dependencies with a version
    /// requirement, into registry dependencies, so those declarations match registry edges.
    fn published_edges(&self, edges: &[PackageId]) -> Vec<PackageId> {
        let resolved = resolved_declarations(&self.declarations, edges, |declaration, edge| {
            let source = declaration.source_id();
            declaration.matches_id(edge)
                || ((source.is_path() || source.is_git())
                    && edge.source_id().is_registry()
                    && declaration.matches_ignoring_source(edge))
        });
        edges
            .iter()
            .copied()
            .filter(|edge| {
                let resolved = &resolved[edge];
                resolved.is_empty() || resolved.iter().any(|index| self.active.contains(index))
            })
            .collect()
    }
}

/// A dependency name and source.
type DependencyGroup = (InternedString, DependencySource);

/// The packages of a dependency group, by version.
type DependencyVersions = BTreeMap<Version, Vec<PackageId>>;

/// The source of a dependency, as the local and released lockfiles can share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum DependencySource {
    /// A path package, whose location differs between the workspaces.
    Path,
    Other(SourceId),
}

impl DependencySource {
    fn of(id: PackageId) -> Self {
        let source = id.source_id();
        if source.is_path() {
            Self::Path
        } else {
            Self::Other(source)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{generate_lockfile, package_manifest, run_cargo_unwrap, write_package};
    use cargo_metadata::{DependencyKind, camino::Utf8PathBuf};

    /// Spell a source the way Cargo writes it into a lockfile: `encodable_source_id`
    /// percent-encodes the Git query parameters, while `cargo metadata` leaves them decoded.
    fn encoded_source(source: &str) -> String {
        match source.split_once('?') {
            Some((base, query)) => {
                format!("{base}?{}", query.replace('+', "%2B").replace('/', "%2F"))
            }
            None => source.to_owned(),
        }
    }

    /// The lockfile entries reachable from `package`, which must be in the lockfile.
    fn lock_dependencies(metadata: &Metadata, package: &str) -> LockedPackage {
        let context =
            crate::cargo::new_cargo_config(Some(metadata.workspace_root.clone())).unwrap();
        let workspace = load_workspace(metadata, &context).unwrap();
        workspace_lock_dependencies(
            &workspace,
            metadata,
            cargo_utils::workspace_package(metadata, package).unwrap(),
            None,
        )
        .unwrap()
        .unwrap()
    }

    /// Give hand-written lockfile fixtures real path packages for Cargo's decoder.
    fn workspace_for_lock(lockfile: &str) -> (crate::fs_utils::Utf8TempDir, Metadata) {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        let value: toml::Value = toml::from_str(lockfile).unwrap();
        let mut members = Vec::new();
        for package in value["package"].as_array().unwrap() {
            if package.get("source").is_some() {
                continue;
            }
            let name = package["name"].as_str().unwrap();
            let version = package["version"].as_str().unwrap();
            let member = format!("{name}-{version}");
            write_package(&directory.path().join(&member), name, version, "");
            members.push(member);
        }
        let manifest = directory.path().join("Cargo.toml");
        fs_err::write(
            &manifest,
            format!("[workspace]\nmembers = {members:?}\nresolver = \"2\"\n"),
        )
        .unwrap();
        fs_err::write(directory.path().join("Cargo.lock"), lockfile).unwrap();
        let metadata = cargo_utils::get_manifest_metadata(&manifest).unwrap();
        (directory, metadata)
    }

    /// Snapshot the lockfile of a workspace the way the reconstruction does.
    fn released_workspace(metadata: Metadata) -> ReleasedWorkspace {
        ReleasedWorkspace::new(metadata, "release-commit".into()).unwrap()
    }

    fn compare_workspace_locks(local: &Utf8Path, released: &Utf8Path, package: &str) -> bool {
        let (_local, local_metadata) = workspace_for_lock(&fs_err::read_to_string(local).unwrap());
        let (_released, released_metadata) =
            workspace_for_lock(&fs_err::read_to_string(released).unwrap());
        let released = released_workspace(released_metadata);
        are_workspace_lock_dependencies_updated(&local_metadata, &released, package).unwrap()
    }

    /// A lockfile in which `app 0.1.0` depends on `dep 1.0.0`.
    const APP_DEP_LOCKFILE: &str = "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"dep\"]\n\
             [[package]]\nname = \"dep\"\nversion = \"1.0.0\"\n";

    #[test]
    fn registry_workspace_lock_comparison_ignores_other_members_dependencies() {
        let lockfile = r#"
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dep 1.0.0"]
[[package]]
name = "other"
version = "0.1.0"
dependencies = ["dep 2.0.0"]
[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "dep"
version = "2.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
        let local = crate::fs_utils::Utf8TempDir::new().unwrap();
        let registry = crate::fs_utils::Utf8TempDir::new().unwrap();
        // The binary is at the workspace root supplied via --registry-manifest-path.
        // The other member uses a different version of the same dependency.
        for directory in [local.path(), registry.path()] {
            write_package(
                directory,
                "app",
                "0.1.0",
                "[workspace]\nmembers = [\"other\"]\nresolver = \"2\"\n\
                 [dependencies]\ndep = \"1\"\n",
            );
            fs_err::rename(directory.join("src/lib.rs"), directory.join("src/main.rs")).unwrap();
            fs_err::write(directory.join("src/main.rs"), "fn main() {}\n").unwrap();
            write_package(
                &directory.join("other"),
                "other",
                "0.1.0",
                "[dependencies]\ndep = \"2\"\n",
            );
            fs_err::write(directory.join("Cargo.lock"), lockfile).unwrap();
        }
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();

        let dependencies_updated =
            |name, path| are_lock_dependencies_updated(&local_metadata, path, name).unwrap();
        assert!(!dependencies_updated("app", registry.path()));
        let other = registry.path().join("other");
        assert!(!dependencies_updated("other", &other));

        // A change confined to the other member still must not release app.
        let updated = lockfile.replace("2.0.0", "2.0.1");
        fs_err::write(local.path().join("Cargo.lock"), &updated).unwrap();
        assert!(!dependencies_updated("app", registry.path()));
        // A nested member must compare against the shared workspace lockfile too.
        assert!(dependencies_updated("other", &other));
        assert_eq!(
            fs_err::read_to_string(registry.path().join("Cargo.lock")).unwrap(),
            lockfile
        );
        assert_eq!(
            fs_err::read_to_string(local.path().join("Cargo.lock")).unwrap(),
            updated
        );
    }

    #[test]
    fn registry_lock_comparison_detects_update_when_another_member_keeps_old_version() {
        let registry_lock = r#"
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dep 1.0.0"]
[[package]]
name = "dep"
version = "1.0.0"
source = "registry+https://example.com/index"
"#;
        let workspace_lock = format!(
            r#"{registry_lock}
[[package]]
name = "other"
version = "0.1.0"
dependencies = ["dep 1.0.0"]
"#
        );
        let (local, metadata) = workspace_for_lock(&workspace_lock);
        let registry = crate::fs_utils::Utf8TempDir::new().unwrap();
        write_package(registry.path(), "app", "0.1.0", "");
        fs_err::write(registry.path().join("Cargo.lock"), registry_lock).unwrap();
        let local_lock = local.path().join("Cargo.lock");
        let dependencies_updated =
            || are_lock_dependencies_updated(&metadata, registry.path(), "app").unwrap();
        assert!(!dependencies_updated());

        let updated = format!(
            r#"{workspace_lock}
[[package]]
name = "dep"
version = "1.1.0"
source = "registry+https://example.com/index"
"#
        );
        // Only app updates to dep 1.1.0; other still uses dep 1.0.0.
        let updated = updated.replacen(
            "dependencies = [\"dep 1.0.0\"]",
            "dependencies = [\"dep 1.1.0\"]",
            1,
        );
        fs_err::write(&local_lock, &updated).unwrap();
        assert!(dependencies_updated());
        assert_eq!(fs_err::read_to_string(&local_lock).unwrap(), updated);
    }

    #[test]
    fn registry_lock_comparison_skips_missing_lockfiles() {
        let (local, metadata) = workspace_for_lock(APP_DEP_LOCKFILE);
        let registry = crate::fs_utils::Utf8TempDir::new().unwrap();
        write_package(registry.path(), "app", "0.1.0", "");
        // There is no published lockfile to compare against.
        assert!(!are_lock_dependencies_updated(&metadata, registry.path(), "app").unwrap());
        fs_err::rename(
            local.path().join("Cargo.lock"),
            registry.path().join("Cargo.lock"),
        )
        .unwrap();
        // There is now a published lockfile, but no local lockfile.
        assert!(!are_lock_dependencies_updated(&metadata, registry.path(), "app").unwrap());
    }

    /// A workspace whose manifest version (`app 0.2.0`) is ahead of the committed
    /// lockfile, which still records `app 0.1.0`.
    fn stale_workspace() -> (crate::fs_utils::Utf8TempDir, Metadata) {
        let (directory, _) = workspace_for_lock(APP_DEP_LOCKFILE);
        let manifest = directory.path().join("app-0.1.0/Cargo.toml");
        let contents = fs_err::read_to_string(&manifest).unwrap();
        fs_err::write(&manifest, contents.replace("0.1.0", "0.2.0")).unwrap();
        let metadata = cargo_utils::get_manifest_metadata(&manifest).unwrap();
        (directory, metadata)
    }

    #[test]
    fn lock_comparison_fails_on_stale_local_lockfile() {
        let (directory, local_metadata) = stale_workspace();
        let (released_dir, released_metadata) = workspace_for_lock(APP_DEP_LOCKFILE);
        let released = released_workspace(released_metadata);
        // The user can fix the local lockfile, so this is an error with a hint.
        for result in [
            are_lock_dependencies_updated(&local_metadata, released_dir.path(), "app"),
            are_workspace_lock_dependencies_updated(&local_metadata, &released, "app"),
        ] {
            let error = result.unwrap_err().to_string();
            assert!(
                error.contains("cannot find package \"app\" 0.2.0"),
                "{error}"
            );
            assert!(error.contains("cargo check"), "{error}");
        }
        assert_eq!(
            fs_err::read_to_string(directory.path().join("Cargo.lock")).unwrap(),
            APP_DEP_LOCKFILE
        );
    }

    #[test]
    fn workspace_lock_comparison_treats_stale_released_lockfile_as_updated() {
        let (_local, local_metadata) = workspace_for_lock(APP_DEP_LOCKFILE);
        let (released_dir, released_metadata) = stale_workspace();
        let released = released_workspace(released_metadata);
        // History can't be rewritten: assume the dependencies changed instead of failing.
        assert!(
            are_lock_dependencies_updated(&local_metadata, released_dir.path(), "app").unwrap()
        );
        assert!(
            are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
        );
    }

    #[test]
    fn workspace_lock_comparison_uses_lockfile_committed_at_release() {
        let committed = APP_DEP_LOCKFILE;
        let re_resolved = committed.replace("1.0.0", "1.0.1");
        let (_local, local_metadata) = workspace_for_lock(&re_resolved);
        let (released_dir, released_metadata) = workspace_for_lock(committed);
        let released = released_workspace(released_metadata);
        // Simulate `cargo package --list` re-resolving the released lockfile on disk
        // after the snapshot was taken.
        let released_lock = released_dir.path().join("Cargo.lock");
        fs_err::write(&released_lock, &re_resolved).unwrap();
        // Comparing against the re-resolved lockfile would report no change.
        assert!(
            are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
        );
        assert_eq!(fs_err::read_to_string(&released_lock).unwrap(), re_resolved);

        // The cached graph is sufficient even if the on-disk lockfile is gone.
        fs_err::remove_file(&released_lock).unwrap();
        assert!(
            are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
        );
        assert!(!released_lock.exists());

        // Without a lockfile at the release there is nothing to compare, even if a
        // cargo command later writes one to disk.
        let released = released_workspace(released.metadata);
        fs_err::write(&released_lock, committed).unwrap();
        assert!(
            !are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
        );
    }

    #[test]
    fn released_workspace_fails_on_invalid_lockfile() {
        let (released_dir, released_metadata) = workspace_for_lock(APP_DEP_LOCKFILE);
        fs_err::write(
            released_dir.path().join("Cargo.lock"),
            "this is not a lockfile",
        )
        .unwrap();
        let err = ReleasedWorkspace::new(released_metadata, "release-commit".into()).unwrap_err();
        assert!(
            format!("{err:#}").contains("committed at release-commit"),
            "{err:#}"
        );
    }

    #[test]
    fn workspace_lock_comparison_distinguishes_same_named_path_packages() {
        let local = crate::fs_utils::Utf8TempDir::new().unwrap();
        let released = crate::fs_utils::Utf8TempDir::new().unwrap();
        for (directory, dependency_version) in [(local.path(), "1.0.1"), (released.path(), "1.0.0")]
        {
            fs_err::write(
                directory.join("Cargo.toml"),
                "[workspace]\nmembers = [\"app\", \"other\"]\nexclude = [\"older-app\"]\nresolver = \"2\"\n",
            )
            .unwrap();
            for (path, name, version, dependencies) in [
                ("app", "app", "0.1.0", ""),
                (
                    "other",
                    "other",
                    "0.1.0",
                    "app = { path = \"../older-app\", version = \"1\" }",
                ),
                ("older-app", "app", dependency_version, ""),
            ] {
                write_package(
                    &directory.join(path),
                    name,
                    version,
                    &format!("[dependencies]\n{dependencies}\n"),
                );
            }
            generate_lockfile(directory);
        }
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
        let released = released_workspace(
            cargo_utils::get_manifest_metadata(&released.path().join("Cargo.toml")).unwrap(),
        );
        assert!(
            !are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
        );
        assert!(
            are_workspace_lock_dependencies_updated(&local_metadata, &released, "other").unwrap()
        );

        // Each side must use its own member version when identifying the root.
        let manifest = local.path().join("app/Cargo.toml");
        let contents = fs_err::read_to_string(&manifest).unwrap();
        fs_err::write(&manifest, contents.replace("0.1.0", "0.1.1")).unwrap();
        generate_lockfile(local.path());
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
        assert!(
            are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
        );
    }

    #[test]
    fn workspace_lock_comparison_distinguishes_path_and_git_packages() {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        let git_path = directory.path().join("dependency");
        let workspace = directory.path().join("workspace");
        fs_err::create_dir(&git_path).unwrap();
        let git_repo = git_cmd::Repo::init(&git_path);
        let git_url = url::Url::from_directory_path(&git_path).unwrap();
        for (root, members) in [
            (&git_path, &["shared", "leaf"][..]),
            (&workspace, &["app", "other", "shared"][..]),
        ] {
            fs_err::create_dir_all(root).unwrap();
            fs_err::write(
                root.join("Cargo.toml"),
                format!("[workspace]\nmembers = {members:?}\nresolver = \"2\"\n"),
            )
            .unwrap();
            for name in members {
                let dependencies = match *name {
                    "shared" if root == &git_path => "leaf = { path = \"../leaf\" }".into(),
                    "app" => "shared = { path = \"../shared\" }".into(),
                    "other" => format!("shared = {{ git = {:?} }}", git_url.as_str()),
                    _ => String::new(),
                };
                write_package(
                    &root.join(name),
                    name,
                    "1.0.0",
                    &format!("[dependencies]\n{dependencies}\n"),
                );
            }
        }
        git_repo.add_all_and_commit("initial dependency").unwrap();
        // Let Cargo encode the ambiguous path/Git dependency IDs itself.
        run_cargo_unwrap(&workspace, &["generate-lockfile"]);
        let released_lock = directory.path().join("released.lock");
        let local_lock = workspace.join("Cargo.lock");
        fs_err::copy(&local_lock, &released_lock).unwrap();
        assert!(!compare_workspace_locks(&local_lock, &released_lock, "app"));
        assert!(!compare_workspace_locks(
            &local_lock,
            &released_lock,
            "other"
        ));

        let leaf_manifest = git_path.join("leaf/Cargo.toml");
        let manifest = fs_err::read_to_string(&leaf_manifest).unwrap();
        fs_err::write(&leaf_manifest, manifest.replace("1.0.0", "1.0.1")).unwrap();
        git_repo.add_all_and_commit("update Git leaf").unwrap();
        run_cargo_unwrap(&workspace, &["update"]);

        // Only `other` reaches the Git package and its updated transitive dependency.
        assert!(!compare_workspace_locks(&local_lock, &released_lock, "app"));
        assert!(compare_workspace_locks(
            &local_lock,
            &released_lock,
            "other"
        ));
    }

    #[test]
    fn workspace_lock_comparison_ignores_transitive_dev_dependencies() {
        let local = crate::fs_utils::Utf8TempDir::new().unwrap();
        let released = crate::fs_utils::Utf8TempDir::new().unwrap();
        for directory in [local.path(), released.path()] {
            fs_err::write(
                directory.join("Cargo.toml"),
                "[workspace]\nmembers = [\"binary\", \"library\"]\nresolver = \"2\"\n\
                 [patch.crates-io]\npatched-test = { git = \"https://example.com/patched-test\" }\n",
            )
            .unwrap();
            for (name, dependencies) in [
                (
                    "binary",
                    r#"
[dependencies]
library = { path = "../library" }
[dev-dependencies]
root-dev = "1"
"#,
                ),
                (
                    "library",
                    r#"
[dependencies]
shared = "1"
both = "1"
[build-dependencies]
builder = "1"
[dev-dependencies]
test-only = "1"
patched-test = "1"
both = "1"
shared-test = { package = "shared", version = "2" }
"#,
                ),
            ] {
                write_package(&directory.join(name), name, "0.1.0", dependencies);
            }
        }
        // No dependency resolution or registry access is needed to read dependency kinds.
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
        let released_metadata =
            cargo_utils::get_manifest_metadata(&released.path().join("Cargo.toml")).unwrap();
        let mut lockfile = r#"
version = 4
[[package]]
name = "binary"
version = "0.1.0"
dependencies = ["library", "root-dev"]
[[package]]
name = "library"
version = "0.1.0"
dependencies = ["shared 1.0.0", "shared 2.0.0", "both", "builder", "test-only", "patched-test"]
[[package]]
name = "patched-test"
version = "1.0.0"
source = "git+https://example.com/patched-test#0123456789abcdef"
"#
        .to_string();
        for (name, version) in [
            ("shared", "1.0.0"),
            ("shared", "2.0.0"),
            ("both", "1.0.0"),
            ("builder", "1.0.0"),
            ("test-only", "1.0.0"),
            ("root-dev", "1.0.0"),
        ] {
            lockfile.push_str(&format!(
                "\n[[package]]\nname = {name:?}\nversion = {version:?}\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            ));
        }
        fs_err::write(released.path().join("Cargo.lock"), &lockfile).unwrap();
        let released = released_workspace(released_metadata);

        for (name, version, should_update) in [
            ("test-only", "1.0.0", false),
            // A registry dev dependency can resolve to a different source via [patch].
            ("patched-test", "1.0.0", false),
            ("shared", "2.0.0", false),
            ("shared", "1.0.0", true),
            ("both", "1.0.0", true),
            ("builder", "1.0.0", true),
            // Dev-dependencies of the binary itself don't reach its build either.
            ("root-dev", "1.0.0", false),
        ] {
            let mut updated_version = Version::parse(version).unwrap();
            updated_version.patch += 1;
            let changed = lockfile
                .replace(
                    &format!("name = {name:?}\nversion = {version:?}"),
                    &format!("name = {name:?}\nversion = \"{updated_version}\""),
                )
                .replace(
                    &format!("{name} {version}"),
                    &format!("{name} {updated_version}"),
                );
            fs_err::write(local.path().join("Cargo.lock"), changed).unwrap();
            assert_eq!(
                are_workspace_lock_dependencies_updated(&local_metadata, &released, "binary")
                    .unwrap(),
                should_update,
                "updating {name} {version}"
            );
        }
    }

    #[test]
    fn workspace_lock_comparison_ignores_optional_dependencies_no_feature_enables() {
        // The lockfile records optional dependencies whether or not a feature enables them.
        let mut lockfile = r#"
version = 4
[[package]]
name = "binary"
version = "0.1.0"
dependencies = ["library", "root-optional", "shared"]
[[package]]
name = "library"
version = "0.1.0"
dependencies = ["default-on", "implicit", "off", "on", "shared", "strong", "weak"]
[[package]]
name = "shared"
version = "0.1.0"
dependencies = ["deep", "unused-deep"]
"#
        .to_string();
        let registry_packages = [
            ("off", false),
            ("on", true),
            ("default-on", false),
            ("implicit", true),
            // A weak dependency feature doesn't activate the dependency.
            ("weak", false),
            ("strong", true),
            // `nested` enables a feature of another member through `library`. `binary`
            // reaches that member first, without any feature, so it's visited again.
            ("deep", true),
            // The member's default feature is turned off by every declaration.
            ("unused-deep", false),
            // The binary can be built with any of its own features.
            ("root-optional", true),
        ];
        for (name, _) in registry_packages {
            lockfile.push_str(&format!(
                "\n[[package]]\nname = {name:?}\nversion = \"1.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
            ));
        }
        for default_features in [false, true] {
            let binary = format!(
                r#"
[dependencies]
shared = {{ path = "../shared", default-features = false }}
root-optional = {{ version = "1", optional = true }}
[dependencies.library]
path = "../library"
default-features = {default_features}
features = ["on-feature", "implicit", "weak-feature", "strong-feature", "nested"]
"#
            );
            let local = crate::fs_utils::Utf8TempDir::new().unwrap();
            let released = crate::fs_utils::Utf8TempDir::new().unwrap();
            for directory in [local.path(), released.path()] {
                let members = ["binary", "library", "shared"];
                fs_err::write(
                    directory.join("Cargo.toml"),
                    format!("[workspace]\nmembers = {members:?}\nresolver = \"2\"\n"),
                )
                .unwrap();
                for (name, manifest) in [
                    ("binary", binary.as_str()),
                    (
                        "library",
                        r#"
[dependencies]
shared = { path = "../shared", default-features = false }
off = { version = "1", optional = true }
on = { version = "1", optional = true }
default-on = { version = "1", optional = true }
implicit = { version = "1", optional = true }
weak = { version = "1", optional = true }
strong = { version = "1", optional = true }
[features]
default = ["dep:default-on"]
on-feature = ["dep:on"]
off-feature = ["dep:off"]
weak-feature = ["weak?/std"]
strong-feature = ["strong/std"]
nested = ["shared/extra"]
"#,
                    ),
                    (
                        "shared",
                        r#"
[dependencies]
deep = { version = "1", optional = true }
unused-deep = { version = "1", optional = true }
[features]
default = ["dep:unused-deep"]
extra = ["dep:deep"]
"#,
                    ),
                ] {
                    write_package(&directory.join(name), name, "0.1.0", manifest);
                }
            }
            // No dependency resolution or registry access is needed to read features.
            let local_metadata =
                cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
            let released_metadata =
                cargo_utils::get_manifest_metadata(&released.path().join("Cargo.toml")).unwrap();
            fs_err::write(released.path().join("Cargo.lock"), &lockfile).unwrap();
            let released = released_workspace(released_metadata);
            for (name, should_update) in registry_packages {
                // The default features of `library` activate its default dependency.
                let should_update = should_update || (default_features && name == "default-on");
                let changed = lockfile.replace(
                    &format!("name = {name:?}\nversion = \"1.0.0\""),
                    &format!("name = {name:?}\nversion = \"1.0.1\""),
                );
                fs_err::write(local.path().join("Cargo.lock"), changed).unwrap();
                assert_eq!(
                    are_workspace_lock_dependencies_updated(&local_metadata, &released, "binary")
                        .unwrap(),
                    should_update,
                    "updating {name} with default features: {default_features}"
                );
            }
        }
    }

    #[test]
    fn registry_lock_comparison_ignores_optional_dependencies_of_published_members() {
        // Only the dev-dependency on `library` enables its optional dependency on `dep 1`.
        let local = crate::fs_utils::Utf8TempDir::new().unwrap();
        fs_err::write(
            local.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"app\", \"library\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        for (name, manifest) in [
            (
                "app",
                r#"
[dependencies]
library = { path = "../library", version = "0.1" }
[dev-dependencies]
library = { path = "../library", version = "0.1", features = ["old"] }
"#,
            ),
            (
                "library",
                r#"
[dependencies]
dep = "2"
old-dep = { package = "dep", version = "1", optional = true }
[features]
old = ["dep:old-dep"]
"#,
            ),
        ] {
            write_package(&local.path().join(name), name, "0.1.0", manifest);
        }
        // The published package depends on `library` from the registry, whose manifest isn't
        // available, so its optional dependency is reached there.
        let registry = crate::fs_utils::Utf8TempDir::new().unwrap();
        write_package(
            registry.path(),
            "app",
            "0.1.0",
            "[dependencies]\nlibrary = \"0.1\"\n\
             [dev-dependencies]\nlibrary = { version = \"0.1\", features = [\"old\"] }\n",
        );
        let crates_io = "registry+https://github.com/rust-lang/crates.io-index";
        let lockfile = |library_source: &str| {
            format!(
                r#"
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["library"]
[[package]]
name = "library"
version = "0.1.0"
{library_source}dependencies = ["dep 1.0.0", "dep 2.0.0"]
[[package]]
name = "dep"
version = "1.0.0"
source = "{crates_io}"
[[package]]
name = "dep"
version = "2.0.0"
source = "{crates_io}"
"#
            )
        };
        let local_lockfile = lockfile("");
        fs_err::write(
            registry.path().join("Cargo.lock"),
            lockfile(&format!("source = \"{crates_io}\"\n")),
        )
        .unwrap();
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
        for (version, updated_version, should_update) in [
            ("2.0.0", "2.0.0", false),
            ("2.0.0", "2.0.1", true),
            ("1.0.0", "1.0.1", false),
        ] {
            let changed = local_lockfile
                .replace(
                    &format!("name = \"dep\"\nversion = \"{version}\""),
                    &format!("name = \"dep\"\nversion = \"{updated_version}\""),
                )
                .replace(&format!("dep {version}"), &format!("dep {updated_version}"));
            fs_err::write(local.path().join("Cargo.lock"), changed).unwrap();
            assert_eq!(
                are_lock_dependencies_updated(&local_metadata, registry.path(), "app").unwrap(),
                should_update,
                "updating dep {version} to {updated_version}"
            );
        }
    }

    /// A Git repository whose root package is `name` at `version`.
    fn git_package(directory: &Utf8Path, name: &str, version: &str) -> (git_cmd::Repo, String) {
        fs_err::create_dir_all(directory).unwrap();
        let repo = git_cmd::Repo::init(directory);
        write_package(directory, name, version, "");
        repo.add_all_and_commit("initial package").unwrap();
        let url = url::Url::from_directory_path(directory)
            .unwrap()
            .to_string();
        (repo, url)
    }

    /// Commit `version` as the new version of the root package of `repo`.
    fn bump_git_package(repo: &git_cmd::Repo, name: &str, version: &str) {
        write_package(repo.directory(), name, version, "");
        repo.add_all_and_commit("bump version").unwrap();
    }

    /// A workspace with a single `app` member, its lockfile generated by Cargo.
    fn git_app_workspace(directory: &Utf8Path, dependencies: &str) -> Utf8PathBuf {
        let workspace = directory.join("workspace");
        write_package(&workspace, "app", "0.1.0", dependencies);
        run_cargo_unwrap(&workspace, &["generate-lockfile"]);
        workspace
    }

    #[test]
    fn workspace_lock_comparison_keeps_git_sources_apart() {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        let (first, first_url) = git_package(&directory.path().join("first"), "shared", "1.0.0");
        let (second, second_url) = git_package(&directory.path().join("second"), "shared", "1.1.0");
        let workspace = git_app_workspace(
            directory.path(),
            &format!(
                "[dependencies]\nfirst = {{ package = \"shared\", git = {first_url:?} }}\n\
                 second = {{ package = \"shared\", git = {second_url:?} }}\n"
            ),
        );
        let released_lock = directory.path().join("released.lock");
        let local_lock = workspace.join("Cargo.lock");
        fs_err::copy(&local_lock, &released_lock).unwrap();
        assert!(!compare_workspace_locks(&local_lock, &released_lock, "app"));

        // The other repository's unchanged `shared 1.1.0` must not hide the update.
        bump_git_package(&first, "shared", "1.1.0");
        run_cargo_unwrap(&workspace, &["update"]);
        assert!(compare_workspace_locks(&local_lock, &released_lock, "app"));

        // Pairing by version alone would match each package with the other repository's.
        bump_git_package(&second, "shared", "1.0.0");
        run_cargo_unwrap(&workspace, &["update"]);
        assert!(compare_workspace_locks(&local_lock, &released_lock, "app"));
    }

    #[test]
    fn workspace_lock_comparison_detects_updates_across_semver_boundaries() {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        let (dependency, url) = git_package(&directory.path().join("dep"), "dep", "1.0.0");
        let workspace = git_app_workspace(
            directory.path(),
            &format!("[dependencies]\ndep = {{ git = {url:?}, version = \">=1, <3\" }}\n"),
        );
        let released_lock = directory.path().join("released.lock");
        let local_lock = workspace.join("Cargo.lock");
        fs_err::copy(&local_lock, &released_lock).unwrap();

        // The requirement allows the update without a manifest change.
        bump_git_package(&dependency, "dep", "2.0.0");
        run_cargo_unwrap(&workspace, &["update"]);
        assert!(
            fs_err::read_to_string(&local_lock)
                .unwrap()
                .contains("name = \"dep\"\nversion = \"2.0.0\"")
        );
        assert!(compare_workspace_locks(&local_lock, &released_lock, "app"));
    }

    #[test]
    fn workspace_lock_comparison_pairs_updated_dependencies_by_edge() {
        let local = crate::fs_utils::Utf8TempDir::new().unwrap();
        let released = crate::fs_utils::Utf8TempDir::new().unwrap();
        for directory in [local.path(), released.path()] {
            fs_err::write(
                directory.join("Cargo.toml"),
                "[workspace]\nmembers = [\"app\", \"library\"]\nresolver = \"2\"\n",
            )
            .unwrap();
            write_package(
                &directory.join("app"),
                "app",
                "0.1.0",
                "[dependencies]\ndep = \">=1, <3\"\nlibrary = { path = \"../library\" }\n",
            );
            write_package(
                &directory.join("library"),
                "library",
                "0.1.0",
                "[dependencies]\nold-dep = { package = \"dep\", version = \"1\", optional = true }\n",
            );
        }
        let crates_io = "registry+https://github.com/rust-lang/crates.io-index";
        let lockfile = |app_dep: &str, packages: &[&str]| {
            let mut lockfile = format!(
                r#"
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["dep {app_dep}", "library"]
[[package]]
name = "library"
version = "0.1.0"
dependencies = ["dep 1.0.0"]
"#
            );
            for version in packages {
                lockfile.push_str(&format!(
                    "[[package]]\nname = \"dep\"\nversion = \"{version}\"\nsource = \"{crates_io}\"\n"
                ));
            }
            lockfile
        };
        fs_err::write(
            released.path().join("Cargo.lock"),
            lockfile("1.0.0", &["1.0.0"]),
        )
        .unwrap();
        // `app` moved to `dep 2.0.0`, while the optional dependency of `library`, which no
        // feature enables, still locks `dep 1.0.0`.
        fs_err::write(
            local.path().join("Cargo.lock"),
            lockfile("2.0.0", &["1.0.0", "2.0.0"]),
        )
        .unwrap();
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
        let released = released_workspace(
            cargo_utils::get_manifest_metadata(&released.path().join("Cargo.toml")).unwrap(),
        );
        assert!(
            are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
        );
    }

    const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

    /// Lockfile entries of `bitflags` from crates.io at `versions`.
    fn bitflags_entries(versions: &[&str]) -> String {
        versions
            .iter()
            .map(|version| {
                format!(
                    "[[package]]\nname = \"bitflags\"\nversion = \"{version}\"\nsource = \"{CRATES_IO}\"\n"
                )
            })
            .collect()
    }

    /// Compare `app` through the git-only path, between workspaces with `members` and the
    /// lockfiles, and through the registry path, against a published `app` with
    /// `published_manifest` and `published_lock`.
    fn compare_app_locks(
        members: &[(&str, &str, &str)],
        local_lock: &str,
        released_lock: &str,
        published_manifest: &str,
        published_lock: &str,
    ) -> (bool, bool) {
        let local = app_workspace(members, local_lock);
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
        let published = crate::fs_utils::Utf8TempDir::new().unwrap();
        write_package(published.path(), "app", "0.1.0", published_manifest);
        fs_err::write(published.path().join("Cargo.lock"), published_lock).unwrap();
        (
            compare_app_workspace_locks(members, local_lock, released_lock),
            are_lock_dependencies_updated(&local_metadata, published.path(), "app").unwrap(),
        )
    }

    /// Compare `app` through the git-only path, between workspaces with `members` and the
    /// lockfiles.
    fn compare_app_workspace_locks(
        members: &[(&str, &str, &str)],
        local_lock: &str,
        released_lock: &str,
    ) -> bool {
        let local = app_workspace(members, local_lock);
        let released = app_workspace(members, released_lock);
        let local_metadata =
            cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
        let released = released_workspace(
            cargo_utils::get_manifest_metadata(&released.path().join("Cargo.toml")).unwrap(),
        );
        are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap()
    }

    /// A workspace with `members`, each a name, version and dependency tables, and `lockfile`.
    fn app_workspace(
        members: &[(&str, &str, &str)],
        lockfile: &str,
    ) -> crate::fs_utils::Utf8TempDir {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        let names: Vec<_> = members.iter().map(|(name, _, _)| *name).collect();
        fs_err::write(
            directory.path().join("Cargo.toml"),
            format!("[workspace]\nmembers = {names:?}\nresolver = \"2\"\n"),
        )
        .unwrap();
        for (name, version, manifest) in members {
            write_package(&directory.path().join(name), name, version, manifest);
        }
        fs_err::write(directory.path().join("Cargo.lock"), lockfile).unwrap();
        directory
    }

    #[test]
    fn lock_comparison_ignores_dev_dependency_edges_to_built_packages() {
        // `app` builds `bitflags 2.13.2`, which the tests of `library` now use too.
        let app = "[dependencies]\nlibrary = { path = \"../library\", version = \"0.1\" }\n\
                   bitflags = \"2\"\n";
        let members = [
            ("app", "0.1.0", app),
            (
                "library",
                "0.1.0",
                "[dev-dependencies]\nbitflags = \">=1, <3\"\n",
            ),
        ];
        let workspace_lock = |app: &str, library: &str, versions: &[&str]| {
            format!(
                "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"{app}\", \"library\"]\n\
                 [[package]]\nname = \"library\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"{library}\"]\n{}",
                bitflags_entries(versions)
            )
        };
        let released_lock =
            workspace_lock("bitflags 2.13.2", "bitflags 1.3.2", &["1.3.2", "2.13.2"]);
        let local_lock = workspace_lock("bitflags", "bitflags", &["2.13.2"]);
        let published_lock = format!(
            "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\"bitflags\", \"library\"]\n\
             [[package]]\nname = \"library\"\nversion = \"0.1.0\"\nsource = \"{CRATES_IO}\"\n{}",
            bitflags_entries(&["2.13.2"])
        );
        let published_manifest = "[dependencies]\nlibrary = \"0.1\"\nbitflags = \"2\"\n";
        assert_eq!(
            compare_app_locks(
                &members,
                &local_lock,
                &released_lock,
                published_manifest,
                &published_lock
            ),
            (false, false)
        );
    }

    #[test]
    fn lock_comparison_resolves_ambiguous_dependency_edges() {
        // The normal requirement matches both locked versions, but the dev-dependency must
        // resolve to `2.13.2`, so the normal one resolved to `1.3.2`.
        let app = "[dependencies]\nbitflags = \">=1, <3\"\n\
                   [dev-dependencies]\nbitflags = \"=2.13.2\"\n";
        let app_lock = |dependencies: &str, versions: &[&str]| {
            format!(
                "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [{dependencies}]\n{}",
                bitflags_entries(versions)
            )
        };
        let released_lock = app_lock(
            "\"bitflags 1.3.2\", \"bitflags 2.13.2\"",
            &["1.3.2", "2.13.2"],
        );
        // Both declarations now resolve to `2.13.2`.
        let local_lock = app_lock("\"bitflags\"", &["2.13.2"]);
        assert_eq!(
            compare_app_locks(
                &[("app", "0.1.0", app)],
                &local_lock,
                &released_lock,
                app,
                &released_lock
            ),
            (true, true)
        );
    }

    /// A lockfile in which `app` depends on `bitflags` at `versions`.
    fn bitflags_app_lock(versions: &[&str]) -> String {
        let dependencies: Vec<_> = versions
            .iter()
            .map(|version| format!("bitflags {version}"))
            .collect();
        format!(
            "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = {dependencies:?}\n{}",
            bitflags_entries(versions)
        )
    }

    #[test]
    fn lock_comparison_detects_dependencies_converging_on_one_version() {
        let app = "[dependencies]\nbitflags = \">=1, <3\"\n\
                   [build-dependencies]\nbitflags = \"=2.13.2\"\n";
        let released_lock = bitflags_app_lock(&["1.3.2", "2.13.2"]);
        // `cargo update -p bitflags@1.3.2 --precise 2.13.2` merges both into one entry.
        let local_lock = bitflags_app_lock(&["2.13.2"]);
        assert_eq!(
            compare_app_locks(
                &[("app", "0.1.0", app)],
                &local_lock,
                &released_lock,
                app,
                &released_lock
            ),
            (true, true)
        );
    }

    #[test]
    fn lock_comparison_detects_dependencies_diverging_from_one_version() {
        let app = "[dependencies]\nbitflags = \">=1, <3\"\n\
                   [build-dependencies]\nbitflags = \"=2.13.2\"\n";
        let released_lock = bitflags_app_lock(&["2.13.2"]);
        // `cargo update -p bitflags@2.13.2 --precise 1.3.2` splits the entry.
        let local_lock = bitflags_app_lock(&["1.3.2", "2.13.2"]);
        assert_eq!(
            compare_app_locks(
                &[("app", "0.1.0", app)],
                &local_lock,
                &released_lock,
                app,
                &released_lock
            ),
            (true, true)
        );
    }

    #[test]
    fn lock_comparison_detects_versions_swapped_between_members() {
        let library = "[dependencies]\ndep = \">=1, <3\"\n";
        let members = [
            (
                "app",
                "0.1.0",
                "[dependencies]\nfirst = { path = \"../first\", version = \"0.1\" }\n\
                 second = { path = \"../second\", version = \"0.1\" }\n",
            ),
            ("first", "0.1.0", library),
            ("second", "0.1.0", library),
        ];
        let lockfile = |first: &str, second: &str, source: &str| {
            format!(
                "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"first\", \"second\"]\n\
                 [[package]]\nname = \"first\"\nversion = \"0.1.0\"\n{source}\
                 dependencies = [\"dep {first}\"]\n\
                 [[package]]\nname = \"second\"\nversion = \"0.1.0\"\n{source}\
                 dependencies = [\"dep {second}\"]\n\
                 [[package]]\nname = \"dep\"\nversion = \"1.0.0\"\nsource = \"{CRATES_IO}\"\n\
                 [[package]]\nname = \"dep\"\nversion = \"2.0.0\"\nsource = \"{CRATES_IO}\"\n"
            )
        };
        // Both versions stay locked, but each member now builds the other one.
        let released_lock = lockfile("1.0.0", "2.0.0", "");
        let local_lock = lockfile("2.0.0", "1.0.0", "");
        let published_lock = lockfile("1.0.0", "2.0.0", &format!("source = \"{CRATES_IO}\"\n"));
        let published_manifest = "[dependencies]\nfirst = \"0.1\"\nsecond = \"0.1\"\n";
        assert_eq!(
            compare_app_locks(
                &members,
                &local_lock,
                &released_lock,
                published_manifest,
                &published_lock
            ),
            (true, true)
        );
    }

    #[test]
    fn lock_comparison_classifies_only_the_published_version_of_a_member() {
        // The registry `num-traits 0.2.19` isn't the member `num-traits 0.3.0`, whose manifest
        // declares `autocfg` as optional.
        let members = [
            (
                "app",
                "0.1.0",
                "[dependencies]\nnum-traits = \"0.2\"\n\
                 next = { package = \"num-traits\", path = \"../num-traits\", version = \"0.3\" }\n",
            ),
            (
                "num-traits",
                "0.3.0",
                "[dependencies]\nautocfg = { version = \"1\", optional = true }\n",
            ),
        ];
        let lockfile = |member_source: &str| {
            format!(
                "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"num-traits 0.2.19\", \"num-traits 0.3.0\"]\n\
                 [[package]]\nname = \"autocfg\"\nversion = \"1.4.0\"\nsource = \"{CRATES_IO}\"\n\
                 [[package]]\nname = \"num-traits\"\nversion = \"0.2.19\"\nsource = \"{CRATES_IO}\"\n\
                 dependencies = [\"autocfg\"]\n\
                 [[package]]\nname = \"num-traits\"\nversion = \"0.3.0\"\n{member_source}\
                 dependencies = [\"autocfg\"]\n"
            )
        };
        let workspace_lock = lockfile("");
        let published_lock = lockfile(&format!("source = \"{CRATES_IO}\"\n"));
        let published_manifest = "[dependencies]\nnum-traits = \"0.2\"\n\
                                  next = { package = \"num-traits\", version = \"0.3\" }\n";
        assert_eq!(
            compare_app_locks(
                &members,
                &workspace_lock,
                &workspace_lock,
                published_manifest,
                &published_lock
            ),
            (false, false)
        );
    }

    #[test]
    fn workspace_lock_comparison_keeps_same_named_path_and_registry_packages_apart() {
        // A path fork of `bitflags` with the version of the registry package it forks.
        let members = [
            (
                "app",
                "0.1.0",
                "[dependencies]\nbitflags = \"1\"\n\
                 fork = { package = \"bitflags\", path = \"../bitflags\" }\n",
            ),
            ("bitflags", "1.3.2", "[dependencies]\nleaf = \"1\"\n"),
        ];
        let lockfile = |leaf: &str| {
            format!(
                "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"bitflags 1.3.2\", \"bitflags 1.3.2 ({CRATES_IO})\"]\n\
                 [[package]]\nname = \"bitflags\"\nversion = \"1.3.2\"\ndependencies = [\"leaf\"]\n\
                 [[package]]\nname = \"bitflags\"\nversion = \"1.3.2\"\nsource = \"{CRATES_IO}\"\n\
                 [[package]]\nname = \"leaf\"\nversion = \"{leaf}\"\nsource = \"{CRATES_IO}\"\n"
            )
        };
        // A source tree supplied with `--registry-manifest-path` has the fork itself, too.
        let compare_source_tree = |local_lock: &str, released_lock: &str| {
            let local = app_workspace(&members, local_lock);
            let released = app_workspace(&members, released_lock);
            let local_metadata =
                cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
            are_lock_dependencies_updated(&local_metadata, released.path(), "app").unwrap()
        };
        let unchanged = lockfile("1.0.0");
        assert!(!compare_app_workspace_locks(
            &members, &unchanged, &unchanged
        ));
        assert!(!compare_source_tree(&unchanged, &unchanged));
        // Only the fork depends on `leaf`.
        let updated = lockfile("1.0.1");
        assert!(compare_app_workspace_locks(&members, &updated, &unchanged));
        assert!(compare_source_tree(&updated, &unchanged));
    }

    #[test]
    fn registry_lock_comparison_matches_git_dependencies_published_from_a_registry() {
        // `cargo package` turns a Git dependency with a version requirement into a registry one.
        let members = [(
            "app",
            "0.1.0",
            "[dependencies]\n\
             bitflags = { git = \"https://example.com/bitflags\", version = \"=1.3.2\" }\n",
        )];
        let lockfile = |source: &str| {
            format!(
                "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"bitflags\"]\n\
                 [[package]]\nname = \"bitflags\"\nversion = \"1.3.2\"\nsource = \"{source}\"\n"
            )
        };
        let workspace_lock =
            lockfile("git+https://example.com/bitflags#0123456789abcdef0123456789abcdef01234567");
        assert_eq!(
            compare_app_locks(
                &members,
                &workspace_lock,
                &workspace_lock,
                "[dependencies]\nbitflags = \"=1.3.2\"\n",
                &lockfile(CRATES_IO)
            ),
            (false, false)
        );
    }

    #[test]
    fn registry_lock_comparison_matches_dependencies_merged_by_publishing() {
        // `rustix` uses the registry `bitflags 2.13.2`, which becomes `app`'s direct dependency
        // too once publishing turns it into a registry dependency.
        let registry_bitflags = format!("bitflags 2.13.2 ({CRATES_IO})");
        let published_lock = format!(
            "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
             dependencies = [\"bitflags\", \"rustix\"]\n\
             [[package]]\nname = \"bitflags\"\nversion = \"2.13.2\"\nsource = \"{CRATES_IO}\"\n\
             [[package]]\nname = \"rustix\"\nversion = \"1.1.5\"\nsource = \"{CRATES_IO}\"\n\
             dependencies = [\"bitflags\"]\n"
        );
        let git = "https://example.com/bitflags";
        let git_source = format!("git+{git}#0123456789abcdef0123456789abcdef01234567");
        let path_members = [
            (
                "app",
                "0.1.0",
                "[dependencies]\nbitflags = { path = \"../bitflags\", version = \"2.13.2\" }\n\
                 rustix = \"1\"\n"
                    .to_owned(),
            ),
            ("bitflags", "2.13.2", String::new()),
        ];
        let git_members = [(
            "app",
            "0.1.0",
            format!(
                "[dependencies]\nbitflags = {{ git = {git:?}, version = \"2.13.2\" }}\n\
                 rustix = \"1\"\n"
            ),
        )];
        for (members, local_bitflags, local_source) in [
            (
                &path_members[..],
                "bitflags 2.13.2".to_owned(),
                String::new(),
            ),
            (
                &git_members[..],
                format!("bitflags 2.13.2 (git+{git})"),
                format!("source = \"{git_source}\"\n"),
            ),
        ] {
            let members: Vec<_> = members
                .iter()
                .map(|(name, version, manifest)| (*name, *version, manifest.as_str()))
                .collect();
            let workspace_lock = format!(
                "version = 4\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\n\
                 dependencies = [\"{local_bitflags}\", \"rustix\"]\n\
                 [[package]]\nname = \"bitflags\"\nversion = \"2.13.2\"\n{local_source}\
                 [[package]]\nname = \"bitflags\"\nversion = \"2.13.2\"\nsource = \"{CRATES_IO}\"\n\
                 [[package]]\nname = \"rustix\"\nversion = \"1.1.5\"\nsource = \"{CRATES_IO}\"\n\
                 dependencies = [\"{registry_bitflags}\"]\n"
            );
            assert_eq!(
                compare_app_locks(
                    &members,
                    &workspace_lock,
                    &workspace_lock,
                    "[dependencies]\nbitflags = \"2.13.2\"\nrustix = \"1\"\n",
                    &published_lock
                ),
                (false, false),
                "{local_bitflags}"
            );
        }
    }

    #[test]
    fn workspace_lock_comparison_counts_dev_dependency_features_with_resolver_1() {
        for (resolver, should_update) in [("1", true), ("2", false)] {
            let local = crate::fs_utils::Utf8TempDir::new().unwrap();
            let released = crate::fs_utils::Utf8TempDir::new().unwrap();
            for directory in [local.path(), released.path()] {
                fs_err::write(
                    directory.join("Cargo.toml"),
                    format!(
                        "[workspace]\nmembers = [\"app\", \"library\"]\nresolver = \"{resolver}\"\n"
                    ),
                )
                .unwrap();
                for (name, manifest) in [
                    (
                        "app",
                        r#"
[dependencies]
library = { path = "../library" }
[dev-dependencies]
library = { path = "../library", features = ["extra"] }
"#,
                    ),
                    (
                        "library",
                        "[dependencies]\nleaf = { version = \"1\", optional = true }\n\
                         [features]\nextra = [\"dep:leaf\"]\n",
                    ),
                ] {
                    write_package(&directory.join(name), name, "0.1.0", manifest);
                }
            }
            let lockfile = r#"
version = 4
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["library"]
[[package]]
name = "library"
version = "0.1.0"
dependencies = ["leaf"]
[[package]]
name = "leaf"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;
            fs_err::write(released.path().join("Cargo.lock"), lockfile).unwrap();
            fs_err::write(
                local.path().join("Cargo.lock"),
                lockfile.replace("1.0.0", "1.0.1"),
            )
            .unwrap();
            let local_metadata =
                cargo_utils::get_manifest_metadata(&local.path().join("Cargo.toml")).unwrap();
            let released = released_workspace(
                cargo_utils::get_manifest_metadata(&released.path().join("Cargo.toml")).unwrap(),
            );
            // Resolver 1 enables the features of dev-dependencies in the binary's build too.
            assert_eq!(
                are_workspace_lock_dependencies_updated(&local_metadata, &released, "app").unwrap(),
                should_update,
                "resolver {resolver}"
            );
        }
    }

    #[test]
    fn workspace_lock_comparison_preserves_patched_path_dependencies() {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        let root = directory.path();
        fs_err::write(
            root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"binary\", \"library\", \"shared\", \"normal-leaf\", \"dev-leaf\"]\n\
             exclude = [\"test-shared\"]\nresolver = \"2\"\n\
             [patch.crates-io]\nshared = { path = \"shared\" }\n",
        )
        .unwrap();
        for (path, name, version, dependencies) in [
            (
                "binary",
                "binary",
                "0.1.0",
                "[dependencies]\nlibrary = { path = \"../library\" }\n",
            ),
            (
                "library",
                "library",
                "0.1.0",
                "[dependencies]\nshared = \"1.0\"\n\
                 [dev-dependencies]\nshared-test = { package = \"shared\", path = \"../test-shared\" }\n",
            ),
            (
                "shared",
                "shared",
                "1.0.0",
                "[dependencies]\nnormal-leaf = { path = \"../normal-leaf\" }\n",
            ),
            (
                "test-shared",
                "shared",
                "2.0.0",
                "[workspace]\n[dependencies]\ndev-leaf = { path = \"../dev-leaf\" }\n",
            ),
            ("normal-leaf", "normal-leaf", "1.0.0", ""),
            ("dev-leaf", "dev-leaf", "1.0.0", ""),
        ] {
            write_package(&root.join(path), name, version, dependencies);
        }
        let read_dependencies = || {
            generate_lockfile(root);
            let metadata = cargo_utils::get_manifest_metadata(&root.join("Cargo.toml")).unwrap();
            lock_dependencies(&metadata, "binary")
        };
        for dependency_kind in ["dependencies", "build-dependencies"] {
            // A dev declaration may resolve to the patched runtime package itself,
            // or to a distinct package with the same name. Preserve only runtime edges.
            for dev_path in ["shared", "test-shared"] {
                fs_err::write(
                    root.join("library/Cargo.toml"),
                    package_manifest(
                        "library",
                        "0.1.0",
                        &format!(
                            "[{dependency_kind}]\nshared = \"1.0\"\n\
                             [dev-dependencies]\nshared-test = {{ package = \"shared\", path = \"../{dev_path}\" }}\n"
                        ),
                    ),
                )
                .unwrap();
                let released = read_dependencies();
                for (leaf, should_update) in [("normal-leaf", true), ("dev-leaf", false)] {
                    let manifest = root.join(leaf).join("Cargo.toml");
                    let original = fs_err::read_to_string(&manifest).unwrap();
                    fs_err::write(&manifest, original.replace("1.0.0", "1.0.1")).unwrap();
                    let local = read_dependencies();
                    assert_eq!(
                        are_dependencies_updated(&local, &released),
                        should_update,
                        "updating {leaf} with {dependency_kind} and dev path {dev_path}"
                    );
                    fs_err::write(manifest, original).unwrap();
                }
            }
        }
    }

    #[test]
    fn workspace_lock_comparison_preserves_replaced_path_dependencies() {
        // Cargo records the original registry edge and its replacement separately.
        let lockfile = r#"
version = 4
[[package]]
name = "app"
version = "1.0.0"
dependencies = ["library"]
[[package]]
name = "library"
version = "1.0.0"
dependencies = ["shared 1.0.0", "shared 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"]
[[package]]
name = "shared"
version = "1.0.0"
dependencies = ["leaf"]
[[package]]
name = "shared"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
replace = "shared 1.0.0"
[[package]]
name = "leaf"
version = "1.0.0"
"#;
        let updated_lockfile = lockfile.replace(
            "name = \"leaf\"\nversion = \"1.0.0\"",
            "name = \"leaf\"\nversion = \"1.0.1\"",
        );
        for (kind, should_update) in [
            ("dependencies", true),
            ("build-dependencies", true),
            ("dev-dependencies", false),
        ] {
            let read_dependencies = |lockfile: &str| {
                let (directory, metadata) = workspace_for_lock(lockfile);
                let root = directory.path();
                let leaf = cargo_utils::workspace_package(&metadata, "leaf").unwrap();
                let dev_table = if kind == "dev-dependencies" {
                    ""
                } else {
                    "[dev-dependencies]\n"
                };
                for (manifest, declarations) in [
                    (
                        "Cargo.toml",
                        "[replace]\n\"shared:1.0.0\" = { path = \"shared-1.0.0\" }\n".to_owned(),
                    ),
                    (
                        "app-1.0.0/Cargo.toml",
                        "[dependencies]\nlibrary = { path = \"../library-1.0.0\" }\n".to_owned(),
                    ),
                    (
                        "library-1.0.0/Cargo.toml",
                        format!(
                            "[{kind}]\nshared = \"=1.0.0\"\n\
                             {dev_table}shared-test = {{ package = \"shared\", path = \"../shared-1.0.0\" }}\n"
                        ),
                    ),
                    (
                        "shared-1.0.0/Cargo.toml",
                        format!(
                            "[dependencies]\nleaf = {{ path = \"../leaf-{}\" }}\n",
                            leaf.version
                        ),
                    ),
                ] {
                    let manifest = root.join(manifest);
                    let contents = fs_err::read_to_string(&manifest).unwrap();
                    fs_err::write(manifest, format!("{contents}{declarations}")).unwrap();
                }
                let metadata =
                    cargo_utils::get_manifest_metadata(&root.join("Cargo.toml")).unwrap();
                lock_dependencies(&metadata, "app")
            };
            let released = read_dependencies(lockfile);
            let local = read_dependencies(&updated_lockfile);
            assert_eq!(
                are_dependencies_updated(&local, &released),
                should_update,
                "updating a replacement's dependency through {kind}"
            );
        }
    }

    #[test]
    fn workspace_lock_comparison_ignores_git_dev_dependency_with_plus_in_branch() {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        let git_path = directory.path().join("git-dependency");
        fs_err::create_dir_all(&git_path).unwrap();
        let git_repo = git_cmd::Repo::init(&git_path);
        write_package(
            &git_path,
            "shared",
            "1.0.0",
            "[dependencies]\ndev-leaf = { path = \"leaf\" }\n",
        );
        let leaf_manifest = git_path.join("leaf/Cargo.toml");
        let leaf = package_manifest("dev-leaf", "1.0.0", "");
        write_package(&git_path.join("leaf"), "dev-leaf", "1.0.0", "");
        git_repo.add_all_and_commit("initial dependency").unwrap();
        git_cmd::git_in_dir(&git_path, &["checkout", "-b", "feature+next"]).unwrap();
        let git_url = url::Url::from_directory_path(&git_path).unwrap();

        let local = directory.path().join("local");
        let released = directory.path().join("released");
        for root in [&local, &released] {
            fs_err::create_dir_all(root).unwrap();
            fs_err::write(
                root.join("Cargo.toml"),
                "[workspace]\nmembers = [\"binary\", \"library\", \"shared\"]\nresolver = \"2\"\n",
            )
            .unwrap();
            for (name, dependencies) in [
                (
                    "binary",
                    "[dependencies]\nlibrary = { path = \"../library\" }\n".to_owned(),
                ),
                (
                    "library",
                    format!(
                        "[dependencies]\nshared = {{ path = \"../shared\" }}\n[dev-dependencies]\nshared-test = {{ package = \"shared\", git = {:?}, branch = \"feature+next\" }}\n",
                        git_url.as_str()
                    ),
                ),
                ("shared", String::new()),
            ] {
                write_package(&root.join(name), name, "1.0.0", &dependencies);
            }
        }
        run_cargo_unwrap(&local, &["generate-lockfile"]);
        fs_err::copy(local.join("Cargo.lock"), released.join("Cargo.lock")).unwrap();
        fs_err::write(&leaf_manifest, leaf.replace("1.0.0", "1.0.1")).unwrap();
        git_repo
            .add_all_and_commit("update dev dependency")
            .unwrap();
        run_cargo_unwrap(&local, &["update"]);

        let local_metadata = cargo_utils::get_manifest_metadata(&local.join("Cargo.toml")).unwrap();
        let released_metadata =
            cargo_utils::get_manifest_metadata(&released.join("Cargo.toml")).unwrap();
        let lockfile = fs_err::read_to_string(local.join("Cargo.lock")).unwrap();
        assert!(lockfile.contains("feature%2Bnext"));
        assert!(lockfile.contains("name = \"dev-leaf\"\nversion = \"1.0.1\""));
        let released = released_workspace(released_metadata);
        // Only the tests of the package declaring the dev dependency build the update.
        for package in ["binary", "library"] {
            assert!(
                !are_workspace_lock_dependencies_updated(&local_metadata, &released, package)
                    .unwrap(),
                "{package}"
            );
        }
    }

    #[test]
    fn workspace_lock_comparison_distinguishes_dependency_sources() {
        let directory = crate::fs_utils::Utf8TempDir::new().unwrap();
        fs_err::write(
            directory.path().join("Cargo.toml"),
            "[workspace]\nmembers = [\"binary\", \"library\", \"shared\"]\nresolver = \"2\"\n",
        )
        .unwrap();
        for name in ["binary", "library", "shared"] {
            write_package(&directory.path().join(name), name, "1.0.0", "");
        }
        fs_err::write(
            directory.path().join("binary/Cargo.toml"),
            package_manifest(
                "binary",
                "1.0.0",
                "[dependencies]\nlibrary = { path = \"../library\" }\n",
            ),
        )
        .unwrap();
        let path = "path = \"../shared\"";
        let registry = "version = \"1\"";
        let git = "git = \"https://example.com/shared\"";
        let other_git = "git = \"https://example.com/other\"";
        let branch = "git = \"https://example.com/shared\", branch = \"next\"";
        // A branch name that Cargo percent-encodes in the lockfile but not in metadata.
        let escaped_branch = "git = \"https://example.com/shared\", branch = \"feature/next\"";
        let plus_branch = "git = \"https://example.com/shared\", branch = \"feature+next\"";
        for (normal, dev) in [
            (git, other_git),
            (git, branch),
            (git, escaped_branch),
            (escaped_branch, git),
            (escaped_branch, branch),
            (git, plus_branch),
            (plus_branch, git),
            (registry, git),
            (git, registry),
            (path, git),
            (git, path),
            (path, registry),
            (registry, path),
        ] {
            fs_err::write(
                directory.path().join("library/Cargo.toml"),
                package_manifest(
                    "library",
                    "1.0.0",
                    &format!(
                        "[dependencies]\nshared = {{ {normal} }}\n\
                         [dev-dependencies]\nshared-test = {{ package = \"shared\", {dev} }}\n"
                    ),
                ),
            )
            .unwrap();
            // Read real dependency declarations without resolving or fetching them.
            let metadata =
                cargo_utils::get_manifest_metadata(&directory.path().join("Cargo.toml")).unwrap();
            let library = metadata
                .packages
                .iter()
                .find(|p| p.name == "library")
                .unwrap();
            let mut dependency_ids = Vec::new();
            let mut lockfile = String::from(
                "version = 4\n[[package]]\nname = \"binary\"\nversion = \"1.0.0\"\ndependencies = [\"library\"]\n",
            );
            for dependency in &library.dependencies {
                let leaf = if dependency.kind == DependencyKind::Development {
                    "dev-leaf"
                } else {
                    "normal-leaf"
                };
                let source = dependency.source.as_ref().map(|s| s.repr.as_str());
                // Cargo writes dependency IDs with the same encoding it uses for the
                // package's own `source`, minus the resolved revision.
                dependency_ids.push(source.map_or_else(
                    || "shared 1.0.0".to_string(),
                    |source| format!("shared 1.0.0 ({})", encoded_source(source)),
                ));
                lockfile.push_str("[[package]]\nname = \"shared\"\nversion = \"1.0.0\"\n");
                if let Some(source) = source {
                    let precise = if source.starts_with("git+") {
                        "#0123456789abcdef"
                    } else {
                        ""
                    };
                    lockfile.push_str(&format!(
                        "source = \"{}{precise}\"\n",
                        encoded_source(source)
                    ));
                }
                lockfile.push_str(&format!(
                    "dependencies = [{leaf:?}]\n[[package]]\nname = {leaf:?}\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
                ));
            }
            lockfile.push_str(&format!(
                "[[package]]\nname = \"library\"\nversion = \"1.0.0\"\ndependencies = {dependency_ids:?}\n"
            ));
            fs_err::write(directory.path().join("Cargo.lock"), &lockfile).unwrap();
            let released = lock_dependencies(&metadata, "binary");
            for (leaf, should_update) in [("dev-leaf", false), ("normal-leaf", true)] {
                let changed = lockfile.replace(
                    &format!("name = {leaf:?}\nversion = \"1.0.0\""),
                    &format!("name = {leaf:?}\nversion = \"1.0.1\""),
                );
                fs_err::write(directory.path().join("Cargo.lock"), changed).unwrap();
                let local = lock_dependencies(&metadata, "binary");
                assert_eq!(
                    are_dependencies_updated(&local, &released),
                    should_update,
                    "updating {leaf} with normal {normal} and dev {dev}"
                );
            }
        }
    }

    #[test]
    fn workspace_lock_comparison_follows_source_qualified_git_dependencies() {
        let directory = tempfile::tempdir().unwrap();
        let directory = Utf8Path::from_path(directory.path()).unwrap();
        let released = directory.join("released.lock");
        let local = directory.join("local.lock");
        // Cargo adds sources to dependency IDs when name and version are ambiguous,
        // but only the package source records the precise Git revision.
        let lockfile = r#"
version = 4
[[package]]
name = "binary"
version = "0.1.0"
dependencies = ["shared 0.1.0 (git+https://example.com/one)", "shared 0.1.0 (git+https://example.com/two?branch=next)"]
[[package]]
name = "shared"
version = "0.1.0"
source = "git+https://example.com/one#1111111111111111111111111111111111111111"
dependencies = ["leaf"]
[[package]]
name = "shared"
version = "0.1.0"
source = "git+https://example.com/two?branch=next#2222222222222222222222222222222222222222"
[[package]]
name = "leaf"
version = "1.0.0"
source = "git+https://example.com/one#1111111111111111111111111111111111111111"
"#;
        fs_err::write(&released, lockfile).unwrap();
        fs_err::write(&local, lockfile).unwrap();
        assert!(!compare_workspace_locks(&local, &released, "binary"));
        fs_err::write(&local, lockfile.replace("1.0.0", "1.0.1")).unwrap();
        assert!(compare_workspace_locks(&local, &released, "binary"));
    }

    #[test]
    fn workspace_lock_comparison_ignores_unrelated_packages() {
        let directory = tempfile::tempdir().unwrap();
        let directory = Utf8Path::from_path(directory.path()).unwrap();
        let released = directory.join("released.lock");
        let local = directory.join("local.lock");
        let lockfile = r#"
version = 4
[[package]]
name = "binary"
version = "0.1.0"
dependencies = ["library"]
[[package]]
name = "library"
version = "0.1.0"
dependencies = ["shared 1.0.0 (registry+https://example.com/index)"]
[[package]]
name = "shared"
version = "1.0.0"
source = "registry+https://example.com/index"
[[package]]
name = "shared"
version = "2.0.0"
source = "registry+https://example.com/index"
[[package]]
name = "unrelated"
version = "0.1.0"
dependencies = ["shared 2.0.0"]
"#;
        fs_err::write(&released, lockfile).unwrap();
        fs_err::write(
            &local,
            lockfile.replace("2.0.0", "2.0.1").replace(
                "name = \"unrelated\"\nversion = \"0.1.0\"",
                "name = \"unrelated\"\nversion = \"0.1.1\"",
            ),
        )
        .unwrap();
        assert!(!compare_workspace_locks(&local, &released, "binary"));
        assert!(compare_workspace_locks(&local, &released, "unrelated"));

        fs_err::write(&local, lockfile.replace("1.0.0", "1.0.1")).unwrap();
        assert!(compare_workspace_locks(&local, &released, "binary"));
        assert!(!compare_workspace_locks(&local, &released, "unrelated"));
    }
}
