const PRODUCTION_KEYRING_SERVICE: &str = "buzz-desktop";
const PERSONAL_STAGING_KEYRING_SERVICE: &str = "buzz-desktop-personal-staging";

/// Service name for the desktop OS keyring. Personal staging always owns a
/// distinct service, including in debug test builds. Other debug builds default
/// to a dev service, while standalone worktree launches may request a scoped
/// dev service.
fn dev_keyring_service(configured: Option<String>) -> String {
    configured
        .filter(|service| service.starts_with("buzz-desktop-dev."))
        .unwrap_or_else(|| "buzz-desktop-dev".to_string())
}

/// Production keyring service, scoped by bundle id when one was compiled in.
///
/// Isolation used to be keyed on the build CHANNEL alone, which suffices only while a single
/// production-channel Buzz exists on a machine. A fork's production build and the upstream
/// production app are BOTH `production`, so they shared one keychain blob
/// (`buzz-desktop` / `secrets`) and therefore the `identity` key inside it. The fork would adopt
/// the upstream identity on first launch and could overwrite or delete it later.
///
/// An empty bundle id keeps the historical `buzz-desktop` service exactly, so upstream builds are
/// unchanged. Scoping can only ever REDUCE sharing, never widen it.
fn production_keyring_service(bundle_id: &str) -> String {
    if bundle_id.is_empty() {
        PRODUCTION_KEYRING_SERVICE.to_string()
    } else {
        format!("{PRODUCTION_KEYRING_SERVICE}.{bundle_id}")
    }
}

fn fixed_keyring_service_for_profile(
    is_personal_staging: bool,
    _is_debug: bool,
) -> Option<&'static str> {
    if is_personal_staging {
        Some(PERSONAL_STAGING_KEYRING_SERVICE)
    } else {
        // Production now resolves through `production_keyring_service`, and debug builds still
        // fall through to the dev service. Neither is a fixed constant, so both return None.
        None
    }
}

pub(crate) fn keyring_service() -> &'static str {
    if let Some(service) = fixed_keyring_service_for_profile(
        crate::desktop_profile::is_personal_staging_build(),
        cfg!(debug_assertions),
    ) {
        return service;
    }

    if !cfg!(debug_assertions) {
        static PRODUCTION_SERVICE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        return PRODUCTION_SERVICE
            .get_or_init(|| production_keyring_service(env!("BUZZ_DESKTOP_BUNDLE_ID")))
            .as_str();
    }

    static DEV_SERVICE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    DEV_SERVICE
        .get_or_init(|| dev_keyring_service(std::env::var("BUZZ_DEV_KEYRING_SERVICE").ok()))
        .as_str()
}

pub(super) fn migration_marker_name(service: &str, default_name: &str) -> String {
    if service == "buzz-desktop" || service == "buzz-desktop-dev" {
        default_name.to_string()
    } else {
        format!("identity.{service}.migrated")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        dev_keyring_service, fixed_keyring_service_for_profile, migration_marker_name,
        production_keyring_service, PERSONAL_STAGING_KEYRING_SERVICE,
    };

    #[test]
    fn personal_staging_keyring_overrides_debug_and_release_services() {
        assert_eq!(
            fixed_keyring_service_for_profile(true, false),
            Some("buzz-desktop-personal-staging")
        );
        assert_eq!(
            fixed_keyring_service_for_profile(true, true),
            Some("buzz-desktop-personal-staging")
        );
        // Production and debug both resolve dynamically now, so neither is a fixed constant.
        assert_eq!(fixed_keyring_service_for_profile(false, true), None);
        assert_eq!(fixed_keyring_service_for_profile(false, false), None);
    }

    #[test]
    fn production_keyring_service_is_scoped_by_bundle_id() {
        // No bundle id compiled in: historical behaviour preserved exactly, so an upstream
        // production build keeps using the service it always used.
        assert_eq!(production_keyring_service(""), "buzz-desktop");

        // A fork's production build gets its own service and therefore its own keychain blob,
        // so it can never read or overwrite the upstream app's stored identity.
        assert_eq!(
            production_keyring_service("com.standardplaybook.buzz"),
            "buzz-desktop.com.standardplaybook.buzz"
        );

        // The two must never collide. This is the whole point of the change.
        assert_ne!(
            production_keyring_service("com.standardplaybook.buzz"),
            production_keyring_service("")
        );

        // Scoping must also separate two different forks from each other.
        assert_ne!(
            production_keyring_service("com.example.one"),
            production_keyring_service("com.example.two")
        );
    }

    #[test]
    fn standalone_scope_must_remain_under_dev_service() {
        assert_eq!(
            dev_keyring_service(Some("buzz-desktop-dev.example".to_string())),
            "buzz-desktop-dev.example"
        );
        assert_eq!(
            dev_keyring_service(Some("buzz-desktop".to_string())),
            "buzz-desktop-dev"
        );
    }

    #[test]
    fn standalone_scope_uses_its_own_migration_marker() {
        assert_eq!(
            migration_marker_name("buzz-desktop", "identity.migrated"),
            "identity.migrated"
        );
        assert_eq!(
            migration_marker_name("buzz-desktop-dev", "identity.migrated"),
            "identity.migrated"
        );
        assert_eq!(
            migration_marker_name("buzz-desktop-dev.example", "identity.migrated"),
            "identity.buzz-desktop-dev.example.migrated"
        );
        assert_eq!(
            migration_marker_name(PERSONAL_STAGING_KEYRING_SERVICE, "identity.migrated"),
            "identity.buzz-desktop-personal-staging.migrated"
        );
    }
}
