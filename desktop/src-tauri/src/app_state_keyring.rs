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

fn fixed_keyring_service_for_profile(
    is_personal_staging: bool,
    is_debug: bool,
) -> Option<&'static str> {
    if is_personal_staging {
        Some(PERSONAL_STAGING_KEYRING_SERVICE)
    } else if is_debug {
        None
    } else {
        Some(PRODUCTION_KEYRING_SERVICE)
    }
}

pub(crate) fn keyring_service() -> &'static str {
    if let Some(service) = fixed_keyring_service_for_profile(
        crate::desktop_profile::is_personal_staging_build(),
        cfg!(debug_assertions),
    ) {
        return service;
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
        PERSONAL_STAGING_KEYRING_SERVICE,
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
        assert_eq!(fixed_keyring_service_for_profile(false, true), None);
        assert_eq!(
            fixed_keyring_service_for_profile(false, false),
            Some("buzz-desktop")
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
