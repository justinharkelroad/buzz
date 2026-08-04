//! Compile-time desktop build profile.
//!
//! The release workflow sets `BUZZ_BUILD_CHANNEL`; `build.rs` validates it and
//! exposes the value here. Personal staging must never infer its profile from
//! a mutable runtime environment variable or from a bundle-id naming
//! convention because both would make storage isolation fail open.

pub(crate) const PERSONAL_STAGING_BUILD_CHANNEL: &str = "personal-staging";

pub(crate) fn build_channel() -> &'static str {
    env!("BUZZ_DESKTOP_BUILD_CHANNEL")
}

pub(crate) fn is_personal_staging_build() -> bool {
    is_personal_staging_channel(build_channel())
}

pub(crate) fn allows_legacy_profile_import() -> bool {
    channel_allows_legacy_profile_import(build_channel())
}

fn is_personal_staging_channel(channel: &str) -> bool {
    channel == PERSONAL_STAGING_BUILD_CHANNEL
}

fn channel_allows_legacy_profile_import(channel: &str) -> bool {
    !is_personal_staging_channel(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn personal_staging_channel_is_exact() {
        assert!(is_personal_staging_channel("personal-staging"));
        assert!(!is_personal_staging_channel("production"));
        assert!(!is_personal_staging_channel("personal-staging-preview"));
    }

    #[test]
    fn only_personal_staging_blocks_legacy_profile_import() {
        assert!(channel_allows_legacy_profile_import("production"));
        assert!(!channel_allows_legacy_profile_import("personal-staging"));
    }

    #[test]
    fn compiled_channel_is_validated_by_build_script() {
        assert!(matches!(build_channel(), "production" | "personal-staging"));
    }

    #[test]
    #[ignore]
    fn compiled_channel_matches_expected_test_contract() {
        let expected = std::env::var("BUZZ_TEST_EXPECTED_BUILD_CHANNEL")
            .expect("BUZZ_TEST_EXPECTED_BUILD_CHANNEL must be set by the compile-mode test");
        assert_eq!(build_channel(), expected);
        assert_eq!(
            is_personal_staging_build(),
            expected == PERSONAL_STAGING_BUILD_CHANNEL
        );
    }
}
