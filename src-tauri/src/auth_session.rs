use isideload::anisette::AnisetteClientInfo;

pub fn client_info() -> AnisetteClientInfo {
    AnisetteClientInfo {
        client_info: "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>".into(),
        user_agent: "akd/1.0 CFNetwork/811.5.4 Darwin/16.7.0".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_identity_avoids_the_legacy_secondary_auth_loop() {
        let info = client_info();
        assert!(info.client_info.contains("<Mac OS X;27.3;26C5035r>"));
        assert!(!info.client_info.contains("<macOS;"));
        assert!(info.user_agent.contains("CFNetwork/3896.300.31 Darwin/27.3.0"));
    }
}
