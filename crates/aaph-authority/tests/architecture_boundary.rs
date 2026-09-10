#[test]
fn authority_cannot_link_workspace_effect_capability() {
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("cap-std"));
    assert!(!manifest.contains("aaph-pep"));

    let library = include_str!("../src/lib.rs");
    let orchestrator = include_str!("../src/orchestrator/mod.rs");
    let routes = include_str!("../src/routes/mod.rs");
    for source in [library, orchestrator, routes] {
        assert!(!source.contains("cap_std"));
        assert!(!source.contains("Workspace"));
        assert!(!source.contains("crate::executor"));
        assert!(!source.contains("aaph_pep"));
    }
}
