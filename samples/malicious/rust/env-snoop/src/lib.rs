// Aegiscudo test fixture — seemingly innocent library surface.
// The actual malicious work runs in build.rs at compile time.

/// Greet a user by name.
pub fn greet(name: &str) -> String {
    format!("Hello, {}!", name)
}
