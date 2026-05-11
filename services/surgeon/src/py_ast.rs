//! Python AST-backed indicator scanning using tree-sitter-python.
//!
//! Tree-sitter provides reliable AST-level detection for Python source files
//! that avoids false positives from regex matching inside string literals and
//! comments. This complements the regex pass in `scan_text` with structured
//! import statement and call expression analysis.
//!
//! Security invariant: this module never executes any scanned code.

use std::path::Path;

use aegiscudo_core::{Severity, StaticIndicator};

use crate::indicator;

/// Dangerous Python standard library modules whose import warrants an indicator.
const DANGEROUS_STDLIB: &[(&str, Severity)] = &[
    ("subprocess", Severity::Critical),
    ("os", Severity::High),
    ("sys", Severity::High),
    ("socket", Severity::High),
    ("http.client", Severity::High),
    ("urllib.request", Severity::High),
    ("urllib.error", Severity::High),
    ("multiprocessing", Severity::High),
    ("pty", Severity::Critical),
    ("ctypes", Severity::Critical),
    ("cffi", Severity::High),
    ("builtins", Severity::Critical),
    ("importlib", Severity::High),
    ("runpy", Severity::High),
    ("code", Severity::High),
    ("codeop", Severity::High),
    ("pickle", Severity::High),
    ("shelve", Severity::High),
    ("marshal", Severity::High),
];

/// Dangerous Python built-in call targets that warrant an indicator.
const DANGEROUS_BUILTINS: &[(&str, Severity)] = &[
    ("eval", Severity::Critical),
    ("exec", Severity::Critical),
    ("compile", Severity::High),
    ("__import__", Severity::Critical),
    ("open", Severity::High),
];

/// Scan a Python source file using the tree-sitter-python grammar.
///
/// Emits indicators for:
/// - `import dangerous_module` / `from dangerous_module import ...`
/// - `eval(...)` and `exec(...)` calls
/// - `__import__(...)` dynamic imports
/// - `compile(...)` code compilation
/// - `open(...)` file access calls (advisory, context-sensitive)
pub fn scan_py_ast(
    root: &Path,
    path: &Path,
    source: &str,
    indicators: &mut Vec<StaticIndicator>,
) {
    let lang = tree_sitter_python::LANGUAGE;
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang.into()).is_err() {
        // Grammar load failure — degrade silently; regex pass still runs.
        return;
    }

    let tree = match parser.parse(source.as_bytes(), None) {
        Some(t) => t,
        None => return,
    };

    // Walk the tree to find import statements and call expressions.
    walk_node(root, path, source, tree.root_node(), indicators);
}

fn walk_node(
    root: &Path,
    path: &Path,
    source: &str,
    node: tree_sitter::Node<'_>,
    indicators: &mut Vec<StaticIndicator>,
) {
    match node.kind() {
        "import_statement" => {
            check_import_statement(root, path, source, node, indicators);
        }
        "import_from_statement" => {
            check_from_import_statement(root, path, source, node, indicators);
        }
        "call" => {
            check_call_expression(root, path, source, node, indicators);
        }
        _ => {}
    }

    for child in node.children(&mut node.walk()) {
        walk_node(root, path, source, child, indicators);
    }
}

/// Handle `import module` and `import module as alias` statements.
fn check_import_statement(
    root: &Path,
    path: &Path,
    source: &str,
    node: tree_sitter::Node<'_>,
    indicators: &mut Vec<StaticIndicator>,
) {
    // The imported name(s) are dotted_name children of this node.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let kind = child.kind();
        if kind == "dotted_name" || kind == "aliased_import" {
            // For aliased_import, the first child is the dotted_name.
            let name_node = if kind == "aliased_import" {
                child.child(0)
            } else {
                Some(child)
            };
            if let Some(n) = name_node {
                let module_name = node_text(source, n);
                emit_for_module(root, path, source, node, module_name, "import", indicators);
            }
        }
    }
}

/// Handle `from module import name` statements.
fn check_from_import_statement(
    root: &Path,
    path: &Path,
    source: &str,
    node: tree_sitter::Node<'_>,
    indicators: &mut Vec<StaticIndicator>,
) {
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "dotted_name" {
            let module_name = node_text(source, child);
            emit_for_module(root, path, source, node, module_name, "from-import", indicators);
            break; // Only the first dotted_name is the module; rest are names.
        }
    }
}

/// Emit an indicator if the module name matches a dangerous known module.
fn emit_for_module(
    root: &Path,
    path: &Path,
    _source: &str,
    context_node: tree_sitter::Node<'_>,
    module_name: &str,
    import_kind: &str,
    indicators: &mut Vec<StaticIndicator>,
) {
    // Normalize: `os.path` → `os`, `subprocess.run` → `subprocess`
    let top_level = module_name.split('.').next().unwrap_or(module_name);

    for (dangerous, severity) in DANGEROUS_STDLIB {
        // Match top-level module or full dotted name.
        if top_level == *dangerous || module_name == *dangerous {
            let line = (context_node.start_position().row + 1) as u32;
            let summary = format!(
                "Python {import_kind} of `{module_name}` — commonly used for dangerous system access"
            );
            indicators.push(indicator(
                root,
                path,
                "py-ast-dangerous-import",
                severity.clone(),
                line,
                line,
                &summary,
                None,
            ));
            return;
        }
    }
}

/// Handle call expressions: `eval(...)`, `exec(...)`, `__import__(...)`, etc.
fn check_call_expression(
    root: &Path,
    path: &Path,
    source: &str,
    node: tree_sitter::Node<'_>,
    indicators: &mut Vec<StaticIndicator>,
) {
    // The function being called is the first child of a `call` node.
    let callee = match node.child(0) {
        Some(c) => c,
        None => return,
    };

    let callee_text = node_text(source, callee);
    let line = (node.start_position().row + 1) as u32;

    for (builtin, severity) in DANGEROUS_BUILTINS {
        if callee_text == *builtin {
            // `open` is common; only flag it if it's calling with write mode or
            // unusual flags — for MVP, flag all occurrences as advisory.
            let summary = format!(
                "Python `{callee_text}()` call — dangerous built-in used at module or install-time scope"
            );
            indicators.push(indicator(
                root,
                path,
                "py-ast-dangerous-call",
                severity.clone(),
                line,
                line,
                &summary,
                None,
            ));
            return;
        }
    }

    // Detect `getattr(obj, 'dangerous')` pattern used to obscure attribute access.
    if callee_text == "getattr" {
        let args_node = node.child(1);
        if let Some(args) = args_node {
            let args_text = node_text(source, args);
            if args_text.contains("__import__")
                || args_text.contains("exec")
                || args_text.contains("eval")
            {
                let obf_line = (node.start_position().row + 1) as u32;
                indicators.push(indicator(
                    root,
                    path,
                    "py-ast-obfuscated-call",
                    Severity::Critical,
                    obf_line,
                    obf_line,
                    "getattr() used to access dangerous built-in — common obfuscation pattern",
                    None,
                ));
            }
        }
    }
}

/// Extract the UTF-8 text for a tree-sitter node from the source string.
fn node_text<'a>(source: &'a str, node: tree_sitter::Node<'_>) -> &'a str {
    let start = node.start_byte();
    let end = node.end_byte().min(source.len());
    &source[start..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(source: &str) -> Vec<String> {
        let mut indicators = Vec::new();
        let root = Path::new("/root");
        let path = Path::new("/root/setup.py");
        scan_py_ast(root, path, source, &mut indicators);
        indicators.into_iter().map(|i| i.indicator_type).collect()
    }

    #[test]
    fn import_subprocess_detected() {
        let types = scan("import subprocess\nsubprocess.run(['ls'])");
        assert!(types.contains(&"py-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn from_subprocess_import_detected() {
        let types = scan("from subprocess import run\nrun(['ls'])");
        assert!(types.contains(&"py-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn import_os_detected() {
        let types = scan("import os\nos.system('ls')");
        assert!(types.contains(&"py-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn import_safe_module_not_flagged() {
        let types = scan("import json\nimport pathlib\ndata = json.loads('{}')");
        assert!(!types.contains(&"py-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn eval_call_detected() {
        let types = scan("result = eval(user_input)");
        assert!(types.contains(&"py-ast-dangerous-call".to_owned()), "{types:?}");
    }

    #[test]
    fn exec_call_detected() {
        let types = scan("exec('import os; os.system(\"ls\")')");
        assert!(types.contains(&"py-ast-dangerous-call".to_owned()), "{types:?}");
    }

    #[test]
    fn dunder_import_detected() {
        let types = scan("mod = __import__('os')");
        assert!(types.contains(&"py-ast-dangerous-call".to_owned()), "{types:?}");
    }

    #[test]
    fn eval_in_comment_not_flagged() {
        // eval inside a comment should not produce an AST-level indicator
        // (regex-based scan may still flag it; this validates AST accuracy)
        let types = scan("# eval is dangerous\nprint('safe code')");
        assert!(!types.contains(&"py-ast-dangerous-call".to_owned()), "{types:?}");
    }

    #[test]
    fn import_socket_detected() {
        let types = scan("import socket\ns = socket.socket()");
        assert!(types.contains(&"py-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn import_pickle_detected() {
        let types = scan("import pickle\nobj = pickle.loads(data)");
        assert!(types.contains(&"py-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn getattr_obfuscation_detected() {
        let types = scan(r#"fn = getattr(builtins, "__import__")"#);
        assert!(types.contains(&"py-ast-obfuscated-call".to_owned()), "{types:?}");
    }
}
