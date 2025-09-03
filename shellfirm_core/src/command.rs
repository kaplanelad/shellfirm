// No external regex; we manually parse quotes and operators

fn flush_current(current: &mut String, out: &mut Vec<String>) {
    let trimmed = current.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
    current.clear();
}

fn try_parse_operator(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    in_single_quote: bool,
    in_double_quote: bool,
) -> bool {
    if in_single_quote || in_double_quote {
        return false;
    }
    match chars.peek().copied() {
        Some('&') => {
            chars.next();
            if matches!(chars.peek(), Some('&')) {
                chars.next();
            }
            true
        }
        Some('|') => {
            chars.next();
            if matches!(chars.peek(), Some('|')) {
                chars.next();
            }
            true
        }
        _ => false,
    }
}

#[must_use]
pub fn parse_and_split_command(command: &str) -> Vec<String> {
    let mut commands: Vec<String> = Vec::new();
    let mut current_command = String::new();
    let mut chars = command.chars().peekable();

    let mut in_single_quote = false;
    let mut in_double_quote = false;
    // Track nesting to avoid splitting inside subshells, groupings, or function bodies
    let mut paren_depth: usize = 0; // ( )
    let mut brace_depth: usize = 0; // { }

    while let Some(ch) = chars.peek().copied() {
        match ch {
            '\\' => {
                // Append backslash and the next character literally
                current_command.push(ch);
                chars.next();
                if let Some(next_ch) = chars.peek().copied() {
                    current_command.push(next_ch);
                    chars.next();
                }
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
                current_command.push(ch);
                chars.next();
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
                current_command.push(ch);
                chars.next();
            }
            // Track nesting when not in quotes
            '(' if !in_single_quote && !in_double_quote => {
                paren_depth = paren_depth.saturating_add(1);
                current_command.push(ch);
                chars.next();
            }
            ')' if !in_single_quote && !in_double_quote && paren_depth > 0 => {
                paren_depth -= 1;
                current_command.push(ch);
                chars.next();
            }
            '{' if !in_single_quote && !in_double_quote => {
                brace_depth = brace_depth.saturating_add(1);
                current_command.push(ch);
                chars.next();
            }
            '}' if !in_single_quote && !in_double_quote && brace_depth > 0 => {
                brace_depth -= 1;
                current_command.push(ch);
                chars.next();
            }
            _ => {
                // Only split on operators when not in quotes and not nested
                let can_split =
                    !in_single_quote && !in_double_quote && paren_depth == 0 && brace_depth == 0;
                if can_split && try_parse_operator(&mut chars, in_single_quote, in_double_quote) {
                    flush_current(&mut current_command, &mut commands);
                } else {
                    current_command.push(ch);
                    chars.next();
                }
            }
        }
    }

    flush_current(&mut current_command, &mut commands);
    commands
}

#[cfg(test)]
mod tests {
    use super::parse_and_split_command;
    use rstest::rstest;

    fn s(input: &str, expected: Vec<&str>) -> (String, Vec<String>) {
        (
            input.to_string(),
            expected.into_iter().map(String::from).collect(),
        )
    }

    fn very_long_case() -> (String, Vec<String>) {
        let long_string = "a".repeat(1000);
        let input = format!("echo '{}' && echo world", long_string);
        let expected = vec![format!("echo '{}'", long_string), "echo world".to_string()];
        (input, expected)
    }

    #[rstest]
    #[case(s("echo hello", vec!["echo hello"]))]
    #[case(s("echo hello & echo world", vec!["echo hello", "echo world"]))]
    #[case(s("echo hello | grep world", vec!["echo hello", "grep world"]))]
    #[case(s("echo hello && echo world", vec!["echo hello", "echo world"]))]
    #[case(s("echo hello || echo world", vec!["echo hello", "echo world"]))]
    #[case(s("echo hello && echo world | grep test & echo done", vec!["echo hello", "echo world", "grep test", "echo done"]))]
    #[case(s("rm -rf '/tmp/test' && echo 'hello world'", vec!["rm -rf '/tmp/test'", "echo 'hello world'"]))]
    #[case(s("rm -rf \"/tmp/test\" && echo \"hello world\"", vec!["rm -rf \"/tmp/test\"", "echo \"hello world\""]))]
    #[case(s("rm -rf '/tmp/test' && echo \"hello world\"", vec!["rm -rf '/tmp/test'", "echo \"hello world\""]))]
    #[case(s("", Vec::<&str>::new()))]
    #[case(s("&& || & |", Vec::<&str>::new()))]
    #[case(s("&& echo hello &&", vec!["echo hello"]))]
    #[case(s("& echo hello &", vec!["echo hello"]))]
    #[case(s("echo hello &&&& echo world", vec!["echo hello", "echo world"]))]
    #[case(s("echo hello |||| echo world", vec!["echo hello", "echo world"]))]
    #[case(s("echo hello && echo world || echo test", vec!["echo hello", "echo world", "echo test"]))]
    #[case(s("echo 'hello world' && echo \"test string\"", vec!["echo 'hello world'", "echo \"test string\""]))]
    #[case(s("echo 'hello\\'world' && echo \"test\\\"string\"", vec!["echo 'hello\\'world'", "echo \"test\\\"string\""]))]
    #[case(s("echo 'hello \"world\"' && echo \"test 'string'\"", vec!["echo 'hello \"world\"'", "echo \"test 'string'\""]))]
    #[case(s("echo hello  &&  echo world", vec!["echo hello", "echo world"]))]
    #[case(s("echo hello\t&&\techo world", vec!["echo hello", "echo world"]))]
    #[case(s("   \t\n  ", Vec::<&str>::new()))]
    #[case(s("echo hello && echo world || echo test && echo done", vec!["echo hello", "echo world", "echo test", "echo done"]))]
    #[case(s("echo hello & echo world && echo test | echo done", vec!["echo hello", "echo world", "echo test", "echo done"]))]
    #[case(s("echo 'hello && world' && echo \"test || done\"", vec!["echo 'hello && world'", "echo \"test || done\""]))]
    #[case(s("echo 'hello 🌍 world' && echo 'test 🚀 done'", vec!["echo 'hello 🌍 world'", "echo 'test 🚀 done'"]))]
    #[case(s("echo 'hello\x00world' && echo 'test\x01done'", vec!["echo 'hello\x00world'", "echo 'test\x01done'"]))]
    #[case(very_long_case())]
    #[case(s("echo 'hello world'", vec!["echo 'hello world'"]))]
    #[case(s("echo 'test string'", vec!["echo 'test string'"]))]
    #[case(s("echo \"quoted text\"", vec!["echo \"quoted text\""]))]
    #[case(s("echo hello && :(){ :|:& };:", vec!["echo hello", ":(){ :|:& };:"]))]
    fn parse_and_split_all_cases(#[case] case: (String, Vec<String>)) {
        let (input, expected) = case;
        assert_eq!(parse_and_split_command(&input), expected);
    }
}
