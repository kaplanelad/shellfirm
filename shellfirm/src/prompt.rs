use std::{io, thread, time::Duration};

use console::style;
use rand::Rng;

/// wrong answer text show when user solve the challenge incorrectly
const WRONG_ANSWER: &str = "wrong answer, try again...";
/// show math challenge text
const SOLVE_MATH_TEXT: &str = "Solve the challenge:";
/// show enter challenge text
const SOLVE_ENTER_TEXT: &str = "Type `Enter` to continue";
/// show yes challenge text
const SOLVE_YES_TEXT: &str = "Type `yes` to continue";
/// show yes challenge text
const DENIED_TEXT: &str = "The command is not allowed.";
/// show to the user how can he cancel the command
const CANCEL_PROMPT_TEXT: &str = "^C to cancel";

/// Show math challenge to the user.
pub fn math_challenge() -> bool {
    let mut rng = rand::thread_rng();
    let num_a = rng.gen_range(0..10);
    let num_b = rng.gen_range(0..10);
    let expected_answer = num_a + num_b;

    eprintln!(
        "{}: {} + {} = ? {}",
        SOLVE_MATH_TEXT,
        num_a,
        num_b,
        get_cancel_string()
    );
    loop {
        let answer = show_stdin_prompt();

        let answer: u32 = match answer.trim().parse() {
            Ok(num) => num,
            Err(_) => continue,
        };
        if answer == expected_answer {
            break;
        }
        eprintln!("{}", WRONG_ANSWER);
    }
    true
}

/// Show enter challenge to the user.
pub fn enter_challenge() -> bool {
    eprintln!("{} {}", SOLVE_ENTER_TEXT, get_cancel_string());
    loop {
        let answer = show_stdin_prompt();
        if answer == "\n" {
            break;
        }
        eprintln!("{}", WRONG_ANSWER);
    }
    true
}

/// Show yes challenge to the user.
pub fn yes_challenge() -> bool {
    eprintln!("{} {}", SOLVE_YES_TEXT, get_cancel_string());
    loop {
        if show_stdin_prompt().trim() == "yes" {
            break;
        }
        eprintln!("{}", WRONG_ANSWER);
    }
    true
}

/// Deny function will loop FOREVER until the user kill the process ^C.
/// it mean that the use command will never executed
pub fn deny() {
    eprintln!("{} type {}", DENIED_TEXT, get_cancel_string());
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

/// Catch user stdin. and return the user type
fn show_stdin_prompt() -> String {
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .expect("Failed to read line");

    answer
}

/// return cancel string with colorize format
fn get_cancel_string() -> String {
    format!("{}", style(CANCEL_PROMPT_TEXT).underlined().bold().italic())
}
