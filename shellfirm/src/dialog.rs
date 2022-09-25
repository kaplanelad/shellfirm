use anyhow::{anyhow, Result};
use requestty::{DefaultSeparator, Question};

// prepare multi choice ignores data
//
/// # Errors
pub fn multi_choice(
    message: &str,
    choices: Vec<String>,
    selected: Vec<String>,
    page_size: usize,
) -> Result<Vec<String>> {
    let choices = {
        let mut choices = choices.clone();
        choices.retain(|x| !selected.contains(x));
        choices
    };
    let mut question = requestty::Question::multi_select("multi")
        .message(message)
        .choices(choices)
        .page_size(page_size);

    for s in selected {
        question = question.choice_with_default(s.to_string(), true);
    }

    let answer = requestty::prompt_one(question.build())?;

    match answer.as_list_items() {
        Some(list) => Ok(list.iter().map(|s| s.text.to_string()).collect::<Vec<_>>()),
        None => Err(anyhow!("could not get selected list")),
    }
}

/// prompt select option
///
/// # Errors
///
/// Will return `Err` when interact error
pub fn reset_config() -> Result<usize> {
    let answer = requestty::prompt_one(
        Question::raw_select("reset")
            .message("Rest configuration will reset all checks settings. Select how to continue...")
            .choices(vec![
                "Yes, i want to override the current configuration".into(),
                "Override and backup the existing file".into(),
                DefaultSeparator,
                "Cancel Or ^C".into(),
            ])
            .build(),
    )?;
    match answer.as_list_item() {
        Some(a) => Ok(a.index),
        _ => Err(anyhow!("select option is empty")),
    }
}
