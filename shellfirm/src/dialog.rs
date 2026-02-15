use anyhow::{bail, Result};
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
        let mut choices = choices;
        choices.retain(|x| !selected.contains(x));
        choices
    };
    let mut question = requestty::Question::multi_select("multi")
        .message(message)
        .choices(choices)
        .page_size(page_size);

    for s in selected {
        question = question.choice_with_default(s.clone(), true);
    }

    let answer = requestty::prompt_one(question.build())?;

    answer.as_list_items().map_or_else(
        || bail!("could not get selected list"),
        |list| Ok(list.iter().map(|s| s.text.clone()).collect::<Vec<_>>()),
    )
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
        _ => bail!("select option is empty"),
    }
}

/// prompt select option
///
/// # Errors
///
/// Will return `Err` when interact error
pub fn select(message: &str, items: &[String]) -> Result<String> {
    let questions = Question::select("select")
        .message(message)
        .choices(items)
        .build();

    let answer = requestty::prompt_one(questions)?;
    match answer.as_list_item() {
        Some(a) => Ok(a.text.clone()),
        _ => bail!("select option is empty"),
    }
}
