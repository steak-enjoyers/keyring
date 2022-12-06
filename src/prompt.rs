use std::io;

#[cfg(feature = "cli")]
pub(crate) fn input(prompt: impl Into<String>) -> io::Result<String> {
    dialoguer::Input::new()
        .with_prompt(prompt)
        .report(false)
        .interact_text()
}

pub(crate) fn password(prompt: impl Into<String>) -> io::Result<String> {
    dialoguer::Password::new()
        .with_prompt(prompt)
        .report(true)
        .interact()
}
