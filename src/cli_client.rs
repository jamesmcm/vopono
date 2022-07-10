use vopono_core::config::providers::UiClient;

pub struct CliClient {}

impl UiClient for CliClient {
    /// Launches a dialoguer single select menu for the enum
    fn get_configuration_choice<T: ConfigurationChoice>() -> anyhow::Result<T> {
        let mut variants = config_choice::variants();
        let display_names = variants.iter().map(|x| x.to_string());
        let descriptions = variants.iter().map(|x| x.description());
        let index = dialoguer::Select::new()
            .with_prompt(config_choice::prompt())
            .items(
                display_names
                    .zip(descriptions)
                    .map(|x| {
                        if x.1.is_some() {
                            format!("{}: {}", x.0, x.1.unwrap())
                        } else {
                            x.0
                        }
                    })
                    .collect::<Vec<String>>()
                    .as_slice(),
            )
            .default(
                variants
                    .iter()
                    .position(|x| *x == config_choice::default())
                    .unwrap(),
            )
            .interact()?;
        Ok(variants.remove(index))
    }
    fn get_bool_choice(bool_choice: &BoolChoice) -> anyhow::Result<bool> {
        dialoguer::Confirm::new()
            .with_prompt(&bool_choice.prompt)
            .default(bool_choice.default)
            .interact()
    }

    fn get_input(inp: &Input) -> anyhow::Result<String> {
        dialoguer::Input::<String>::new()
            .with_prompt(&inp.prompt)
            .validate_with(inp.validator)
    }
    fn get_password(pw: &Password) -> anyhow::Result<String> {
        let req = dialoguer::Password::new().with_prompt(pw.prompt);
        let req = if pw.confirm {
            req.with_confirmation("Confirm password", "Passwords did not match")
        } else {
            req
        };
        req.interact()?;
    }
}
