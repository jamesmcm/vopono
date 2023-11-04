use vopono_core::config::providers::{
    BoolChoice, ConfigurationChoice, Input, InputNumericu16, Password, UiClient,
};

pub struct CliClient {}

impl UiClient for CliClient {
    /// Launches a dialoguer single select menu for the enum
    fn get_configuration_choice(
        &self,
        config_choice: &dyn ConfigurationChoice,
    ) -> anyhow::Result<usize> {
        let display_names = config_choice.all_names();
        let descriptions = config_choice.all_descriptions();
        let parsed = if let Some(descs) = descriptions {
            display_names
                .iter()
                .zip(descs)
                .map(|x| format!("{}: {}", x.0, x.1))
                .collect::<Vec<String>>()
        } else {
            display_names
        };

        let index = dialoguer::Select::new()
            .with_prompt(config_choice.prompt())
            .items(&parsed)
            // TODO: Is this good enough?
            .default(0)
            .interact()?;
        Ok(index)
    }
    fn get_bool_choice(&self, bool_choice: BoolChoice) -> anyhow::Result<bool> {
        Ok(dialoguer::Confirm::new()
            .with_prompt(&bool_choice.prompt)
            .default(bool_choice.default)
            .interact()?)
    }

    fn get_input(&self, inp: Input) -> anyhow::Result<String> {
        let mut d = dialoguer::Input::<String>::new().with_prompt(&inp.prompt);

        if inp.validator.is_some() {
            d = d.validate_with(inp.validator.unwrap());
        };

        Ok(d.interact()?)
    }

    fn get_input_numeric_u16(&self, inp: InputNumericu16) -> anyhow::Result<u16> {
        let mut d = dialoguer::Input::<u16>::new().with_prompt(&inp.prompt);

        if inp.default.is_some() {
            d = d.default(inp.default.unwrap());
        }
        if inp.validator.is_some() {
            d = d.validate_with(inp.validator.unwrap());
        }

        Ok(d.interact()?)
    }

    fn get_password(&self, pw: Password) -> anyhow::Result<String> {
        let mut req = dialoguer::Password::new();
        if pw.confirm {
            req = req.with_confirmation("Confirm password", "Passwords did not match");
        };
        req = req.with_prompt(pw.prompt);
        Ok(req.interact()?)
    }
}
