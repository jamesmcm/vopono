use strum::IntoEnumIterator;

/// Find the position of an enum's `#[default]` variant in its iteration order.
///
/// Use this for a `ConfigurationChoice` whose default variant is not the first
/// variant, so changing either the declaration order or `#[default]` cannot
/// leave a hard-coded index stale.
pub(crate) fn enum_default_index<T>() -> usize
where
    T: Default + PartialEq + IntoEnumIterator,
{
    let default = T::default();
    T::iter()
        .position(|variant| variant == default)
        .expect("enum iteration must include its default variant")
}

/// Implement this trait for enums used as configuration choices e.g. when deciding which set of
/// config files to generate
pub trait ConfigurationChoice {
    /// Prompt string for the selector (automatically terminates in ':')
    fn prompt(&self) -> String;

    /// Descriptions are a user-friendly descriptions for each enum variant
    fn description(&self) -> Option<String>;

    /// Descriptions are a user-friendly descriptions for each enum variant
    fn all_descriptions(&self) -> Option<Vec<String>>;

    /// Get all enum variant names (this order will be used for other methods)
    fn all_names(&self) -> Vec<String>;

    /// Index of the default option within `all_names()`. Used as the preselected
    /// entry in interactive menus.
    fn default_index(&self) -> usize {
        0
    }
}
// TODO: FromStr, ToString

pub struct BoolChoice {
    pub prompt: String,
    pub default: bool,
}

#[allow(clippy::type_complexity)]
/// Only supports strings
pub struct Input {
    pub prompt: String,
    pub validator: Option<Box<dyn Fn(&String) -> core::result::Result<(), String>>>,
}

#[allow(clippy::type_complexity)]
/// Only supports u16 input - so UI Client can allow numbers only
pub struct InputNumericu16 {
    pub prompt: String,
    pub validator: Option<Box<dyn Fn(&u16) -> core::result::Result<(), String>>>,
    pub default: Option<u16>,
}

pub struct Password {
    pub prompt: String,
    pub confirm: bool,
}

/// Trait to be implemented by a struct wrapping the user-facing client code
/// e.g. separate implementations for CLI, TUI, GUI, etc.
/// For GUI and TUI may want to override `process_choices()` to get the responses in a batch
pub trait UiClient {
    /// Returns index of chosen element from ConfigurationChoice - this can then be used with concrete enum::variants() for concrete variant
    fn get_configuration_choice(
        &self,
        conf_choice: &dyn ConfigurationChoice,
    ) -> anyhow::Result<usize>;
    fn get_bool_choice(&self, bool_choice: BoolChoice) -> anyhow::Result<bool>;
    fn get_input(&self, input: Input) -> anyhow::Result<String>;
    fn get_input_numeric_u16(&self, input: InputNumericu16) -> anyhow::Result<u16>;
    fn get_password(&self, password: Password) -> anyhow::Result<String>;
}
