// TODO: Use specific interface names

#[derive(Clone, Copy)]
pub enum NetworkInterface {
    Ethernet,
    WiFi,
}

impl NetworkInterface {
    pub fn wildcard(&self) -> String {
        match self {
            Self::Ethernet => String::from("e+"),
            Self::WiFi => String::from("w+"),
        }
    }
}
