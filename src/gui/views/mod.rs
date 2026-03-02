pub mod overview;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tab {
    Overview,
    Servers,
    Speed,
    Logs,
    Settings,
}

impl Tab {
    pub fn label(&self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Servers => "Servers",
            Tab::Speed => "Speed",
            Tab::Logs => "Logs",
            Tab::Settings => "Settings",
        }
    }

    pub fn all() -> &'static [Tab] {
        &[
            Tab::Overview,
            Tab::Servers,
            Tab::Speed,
            Tab::Logs,
            Tab::Settings,
        ]
    }
}
