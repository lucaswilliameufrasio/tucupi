use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Cargo,
    Go,
    Dart,
    Elixir,
    Npm,
    Php,
    Ruby,
    Python,
    Pacman,
    Mise,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Cargo => "Cargo",
            Ecosystem::Go => "Go",
            Ecosystem::Dart => "Dart",
            Ecosystem::Elixir => "Elixir",
            Ecosystem::Npm => "npm",
            Ecosystem::Php => "PHP",
            Ecosystem::Ruby => "Ruby",
            Ecosystem::Python => "Python",
            Ecosystem::Pacman => "Pacman",
            Ecosystem::Mise => "mise",
        }
    }

    pub fn osv_name(&self) -> &'static str {
        match self {
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Dart => "Pub",
            Ecosystem::Elixir => "Hex",
            Ecosystem::Npm => "npm",
            Ecosystem::Php => "Packagist",
            Ecosystem::Ruby => "RubyGems",
            Ecosystem::Python => "PyPI",
            Ecosystem::Pacman => "Arch Linux",
            Ecosystem::Mise => "GitHub Actions",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub current_version: String,
    pub latest_version: String,
    pub ecosystem: Ecosystem,
    pub is_global: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub summary: String,
    pub details: String,
    pub aliases: Vec<String>,
}
