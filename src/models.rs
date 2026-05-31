use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Ecosystem {
    Cargo,
    Go,
    Dart,
    Elixir,
    Npm,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Cargo => "Cargo",
            Ecosystem::Go => "Go",
            Ecosystem::Dart => "Dart",
            Ecosystem::Elixir => "Elixir",
            Ecosystem::Npm => "npm",
        }
    }

    pub fn osv_name(&self) -> &'static str {
        match self {
            Ecosystem::Cargo => "crates.io",
            Ecosystem::Go => "Go",
            Ecosystem::Dart => "Pub",
            Ecosystem::Elixir => "Hex",
            Ecosystem::Npm => "npm",
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
