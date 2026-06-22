use serde::{Deserialize, Serialize};

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
    Homebrew,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PackageOrigin {
    OfficialRepo,
    Aur,
    Unknown,
}

impl PackageOrigin {
    pub fn as_str(&self) -> &'static str {
        match self {
            PackageOrigin::OfficialRepo => "Official Repo",
            PackageOrigin::Aur => "AUR",
            PackageOrigin::Unknown => "Unknown",
        }
    }
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
            Ecosystem::Homebrew => "Homebrew",
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
            Ecosystem::Homebrew => "Homebrew",
        }
    }

    pub fn has_osv_coverage(&self) -> bool {
        matches!(
            self,
            Ecosystem::Cargo
                | Ecosystem::Go
                | Ecosystem::Dart
                | Ecosystem::Elixir
                | Ecosystem::Npm
                | Ecosystem::Php
                | Ecosystem::Ruby
                | Ecosystem::Python
                | Ecosystem::Homebrew
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub current_version: String,
    pub latest_version: String,
    pub ecosystem: Ecosystem,
    pub is_global: bool,
    pub origin: Option<PackageOrigin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityInfo {
    pub id: String,
    pub summary: String,
    pub details: String,
    pub aliases: Vec<String>,
    pub severity: Option<String>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FreshnessInfo {
    VeryRecent(i64),
    Recent(i64),
    Mature(i64),
    Unavailable,
}

impl FreshnessInfo {
    pub fn age_days(&self) -> Option<i64> {
        match self {
            FreshnessInfo::VeryRecent(days)
            | FreshnessInfo::Recent(days)
            | FreshnessInfo::Mature(days) => Some(*days),
            FreshnessInfo::Unavailable => None,
        }
    }

    pub fn is_too_fresh(&self) -> bool {
        matches!(self, FreshnessInfo::VeryRecent(_))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceInfo {
    pub validated_by: Option<String>,
    pub install_date: Option<String>,
    pub pkgbuild_age_days: Option<i64>,
    pub signature_verified: bool,
}
