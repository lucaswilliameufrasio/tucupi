pub mod cargo;
pub mod dart;
pub mod elixir;
pub mod global;
pub mod go;
pub mod homebrew;
pub mod js_ts;
pub mod mise;
pub mod pacman;
pub mod php;
pub mod python;
pub mod ruby;

use crate::models::Dependency;
use std::path::Path;

pub async fn check_all_outdated(dir: &Path) -> Vec<Dependency> {
    let cargo = cargo::CargoAdapter::try_new();
    let go = go::GoAdapter::try_new();
    let dart = dart::DartAdapter::try_new();
    let elixir = elixir::ElixirAdapter::try_new();
    let js_ts = js_ts::JsTsAdapter::try_new();
    let php = php::PhpAdapter::try_new();
    let ruby = ruby::RubyAdapter::try_new();
    let python = python::PythonAdapter::try_new();

    let (cargo_res, go_res, dart_res, elixir_res, js_ts_res, php_res, ruby_res, python_res) = tokio::join!(
        async {
            match cargo {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        },
        async {
            match go {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        },
        async {
            match dart {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        },
        async {
            match elixir {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        },
        async {
            match js_ts {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        },
        async {
            match php {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        },
        async {
            match ruby {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        },
        async {
            match python {
                Ok(ref a) => a.check_outdated(dir).await,
                Err(_) => Ok(Vec::new()),
            }
        }
    );

    let mut all_deps = Vec::new();

    if let Ok(deps) = cargo_res {
        all_deps.extend(deps);
    }
    if let Ok(deps) = go_res {
        all_deps.extend(deps);
    }
    if let Ok(deps) = dart_res {
        all_deps.extend(deps);
    }
    if let Ok(deps) = elixir_res {
        all_deps.extend(deps);
    }
    if let Ok(deps) = js_ts_res {
        all_deps.extend(deps);
    }
    if let Ok(deps) = php_res {
        all_deps.extend(deps);
    }
    if let Ok(deps) = ruby_res {
        all_deps.extend(deps);
    }
    if let Ok(deps) = python_res {
        all_deps.extend(deps);
    }

    all_deps
}

pub async fn check_global_outdated() -> Vec<Dependency> {
    let global = global::GlobalAdapter::try_new();
    let pacman = pacman::PacmanAdapter::try_new();
    let mise = mise::MiseAdapter::try_new();
    let homebrew = homebrew::HomebrewAdapter::try_new();

    let (global_res, pacman_res, mise_res, homebrew_res) = tokio::join!(
        async {
            match global {
                Ok(ref adapter) => adapter.check_outdated().await.unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        },
        async {
            match pacman {
                Ok(ref adapter) => adapter
                    .check_outdated(&std::path::PathBuf::from("/"))
                    .await
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        },
        async {
            match mise {
                Ok(ref adapter) => adapter
                    .check_outdated(&std::path::PathBuf::from("/"))
                    .await
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        },
        async {
            match homebrew {
                Ok(ref adapter) => adapter
                    .check_outdated(&std::path::PathBuf::from("/"))
                    .await
                    .unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        }
    );

    let mut all_deps = Vec::new();
    all_deps.extend(global_res);
    all_deps.extend(pacman_res);
    all_deps.extend(mise_res);
    all_deps.extend(homebrew_res);
    all_deps
}
