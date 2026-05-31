pub mod cargo;
pub mod go;
pub mod dart;
pub mod elixir;
pub mod js_ts;
pub mod global;

use std::path::Path;
use crate::models::Dependency;

pub async fn check_all_outdated(dir: &Path) -> Vec<Dependency> {
    let cargo = cargo::CargoAdapter::try_new();
    let go = go::GoAdapter::try_new();
    let dart = dart::DartAdapter::try_new();
    let elixir = elixir::ElixirAdapter::try_new();
    let js_ts = js_ts::JsTsAdapter::try_new();

    let (cargo_res, go_res, dart_res, elixir_res, js_ts_res) = tokio::join!(
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
        }
    );

    let mut all_deps = Vec::new();
    
    if let Ok(deps) = cargo_res { all_deps.extend(deps); }
    if let Ok(deps) = go_res { all_deps.extend(deps); }
    if let Ok(deps) = dart_res { all_deps.extend(deps); }
    if let Ok(deps) = elixir_res { all_deps.extend(deps); }
    if let Ok(deps) = js_ts_res { all_deps.extend(deps); }

    all_deps
}

pub async fn check_global_outdated() -> Vec<Dependency> {
    let global = global::GlobalAdapter::try_new();
    match global {
        Ok(a) => a.check_outdated().await.unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}
