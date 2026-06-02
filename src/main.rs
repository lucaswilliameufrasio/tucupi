pub mod models;
pub mod config;
pub mod security;
pub mod adapters;
pub mod app;
pub mod ui;
pub mod batch;
pub mod i18n;

use app::{App, Modal};
use std::io;
use std::path::PathBuf;
use std::time::Duration;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Parse Arguments
    let args: Vec<String> = std::env::args().collect();
    let mut target_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut boot_global = false;
    let mut interactive = false;

    for arg in &args[1..] {
        if arg == "--help" || arg == "-h" {
            println!("🍵 TUCUPI");
            println!();
            println!("USAGE:");
            println!("  tucupi [options] [directory]");
            println!();
            println!("OPTIONS:");
            println!("  -g, --global        Start on the Global Packages tab");
            println!("  -i, --interactive   Open interactive batch mode (npm-check style)");
            println!("  -h, --help          Show this help message");
            println!();
            println!("  directory           Target project directory (default: current dir)");
            println!();
            println!("EXAMPLES:");
            println!("  tucupi              Scan current directory and open TUI");
            println!("  tucupi -g           Open TUI on Global tab");
            println!("  tucupi -i           Interactive batch mode");
            println!("  tucupi /path/to/proj Scan a specific project");
            println!("  tucupi -i /path     Interactive mode in a specific directory");
            return Ok(());
        } else if arg == "--global" || arg == "-g" {
            boot_global = true;
        } else if arg == "--interactive" || arg == "-i" {
            interactive = true;
        } else if !arg.starts_with('-') {
            target_dir = PathBuf::from(arg);
        }
    }

    // Convert target_dir to absolute path for safety
    if let Ok(abs) = std::fs::canonicalize(&target_dir) {
        target_dir = abs;
    }

    // Route to interactive batch mode if requested
    if interactive {
        return batch::run(target_dir, boot_global).await;
    }

    // 2. Set up Panic Hook to restore terminal state
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(panic_info);
    }));

    // 3. Initialize Terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 4. Initialize App
    let mut app = App::new(target_dir, boot_global);
    app.load_config_sync().await; // Load local tucupi.toml sync at startup
    app.trigger_scan();          // Run initial dependency checks in background

    // 5. TUI Loop
    loop {
        terminal.draw(|f| ui::render(f, &mut app))?;

        // Poll background async events
        while let Ok(event) = app.event_rx.try_recv() {
            app.handle_event(event);
        }

        // Poll UI events (50ms timeout)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match &app.modal {
                        Modal::ConfirmForce(_, _) => match key.code {
                            KeyCode::Enter => {
                                app.trigger_upgrade_selected(true);
                            }
                            KeyCode::Esc => {
                                app.modal = Modal::None;
                            }
                            _ => {}
                        },
                        Modal::Blocked(_, _) => match key.code {
                            KeyCode::Enter | KeyCode::Esc => {
                                app.modal = Modal::None;
                            }
                            _ => {}
                        },
                        Modal::None => match key.code {
                            KeyCode::Char('q') => break,
                            KeyCode::Up => app.scroll_up(),
                            KeyCode::Down => app.scroll_down(),
                            KeyCode::Tab => app.switch_tab(),
                            KeyCode::Char('r') => app.trigger_scan(),
                            KeyCode::Char('u') => app.trigger_upgrade_selected(false),
                            KeyCode::Char('f') => app.trigger_upgrade_selected(true),
                            KeyCode::Char('c') => app.check_security_selected(),
                            _ => {}
                        },
                    }
                }
            }
        }
    }

    // 6. Restore Terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}
