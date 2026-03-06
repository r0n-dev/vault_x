use crate::vault_logic;
use crate::config::{
    VaultConfig,
    KEY_SIZE,
    SALT_SIZE,
    NONCE_SIZE,
    CONFIG_FILE,
    VAULT_FILE,
    AUTO_LOCK_TIMEOUT_MINUTES,
    CLIPBOARD_TIMEOUT_SECONDS,
};
use crate::crypto::{self, PasswordOptions, generate_and_save_keyfile, DEFAULT_KEYFILE_SIZE_BYTES};
use crate::errors::VaultError;
use arboard::Clipboard;
use colored::*;
use crossterm::{
    cursor, execute,
    terminal::{Clear, ClearType},
};
use rust_i18n::t;
use rpassword::read_password;
use std::{
    io::{self, BufRead, Write},
    sync::{Arc, Mutex, RwLock},
    thread,
    thread::sleep,
    time::Duration,
};
use zeroize::Zeroizing;
use zxcvbn::zxcvbn;
use zxcvbn::feedback::{Feedback, Suggestion, Warning};
use prettytable::{Table, Row, Cell, Attr, format::consts::FORMAT_BOX_CHARS};
use crate::models::{Vault, AppState};
use std::path::PathBuf;
use std::fs;
use rand::seq::SliceRandom;
use rand::Rng;
use crate::config;

pub fn clear_screen() -> io::Result<()> {
    execute!(io::stdout(), Clear(ClearType::All), cursor::MoveTo(0, 0))
}

pub fn wait_for_enter() -> io::Result<()> {
    println!("\n{}", t!("prompts.press_enter").dimmed());
    let _ = io::stdin().read_line(&mut String::new());
    Ok(())
}

#[derive(Debug)]
enum CipherType {
    Caesar,
    Atbash,
    Reverse,
}


pub fn prompt_single_password(prompt_message: &str) -> Result<Zeroizing<String>, VaultError> {
    println!("{}", prompt_message.bold().cyan());
    print!("{}", "[*] ".dimmed());
    io::stdout().flush()?;
    let password_result = read_password();
    match password_result {
        Ok(pw) => {
            let password = Zeroizing::new(pw);
            if password.trim().is_empty() {
                log::warn!("{}", t!("log.empty_password_entered"));
                Err(VaultError::InvalidData(t!("errors.password_cannot_be_empty")))
            } else {
                Ok(password)
            }
        }
        Err(e) => {
            log::warn!("{} {}", t!("log.password_read_error"), e);
             Err(VaultError::PasswordReadFailed(e))
        }
    }
}

fn display_strength_feedback(password: &Zeroizing<String>, estimate: &zxcvbn::Entropy) -> Result<(), VaultError> {
    let score = estimate.score();
    let guesses = estimate.guesses();
    let strength_label = match score {
        0 => t!("strength.very_weak").red().bold(),
        1 => t!("strength.weak").red().bold(),
        2 => t!("strength.medium").yellow().bold(),
        3 => t!("strength.strong").green().bold(),
        4 => t!("strength.very_strong").purple().bold(),
        _ => t!("strength.unknown").dimmed(),
    };

    println!(
        "{}",
        format!(
            "\n{} {} (~ {:.1e} {})",
            t!("cli.strength_check_prefix"),
            strength_label,
            guesses,
            t!("cli.strength_check_suffix")
        )
    );

    let mut tips: Vec<String> = Vec::new();
     match score {
         0 | 1 => {
             tips.push(t!("strength.tips_title_weak").bold().to_string());
             if password.len() < 12 { tips.push(format!("  🔹 {}", t!("strength.tip_make_longer"))); }
             tips.push(format!("  🔹 {}", t!("strength.tip_mix_chars")));
             tips.push(format!("  🔹 {}", t!("strength.tip_avoid_patterns")));
         }
         2 => {
             tips.push(t!("strength.tips_title_medium").bold().to_string());
             tips.push(format!("  🔸 {}", t!("strength.tip_make_even_longer")));
             tips.push(format!("  🔸 {}", t!("strength.tip_use_more_random")));
         }
         _ => {}
     }

    let feedback_ref_opt: &Option<Feedback> = estimate.feedback();
    if let Some(feedback_ref) = feedback_ref_opt {
         let warning_opt: Option<Warning> = feedback_ref.warning();
         let suggestions: &[Suggestion] = feedback_ref.suggestions();
         if let Some(warning) = warning_opt.as_ref() {
             let warning_text = format!("{:?}", warning);
             tips.push(format!("  ❗ {}: {}", t!("strength.warning_prefix").yellow(), warning_text.yellow()));
         }
         for suggestion in suggestions {
             let suggestion_text = format!("{:?}", suggestion);
             tips.push(format!("  💡 {}: {}", t!("strength.suggestion_prefix").green(), suggestion_text.green()));
         }
     }

    if !tips.is_empty() {
        println!("{}", tips.join("\n"));
    }
    println!();
    Ok(())
}

pub fn prompt_new_password_with_confirmation(
    prompt_message: &str,
    confirm_message: &str,
    require_strength_score: Option<u8>,
) -> Result<Zeroizing<String>, VaultError> {
    loop {
        let password = prompt_single_password(prompt_message)?;
        let password_confirm = prompt_single_password(confirm_message)?;

        if password == password_confirm {
            if let Some(required_score) = require_strength_score {
                 let estimate = zxcvbn(password.as_str(), &[]).map_err(|e| VaultError::ZxcvbnError(t!("errors.zxcvbn_internal_error", error = e.to_string())))?;
                 let score = estimate.score();

                display_strength_feedback(&password, &estimate)?;

                if score >= required_score {
                    log::info!("{}", t!("log.new_password_confirmed_ok", score = score, required = required_score));
                    println!("{}", t!("messages.password_strength_ok").green());
                    return Ok(password);
                } else {
                    log::warn!("{}", t!("log.password_too_weak", score = score, required = required_score));
                    println!("{}", t!("messages.password_too_weak", required = required_score).red().bold());
                }
            } else {
                log::info!("{}", t!("log.new_password_confirmed_no_check"));
                return Ok(password);
            }
        } else {
            log::warn!("{}", t!("log.password_confirmation_failed"));
            println!("{}", t!("messages.passwords_dont_match").red());
        }
        println!("{}", t!("messages.please_try_again").yellow());
        wait_for_enter()?;
        clear_screen()?;
    }
}


pub fn prompt_new_master_password() -> Result<Zeroizing<String>, VaultError> {
    prompt_new_password_with_confirmation(
        &t!("prompts.new_master_pw"),
        &t!("prompts.confirm_master_pw"),
        Some(2),
    )
}

fn prompt_new_password_for_export() -> Result<Zeroizing<String>, VaultError> {
    prompt_new_password_with_confirmation(
        &t!("prompts.export_pw_set"),
        &t!("prompts.export_pw_confirm"),
        None,
    )
}


pub fn prompt_non_empty(prompt_text: &str) -> Result<String, VaultError> {
    loop {
        print!("{} ", prompt_text);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        } else {
            println!("{}", t!("errors.input_cannot_be_empty").red());
        }
    }
}

pub fn prompt_optional(prompt_text: &str) -> Result<Option<String>, VaultError> {
    print!("{} ", prompt_text);
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed.to_string()))
    }
}

pub fn prompt_numeric(prompt_text: &str, min: usize, max: usize, default: Option<usize>) -> Result<usize, VaultError> {
    loop {
        let default_str = default.map_or("".to_string(), |d| format!(" [{}]", d));
        print!("{}{} ({} - {}): ", prompt_text, default_str, min, max);
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();

        if trimmed.is_empty() && default.is_some() {
            return Ok(default.unwrap());
        }

        match trimmed.parse::<usize>() {
            Ok(num) if num >= min && num <= max => return Ok(num),
            Ok(_) => println!("{}", t!("errors.number_out_of_range", min = min, max = max).red()),
            Err(_) => println!("{}", t!("errors.invalid_number_input").red()),
        }
    }
}

pub fn prompt_yes_no(prompt_text: &str, default: Option<bool>) -> Result<bool, VaultError> {
    loop {
        let default_display_char = default.map(|d_val| {
            if d_val {
                t!("common.yes_short", default="j").trim().to_lowercase()
            } else {
                t!("common.no_short", default="n").trim().to_lowercase()
            }
        });
        let default_str = default_display_char
            .as_deref()
            .map_or("".to_string(), |c| format!(" [{}]", c));

        let yes_no_display_options = t!("common.yes_no_short", default="j/n").trim().to_string();

        print!("{}{} ({}): ", prompt_text, default_str, yes_no_display_options);
        io::stdout().flush()?;

        let mut input_str = String::new();
        io::stdin().read_line(&mut input_str)?;
        let trimmed_input = input_str.trim().to_lowercase();

        if trimmed_input.is_empty() {
            if let Some(default_val) = default {
                return Ok(default_val);
            } else {
                println!("{}", t!("errors.input_cannot_be_empty_for_choice", choice_options = yes_no_display_options).red());
                continue;
            }
        }

        let yes_short_cmp = t!("common.yes_short", default="j").trim().to_lowercase();
        let yes_long_cmp = t!("common.yes_long", default="ja").trim().to_lowercase();
        let no_short_cmp = t!("common.no_short", default="n").trim().to_lowercase();
        let no_long_cmp = t!("common.no_long", default="nein").trim().to_lowercase();

        if trimmed_input == yes_short_cmp || trimmed_input == yes_long_cmp {
            return Ok(true);
        }
        if trimmed_input == no_short_cmp || trimmed_input == no_long_cmp {
            return Ok(false);
        }
        println!("{}", t!("errors.invalid_input_yes_no_generic").red());
    }
}

pub fn copy_to_clipboard(text_to_copy: &str) -> Result<(), VaultError> {
    log::debug!("{}", t!("log.clipboard_attempt", len = text_to_copy.len()));

    let clipboard_mutex = Arc::new(Mutex::new(Clipboard::new().map_err(|e| {
         VaultError::ClipboardError(t!("errors.clipboard_init_failed", error = e.to_string()))
    })?));

    let clipboard_main = Arc::clone(&clipboard_mutex);
    let clipboard_timeout = Arc::clone(&clipboard_mutex);
    let text_data = text_to_copy.to_string();

    {
        let mut clipboard = clipboard_main.lock().map_err(|_| {
             VaultError::ClipboardError(t!("errors.clipboard_mutex_poisoned_write"))
         })?;
        clipboard.set_text(text_data.clone()).map_err(|e| {
             VaultError::ClipboardError(t!("errors.clipboard_write_failed", error = e.to_string()))
        })?;
    }

    log::info!("{}", t!("log.clipboard_copy_success"));
    println!("{}", t!("messages.clipboard_copy", seconds = CLIPBOARD_TIMEOUT_SECONDS).green());

    thread::spawn(move || {
        log::debug!("{}", t!("log.clipboard_timeout_thread_start", seconds = CLIPBOARD_TIMEOUT_SECONDS));
        sleep(Duration::from_secs(CLIPBOARD_TIMEOUT_SECONDS));
        match clipboard_timeout.lock() {
            Ok(mut clipboard) => {
                log::debug!("{}", t!("log.clipboard_timeout_clearing"));
                 match clipboard.get_text() {
                     Ok(current_content) if current_content == text_data => {
                         if let Err(e) = clipboard.clear() {
                             log::warn!("{} {}", t!("log.clipboard_clear_failed"), e.to_string());
                         } else {
                             log::info!("{}", t!("log.clipboard_cleared"));
                         }
                     }
                     Ok(_) => {
                         log::info!("{}", t!("log.clipboard_content_changed_skip_clear"));
                     }
                     Err(e) => {
                         log::warn!("{} {}", t!("log.clipboard_read_before_clear_failed"), e.to_string());
                     }
                 }
            }
            Err(_) => {
                 let error_msg = t!("errors.clipboard_mutex_poisoned_clear");
                log::error!("{}", error_msg);
            }
        }
    });

    Ok(())
}


pub fn show_menu() {
    let logo = r#"
 ██▒   █▓ ▄▄▄       █    ██  ██▓  ▄▄▄█████▓   ▒██   ██▒
▓██░   █▒▒████▄     ██  ▓██▒▓██▒  ▓  ██▒ ▓▒   ▒▒ █ █ ▒░
 ▓██  █▒░▒██  ▀█▄  ▓██  ▒██░▒██░  ▒ ▓██░ ▒░   ░░  █   ░
  ▒██ █░░░██▄▄▄▄██ ▓▓█  ░██░▒██░  ░ ▓██▓ ░     ░ █ █ ▒
   ▒▀█░   ▓█   ▓██▒▒▒█████▓ ░██████▒▒██▒ ░    ▒██▒ ▒██▒
   ░ ▐░   ▒▒   ▓▒█░░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒ ░░      ▒▒ ░ ░▓ ░
   ░ ░░    ▒   ▒▒ ░░░▒░ ░ ░ ░ ░ ▒  ░  ░       ░░   ░▒ ░
     ░░    ░   ▒    ░░░ ░ ░   ░ ░   ░          ░    ░
      ░        ░  ░   ░         ░  ░           ░    ░
     ░
"#
    .bright_cyan();
    println!("{}", logo);
    println!(
        "{}",
        t!("messages.welcome", version = crate::VERSION).bold().yellow()
    );
 println!("{}", "==========================================".dimmed());

    println!("\n  {} {}", "🔑".blue(), t!("menu.section_passwords").bold());
    println!("  {} {}", "[1]".bold().green(), t!("menu.add_pw"));
    println!("  {} {}", "[2]".bold().blue(), t!("menu.find_pw"));
    println!("  {} {}", "[3]".bold().cyan(), t!("menu.view_pw"));
    println!("  {} {}", "[4]".bold().red(), t!("menu.del_pw"));
    println!("  {} {}", "[E]".bold().yellow(), t!("menu.edit_pw"));
    println!("{}", "------------------------------------------".dimmed());

    println!("\n  {} {}", "📝".blue(), t!("menu.section_notes").bold());
    println!("  {} {}", "[5]".bold().green(), t!("menu.add_note"));
    println!("  {} {}", "[6]".bold().blue(), t!("menu.all_notes"));
    println!("  {} {}", "[7]".bold().red(), t!("menu.del_note"));
    println!("  {} {}", "[K]".bold().yellow(), t!("menu.edit_note"));
    println!("{}", "------------------------------------------".dimmed());

    println!("\n  {} {}", "📦".blue(), t!("menu.section_export_import").bold());
    println!("  {} {}", "[X]".bold().yellow(), t!("menu.export_vault"));
    println!("  {} {}", "[I]".bold().yellow(), t!("menu.import_vault"));
    println!("{}", "------------------------------------------".dimmed());

    println!("\n  {} {}", "🛡️".blue(), t!("menu.section_vault_management").bold());
    println!("  {} {}", "[L]".bold().magenta(), t!("menu.lock_vault"));
    println!("  {} {}", "[U]".bold().green(), t!("menu.unlock_vault"));
    println!("  {} {}", "[G]".bold().purple(), t!("menu.generate_password"));
    println!("  {} {}", "[16]".bold().green(), t! ("check_password_strength_standalone"));
    println!("  {} {}", "[O]".bold().cyan(), t!("menu.view_config_details"));
    println!("  {} {}", "[A]".bold().cyan(), t!("menu.manage_autolock"));
    println!("{}", "------------------------------------------".dimmed());


    println!("\n  {} {}", "ℹ️".blue(), t!("menu.section_info").bold());
    println!("  {} {}", "[8]".bold().purple(), t!("menu.about"));
    println!("  {} {}", "[9]".bold().red(), t!("menu.exit").bold());
    println!("{}", "==========================================".dimmed());

    print!("\n{} ", t!("menu.prompt").bold().blue());
    io::stdout().flush().unwrap_or_default();
}


pub fn show_about(config: &VaultConfig) {
    clear_screen().ok();
    let logo = r#"
 ██▒   █▓ ▄▄▄       █    ██  ██▓  ▄▄▄█████▓   ▒██   ██▒
▓██░   █▒▒████▄     ██  ▓██▒▓██▒  ▓  ██▒ ▓▒   ▒▒ █ █ ▒░
 ▓██  █▒░▒██  ▀█▄  ▓██  ▒██░▒██░  ▒ ▓██░ ▒░   ░░  █   ░
  ▒██ █░░░██▄▄▄▄██ ▓▓█  ░██░▒██░  ░ ▓██▓ ░     ░ █ █ ▒
   ▒▀█░   ▓█   ▓██▒▒▒█████▓ ░██████▒▒██▒ ░    ▒██▒ ▒██▒
   ░ ▐░   ▒▒   ▓▒█░░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒ ░░      ▒▒ ░ ░▓ ░
   ░ ░░    ▒   ▒▒ ░░░▒░ ░ ░ ░ ░ ▒  ░  ░       ░░   ░▒ ░
     ░░    ░   ▒    ░░░ ░ ░   ░ ░   ░          ░    ░
      ░        ░  ░   ░         ░  ░           ░    ░
     ░
"#
    .cyan().bold();

    let separator = "═".repeat(70).dimmed();

    println!("{}", logo);
    println!("{}", separator);
    println!(
        "{} {}",
        "🛡️ VaultX".bold().yellow(),
        format!("v{}", crate::VERSION).dimmed()
    );
    println!("{}", t!("about.tagline").italic().cyan());
    println!("{}", separator);

    println!("\n{}", "🔒 Sicherheit im Detail".bold().magenta());
    println!("{}", "-".repeat(30).dimmed());
    println!(
        "  {:<25} {}",
        t!("about.encryption_label").yellow(),
        format!("{} ({}-bit)", "AES-GCM".green(), KEY_SIZE * 8)
    );
    println!(
        "  {:<25} {}",
        t!("about.kdf_label").yellow(),
        config.kdf_algorithm.green()
    );
    println!(
        "    {:<23} {}", "└─ M_COST:".dimmed(),
        format!("{} ({} MiB)", config.m_cost, config.m_cost / 1024).cyan()
    );
    println!(
        "    {:<23} {}", "└─ T_COST:".dimmed(),
        config.t_cost.to_string().cyan()
    );
     println!(
        "    {:<23} {}", "└─ P_COST:".dimmed(),
        config.p_cost.to_string().cyan()
    );
    println!(
        "  {:<25} {}",
        t!("about.salt_label").yellow(),
        format!("{} {}-bit ({})", t!("about.salt_desc_type"), SALT_SIZE * 8, t!("about.salt_info")).green()
    );
     println!(
        "  {:<25} {}",
        t!("about.nonce_label").yellow(),
        format!("{} {}-bit ({})", "AES-GCM Nonce".green(), NONCE_SIZE * 8, t!("about.nonce_info"))
    );

    println!("\n{}", "⚙️ Aktuelle Konfiguration".bold().magenta());
    println!("{}", "-".repeat(30).dimmed());
    println!(
        "  {:<25} {}",
        t!("about.config_file_label").yellow(),
        CONFIG_FILE.cyan()
    );
    println!(
        "  {:<25} {}",
        t!("about.vault_file_label").yellow(),
        VAULT_FILE.cyan()
    );
    println!(
        "  {:<25} {}",
        t!("about.keyfile_label").yellow(),
        match &config.keyfile_path {
            Some(path) => format!("{} ({})", t!("common.active").green(), path.dimmed()),
            None => t!("common.inactive").dimmed().to_string(),
        }
    );
     println!(
        "  {:<25} {}",
        t!("about.autolock_label").yellow(),
        format!("{} {} {}", t!("common.active").green(), config.auto_lock_timeout_minutes.unwrap_or(AUTO_LOCK_TIMEOUT_MINUTES), t!("unit.minutes")).cyan()
    );
     println!(
        "  {:<25} {}",
        t!("about.clipboard_label").yellow(),
        format!("{} {} {}", t!("common.active").green(), CLIPBOARD_TIMEOUT_SECONDS, t!("unit.seconds")).cyan()
    );
     println!(
        "  {:<25} {}",
        t!("about.language_label").yellow(),
        config.language.as_deref().unwrap_or("n/a").cyan()
    );
    println!(
        "  {:<25} {}",
        t!("about.password_symbols_label").yellow(),
        match &config.password_generator_symbols {
            Some(symbols) if !symbols.is_empty() => t!("common.custom").cyan().to_string(),
            _ => t!("common.default").dimmed().to_string(),
        }
    );
    if config.password_generator_symbols.as_ref().map_or(false, |s| !s.is_empty()) {
         println!("    {:<23} {}", "└─ Hinweis:".dimmed(), t!("about.symbols_custom_info", config=CONFIG_FILE).dimmed());
    }

    println!("\n{}", "✨ Features".bold().magenta());
    println!("{}", "-".repeat(30).dimmed());
    let features = vec![
        format!("✅ {}", t!("about.feature_manager")),
        format!("📝 {}", t!("about.feature_notes")),
        format!("✏️ {}", t!("about.feature_edit")),
        format!("🔍 {}", t!("about.feature_search")),
        format!("🎲 {}", t!("about.feature_generator_custom")),
        format!("💪 {}", t!("about.feature_strength")),
        format!("✂️ {}", t!("about.feature_clipboard")),
        format!("📦 {}", t!("about.feature_export_safe")),
        format!("📤 {}", t!("about.feature_export_unsafe")),
        format!("⏳ {}", t!("about.feature_autolock")),
        format!("🌐 {}", t!("about.feature_i18n")),
    ];
    let mid = (features.len() + 1) / 2;
    for i in 0..mid {
        let left = features[i].clone();
        let right = if i + mid < features.len() { features[i + mid].clone() } else { "".to_string() };
        println!("  {:<35} {}", left, right);
    }

    println!("\n{}", "🌍 Entwickler & Open Source".bold().magenta());
    println!("{}", "-".repeat(30).dimmed());
    println!("  {:<25} {}", t!("about.author_label").yellow(), t!("about.author_name").cyan());
    println!("  {:<25} {}", t!("about.license_label").yellow(), t!("about.license_type").cyan());
    println!("  {:<25} {}", t!("about.repository_label").yellow(), t!("about.repository_url").cyan().underline());

    println!("\n{}", "⚠️ Wichtige Hinweise".bold().red());
    println!("{}", "-".repeat(30).dimmed());
    println!("  ❗ {}", t!("about.warning_password").red());
    if config.keyfile_path.is_some() {
        println!("  ❗ {}", t!("about.warning_keyfile_loss").red());
    }
    println!("  ❗ {}", t!("about.warning_backup").yellow());
    println!("\n{}", separator);
    wait_for_enter().ok();
}

pub fn show_config_details_cli(config: &VaultConfig) {
    clear_screen().ok();
    println!("{}\n", t!("messages.config_details_title").bold().yellow());

    let mut table = Table::new();
    table.set_format(*FORMAT_BOX_CHARS);
    table.add_row(Row::new(vec![
        Cell::new(&t!("common.setting")).with_style(Attr::Bold),
        Cell::new(&t!("common.value")).with_style(Attr::Bold),
    ]));

    table.add_row(Row::new(vec![
        Cell::new(&t!("about.config_file_label")),
        Cell::new(CONFIG_FILE).style_spec("c"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new(&t!("about.vault_file_label")),
        Cell::new(VAULT_FILE).style_spec("c"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new(&t!("about.language_label")),
        Cell::new(config.language.as_deref().unwrap_or("n/a")).style_spec("c"),
    ]));
    let keyfile_text = match &config.keyfile_path {
        Some(path) => format!("{} ({})", t!("common.active").green(), path),
        None => t!("common.inactive").dimmed().to_string(),
    };
    table.add_row(Row::new(vec![
        Cell::new(&t!("about.keyfile_label")),
        Cell::new(&keyfile_text).style_spec("c"),
    ]));
    let autolock_text = format!("{} {} {}",
        t!("common.active"),
        config.auto_lock_timeout_minutes.unwrap_or(AUTO_LOCK_TIMEOUT_MINUTES),
        t!("unit.minutes")
    );
    table.add_row(Row::new(vec![
        Cell::new(&t!("about.autolock_label")),
        Cell::new(&autolock_text).style_spec("c"),
    ]));
    let clipboard_text = format!("{} {} {}",
        t!("common.active"),
        CLIPBOARD_TIMEOUT_SECONDS,
        t!("unit.seconds")
    );
    table.add_row(Row::new(vec![
        Cell::new(&t!("about.clipboard_label")),
        Cell::new(&clipboard_text).style_spec("c"),
    ]));
    let symbols_text = match &config.password_generator_symbols {
        Some(symbols) if !symbols.is_empty() => format!("{} ({})", t!("common.custom").cyan(), symbols),
        _ => t!("common.default").dimmed().to_string(),
    };
    table.add_row(Row::new(vec![
        Cell::new(&t!("about.password_symbols_label")),
        Cell::new(&symbols_text).style_spec("c"),
    ]));

    table.add_empty_row();
    table.add_row(Row::new(vec![
        Cell::new(&t!("about.kdf_label")).with_style(Attr::Bold),
        Cell::new(&config.kdf_algorithm).style_spec("c"),
    ]));
    let salt_display = config.salt_hex[..16.min(config.salt_hex.len())].to_string() + "...";
    table.add_row(Row::new(vec![
        Cell::new("  Salt (Hex Preview)"),
        Cell::new(&salt_display).style_spec("c"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("  M_COST (Memory KiB)"),
        Cell::new(&config.m_cost.to_string()).style_spec("c"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("  T_COST (Iterations)"),
        Cell::new(&config.t_cost.to_string()).style_spec("c"),
    ]));
    table.add_row(Row::new(vec![
        Cell::new("  P_COST (Parallelism)"),
        Cell::new(&config.p_cost.to_string()).style_spec("c"),
    ]));

    table.add_empty_row();
    table.add_row(Row::new(vec![
        Cell::new("Defender Security Suite").with_style(Attr::Bold),
        Cell::new("").with_style(Attr::Bold),
    ]));

    let rfm_status_text = if config.defender_settings.enable_realtime_file_monitoring { t!("common.active").green() } else { t!("common.inactive").dimmed() };
    table.add_row(Row::new(vec![
        Cell::new("  Echtzeit-Monitoring"),
        Cell::new(&rfm_status_text).style_spec("c"),
    ]));
    let aad_status_text = if config.defender_settings.enable_advanced_antidebug { t!("common.active").green() } else { t!("common.inactive").dimmed() };
    table.add_row(Row::new(vec![
        Cell::new("  Erweiterte Anti-Debug Checks"),
        Cell::new(&aad_status_text).style_spec("c"),
    ]));
    let vm_status_text = if config.defender_settings.enable_vm_detection { t!("common.active").green() } else { t!("common.inactive").dimmed() };
    table.add_row(Row::new(vec![
        Cell::new("  VM Erkennung"),
        Cell::new(&vm_status_text).style_spec("c"),
    ]));
    let sps_status_text = if config.defender_settings.enable_suspicious_process_scan { t!("common.active").green() } else { t!("common.inactive").dimmed() };
    table.add_row(Row::new(vec![
        Cell::new("  Scan verdächtiger Prozesse"),
        Cell::new(&sps_status_text).style_spec("c"),
    ]));
    let sic_status_text = if config.defender_settings.enable_self_integrity_check { t!("common.active").green() } else { t!("common.inactive").dimmed() };
    table.add_row(Row::new(vec![
        Cell::new("  Selbstintegritätsprüfung"),
        Cell::new(&sic_status_text).style_spec("c"),
    ]));

    let behavioral_logging_text = if config.defender_settings.enable_behavioral_logging { t!("common.active").green() } else { t!("common.inactive").dimmed() };
    table.add_row(Row::new(vec![
    Cell::new("  AI Verhaltens-Logging"),
    Cell::new(&behavioral_logging_text).style_spec("c"),
    ]));

    table.printstd();
    wait_for_enter().ok();
}

pub fn manage_autolock_cli(config: &mut VaultConfig) -> Result<bool, VaultError> {
    clear_screen()?;
    println!("--- {} ---", t!("menu.manage_autolock").bold().yellow());

    let current_timeout = config.auto_lock_timeout_minutes.unwrap_or(AUTO_LOCK_TIMEOUT_MINUTES);
    println!("{}", t!("prompts.autolock_current", minutes = current_timeout));

    let new_timeout_str = prompt_optional(&t!("prompts.autolock_new", default_minutes = AUTO_LOCK_TIMEOUT_MINUTES))?;

    match new_timeout_str {
        Some(input_str) if !input_str.is_empty() => {
            match input_str.parse::<u64>() {
                Ok(new_val) => {
                    if new_val == 0 {
                        config.auto_lock_timeout_minutes = Some(0);
                        log::info!("Auto-Lock deaktiviert durch Benutzereingabe.");
                    } else {
                        config.auto_lock_timeout_minutes = Some(new_val);
                        log::info!("Auto-Lock Timeout geändert auf {} Minuten.", new_val);
                    }
                    println!("{}", t!("messages.autolock_updated", minutes = config.auto_lock_timeout_minutes.unwrap_or(0)).green());
                    Ok(true)
                }
                Err(_) => {
                    println!("{}", t!("errors.invalid_number_input").red());
                    Ok(false)
                }
            }
        }
        _ => {
            println!("{}", t!("prompts.autolock_no_change").dimmed());
            Ok(false)
        }
    }
}


pub fn export_vault_cli(vault: &Vault) -> Result<(), VaultError> {
    clear_screen()?;
    println!("--- {} (JSON) ---", t!("cli.export_vault_title").yellow());
    let path_str = prompt_non_empty(&t!("prompts.export_file_path_json"))?;
    if path_str.trim().to_lowercase() == "q" {
        println!("{}", t!("actions.cancelled"));
        return Ok(());
    }
    let path_buf = PathBuf::from(path_str);
    if path_buf.is_dir() {
        println!("{}", t!("errors.export_path_is_dir", path = path_buf.display()).red());
        return Ok(());
    }
    if path_buf.exists() && !prompt_yes_no(&t!("prompts.confirm_overwrite_export", path = path_buf.display()), Some(false))? {
        println!("{}", t!("actions.cancelled"));
        return Ok(());
    }
    vault_logic::export_vault_plaintext_json(vault, &path_buf)?;
    println!("{}", t!("messages.export_success_json", path = path_buf.display()).green());
    Ok(())
}

pub fn export_vault_csv_cli(vault: &Vault) -> Result<(), VaultError> {
    clear_screen()?;
    println!("--- {} (CSV) ---", t!("cli.export_vault_title_csv").yellow());
    let path_str = prompt_non_empty(&t!("prompts.export_file_path_csv"))?;
    if path_str.trim().to_lowercase() == "q" {
        println!("{}", t!("actions.cancelled"));
        return Ok(());
    }
    let path_buf = PathBuf::from(path_str);
    if path_buf.is_dir() {
        println!("{}", t!("errors.export_path_is_dir", path = path_buf.display()).red());
        return Ok(());
    }
     if path_buf.exists() && !prompt_yes_no(&t!("prompts.confirm_overwrite_export", path = path_buf.display()), Some(false))? {
        println!("{}", t!("actions.cancelled"));
        return Ok(());
    }
    vault_logic::export_vault_csv(vault, &path_buf)?;
    println!("{}", t!("messages.export_success_csv", path = path_buf.display()).green());
    Ok(())
}

pub fn export_vault_encrypted_cli(vault: &Vault) -> Result<(), VaultError> {
    clear_screen()?;
    println!("--- {} (Encrypted JSON) ---", t!("cli.export_vault_title_encrypted").yellow());
    let path_str = prompt_non_empty(&t!("prompts.export_file_path_encrypted_json"))?;
     if path_str.trim().to_lowercase() == "q" {
        println!("{}", t!("actions.cancelled"));
        return Ok(());
    }
    let path_buf = PathBuf::from(path_str);
     if path_buf.is_dir() {
        println!("{}", t!("errors.export_path_is_dir", path = path_buf.display()).red());
        return Ok(());
    }
    if path_buf.exists() && !prompt_yes_no(&t!("prompts.confirm_overwrite_export", path = path_buf.display()), Some(false))? {
        println!("{}", t!("actions.cancelled"));
        return Ok(());
    }
    let export_password = prompt_new_password_for_export()?;
    vault_logic::export_vault_encrypted(vault, &path_buf, &export_password)?;
    println!("{}", t!("messages.export_success_encrypted", path = path_buf.display()).green());
    Ok(())
}

pub fn check_password_strength_standalone() -> Result<(), VaultError> {
    println!("\n{}", t!("password_checker.title").bold().underline());
    println!("{}", t!("password_checker.description").dimmed());

    loop {
        let password_to_check: Zeroizing<String> = 
            prompt_password_hidden(&t!("password_checker.prompt_enter_password"))?;

        if password_to_check.is_empty() {
            println!("{}", t!("password_checker.empty_password_error").red());
            if !prompt_yes_no(&t!("prompts.try_again"), Some(true))? {
                break; 
            }
            continue; 
        }

        let user_inputs: &[&str] = &[];
        
        match zxcvbn::zxcvbn(password_to_check.as_str(), user_inputs) {
            Ok(entropy_estimate) => {
                display_strength_feedback(&password_to_check, &entropy_estimate)?; 
            }
            Err(e) => {
                log::error!("Fehler bei zxcvbn::zxcvbn: {:?}", e);
                println!("{}", t!("errors.zxcvbn_error_details", details = format!("Zxcvbn Fehler: {:?}", e)).red());
            }
        }

        if !prompt_yes_no(&t!("password_checker.prompt_check_another"), Some(true))? {
            break; 
        }
    }
    Ok(())
}

pub fn prompt_password_hidden(prompt_text: &str) -> Result<Zeroizing<String>, VaultError> {
    print!("{} ", prompt_text);
    io::stdout().flush().map_err(VaultError::Io)?;
    let password = read_password().map_err(|e| VaultError::Io(e))?;
    Ok(Zeroizing::new(password))
}

pub fn import_vault_cli(vault: &mut Vault) -> Result<usize, VaultError> {
    clear_screen()?;
    println!("--- {} (JSON) ---", t!("cli.import_vault_title").yellow());
    let path_str = prompt_non_empty(&t!("prompts.import_file_path_json"))?;
    if path_str.trim().to_lowercase() == "q" {
        println!("{}", t!("actions.cancelled"));
        return Ok(0);
    }
    let path_buf = PathBuf::from(path_str);
    vault_logic::import_vault(vault, &path_buf)
}

pub fn import_vault_encrypted_cli(vault: &mut Vault) -> Result<usize, VaultError> {
    clear_screen()?;
    println!("--- {} (Encrypted JSON) ---", t!("cli.import_vault_title_encrypted").yellow());
    let path_str = prompt_non_empty(&t!("prompts.import_file_path_encrypted_json"))?;
    if path_str.trim().to_lowercase() == "q" {
        println!("{}", t!("actions.cancelled"));
        return Ok(0);
    }
    let path_buf = PathBuf::from(path_str);
    let import_password = prompt_single_password(&t!("prompts.import_enter_pw"))?;
    vault_logic::import_vault_encrypted(vault, &path_buf, &import_password)
}


pub fn add_password_cli(vault: &mut Vault, custom_symbols: Option<&str>) -> Result<bool, VaultError> {
    clear_screen()?;
    println!("\n--- {} ---", t!("cli.add_password_title").cyan());
    let site = prompt_non_empty(&t!("prompts.site"))?;

     if vault.passwords.iter().any(|p| p.site.eq_ignore_ascii_case(&site)) {
         println!("{}", t!("errors.entry_already_exists", site = site).red());
         if !prompt_yes_no(&t!("prompts.confirm_add_duplicate"), Some(false))? {
             println!("{}", t!("actions.cancelled"));
             return Ok(false);
         }
         log::warn!("{}", t!("log.adding_duplicate_entry", site = site));
     }

    let username = prompt_optional(&t!("prompts.username"))?;

    let password: Zeroizing<String>;
    loop {
        let password_input_opt = prompt_optional(&t!("prompts.password_or_generate"))?;

        match password_input_opt {
            Some(pw_input) if pw_input.trim().to_lowercase() == "q" => {
                println!("{}", t!("actions.cancelled"));
                return Ok(false);
            }
            Some(pw_input) if !pw_input.trim().is_empty() => {
                let pw_zeroizing = Zeroizing::new(pw_input);
                match zxcvbn(pw_zeroizing.as_str(), &[]) {
                     Ok(estimate) => {
                         display_strength_feedback(&pw_zeroizing, &estimate)?;
                         if estimate.score() >= 1 {
                             password = pw_zeroizing;
                             break;
                         } else {
                             println!("{}", t!("messages.password_extremely_weak").red());
                         }
                     }
                     Err(e) => return Err(VaultError::ZxcvbnError(t!("errors.zxcvbn_internal_error", error = e.to_string()))),
                 }
            }
            _ => {
                println!("{}", t!("messages.generating_password"));

                let length = prompt_numeric(&t!("prompts.gen_length"), 8, 128, Some(16))?;
                let use_lowercase = prompt_yes_no(&t!("prompts.gen_use_lowercase"), Some(true))?;
                let use_uppercase = prompt_yes_no(&t!("prompts.gen_use_uppercase"), Some(true))?;
                let use_digits = prompt_yes_no(&t!("prompts.gen_use_digits"), Some(true))?;
                let use_symbols = prompt_yes_no(&t!("prompts.gen_use_symbols"), Some(true))?;

                let options = PasswordOptions {
                    length,
                    use_lowercase,
                    use_uppercase,
                    use_digits,
                    use_symbols,
                };

                password = Zeroizing::new(crypto::generate_password_custom(&options, custom_symbols)?);
                println!("{} {}", t!("messages.generated_password_prefix"), format!("{}", *password).green());
                if let Ok(estimate) = zxcvbn(password.as_str(), &[]) {
                     display_strength_feedback(&password, &estimate)?;
                 }
                break;
            }
        }
    }

    let category = prompt_optional(&t!("prompts.category"))?;
    let url = prompt_optional(&t!("prompts.url"))?;
    let labels_str = prompt_optional(&t!("prompts.labels"))?;
    let labels = labels_str.map(|s| s.split(',')
                                 .map(|tag| tag.trim().to_string())
                                 .filter(|t| !t.is_empty())
                                 .collect::<Vec<String>>())
                                 .filter(|v| !v.is_empty());

    let new_entry = crate::models::PasswordEntry { site: site.clone(), username, password, category, url, labels };
    vault.passwords.push(new_entry);
    log::info!("{}", t!("log.password_added", site = site));
    println!("{}", t!("messages.password_added", site = site).green());
    Ok(true)
}


pub fn show_passwords_cli<'a>(vault: &'a Vault) -> Result<Vec<usize>, VaultError> {
    clear_screen()?;
    println!("{}", t!("cli.list_passwords_title").bold().cyan());

    if vault.passwords.is_empty() {
        println!("\n{}", t!("messages.no_passwords_saved").yellow());
        return Ok(Vec::new());
    }

    print!("{} ", t!("prompts.search_term_pw"));
    io::stdout().flush()?;
    let mut search_term = String::new();
    io::stdin().read_line(&mut search_term)?;
    let search_term = search_term.trim().to_lowercase();
    log::debug!("{}", t!("log.searching_passwords", term = search_term));

    let mut filtered_indices = Vec::new();
    let mut table = Table::new();
    table.set_format(*FORMAT_BOX_CHARS);
    table.add_row(Row::new(vec![
        Cell::new(&t!("cli.table_header_num")).with_style(Attr::Bold),
        Cell::new(&t!("cli.table_header_site")).with_style(Attr::Bold),
        Cell::new(&t!("cli.table_header_username")).with_style(Attr::Bold),
        Cell::new(&t!("cli.table_header_category")).with_style(Attr::Bold),
        Cell::new(&t!("cli.table_header_url")).with_style(Attr::Bold),
        Cell::new(&t!("cli.table_header_labels")).with_style(Attr::Bold),
    ]));

    let mut displayed_count = 0;
    for (index, entry) in vault.passwords.iter().enumerate() {
        let site_match = entry.site.to_lowercase().contains(&search_term);
        let user_match = entry.username.as_deref().unwrap_or("").to_lowercase().contains(&search_term);
        let category_match = entry.category.as_deref().unwrap_or("").to_lowercase().contains(&search_term);
        let url_match = entry.url.as_deref().unwrap_or("").to_lowercase().contains(&search_term);
        let labels_match = entry.labels.as_ref().map_or(false, |tags| tags.iter().any(|tag| tag.to_lowercase().contains(&search_term)));

        if search_term.is_empty() || site_match || user_match || category_match || url_match || labels_match {
            filtered_indices.push(index);
            displayed_count += 1;

            let none_str = t!("common.none");
            table.add_row(Row::new(vec![
                Cell::new(&format!("{}.", displayed_count)).style_spec("r"),
                Cell::new(&entry.site),
                Cell::new(entry.username.as_deref().unwrap_or("-")),
                Cell::new(entry.category.as_deref().unwrap_or(&none_str)),
                Cell::new(entry.url.as_deref().unwrap_or("-")),
                Cell::new(&entry.labels.as_ref().map_or_else(
                    || "".to_string(),
                    |tags| if tags.is_empty() { "".to_string() } else { tags.join(", ") }
                )),
            ]));
        }
    }

    if displayed_count > 0 {
        println!();
        table.printstd();
    }

    println!("{}", "-----------------------------------------".dimmed());

    if displayed_count == 0 {
        if !search_term.is_empty() {
            log::debug!("{}", t!("log.search_no_results", term = search_term));
            println!("\n{}", t!("messages.search_no_results", term = search_term).yellow());
        }
    } else {
        log::debug!("{}", t!("log.search_results_count", count = displayed_count));
        println!("\n{}", t!("messages.search_results_count", count = displayed_count));
    }

    Ok(filtered_indices)
}


fn format_password_entry_summary(entry: &crate::models::PasswordEntry) -> String {
    let user = entry.username.as_deref().unwrap_or("-");
    let none_str = t!("common.none");
    let category = entry.category.as_deref().unwrap_or(&none_str);
    let url = entry.url.as_deref().unwrap_or("-");
    let labels = entry.labels.as_ref().map_or_else(
        || "".to_string(),
        |tags| {
            if tags.is_empty() { "".to_string() }
            else { format!("🏷️ [{}]", tags.join(", ")).purple().to_string() }
        },
    );

    format!(
        "{} {} {} {} {} {}",
        format!("🌐 {}", entry.site).bold().blue(),
        format!("👤 ({})", user).cyan(),
        format!("📁 [{}]", category).yellow(),
        "****".dimmed(),
        format!("🔗 ({})", url).blue().dimmed(),
        labels
    )
}

pub fn view_or_copy_password_cli(vault: &Vault, filtered_indices: &[usize]) -> Result<(), VaultError> {
    if filtered_indices.is_empty() {
        log::debug!("{}", t!("log.view_copy_no_entries"));
        return Ok(());
    }

    loop {
        print!("\n{} ", t!("prompts.select_entry_view_copy"));
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().parse::<usize>() {
            Ok(0) => {
                log::debug!("{}", t!("log.view_copy_cancelled"));
                return Ok(());
            }
            Ok(num) if num > 0 && num <= filtered_indices.len() => {
                let original_index = filtered_indices[num - 1];
                let entry = &vault.passwords[original_index];
                log::debug!("{}", t!("log.view_copy_selected", num = num, index = original_index));

                'action_loop: loop {
                    clear_screen()?;
                    println!("\n{}", format!("--- 🌐 {} Details ---", entry.site.bold()).cyan().bold());
                    println!("{}", "-----------------------------".dimmed());

                    let none_str = t!("common.none");

                    println!("  {:<15} {}", t!("common.site_service").dimmed(), format!("🌐 {}", entry.site).blue());
                    println!("  {:<15} {}", t!("common.username").dimmed(), format!("👤 {}", entry.username.as_deref().unwrap_or("-")).cyan());
                    println!("  {:<15} {}", t!("common.password").dimmed(), "****".italic());
                    println!("  {:<15} {}", t!("common.category").dimmed(), format!("📁 {}", entry.category.as_deref().unwrap_or(&none_str)).yellow());
                    println!("  {:<15} {}", t!("common.url").dimmed(), format!("🔗 {}", entry.url.as_deref().unwrap_or("-")).blue().dimmed());
                    let labels_formatted = entry.labels.as_ref().map_or_else(
                        || "-".to_string(),
                        |tags| if tags.is_empty() { "-".to_string() } else { tags.join(", ") }
                    );
                    println!("  {:<15} {}", t!("common.labels").dimmed(), format!("🏷️ {}", labels_formatted).purple());

                    println!("{}", "-----------------------------".dimmed());

                    println!("\n{}:", t!("cli.actions_for", site = entry.site.bold()));
                    println!("  [{}] {}", "P".bold().green(), format!("✂️ {}", t!("actions.copy_password")).green());
                    println!("  [{}] {}", "U".bold().blue(), format!("✂️ {}", t!("actions.copy_username")).blue());
                    println!("  [{}] {}", "S".bold().blue(), format!("✂️ {}", t!("actions.copy_site")).blue());
                    println!("  [{}] {}", "R".bold().blue(), format!("✂️ {}", t!("actions.copy_url")).blue());
                    println!("  [{}] {}", "V".bold().yellow(), format!("👁️ {}", t!("actions.view_password")).yellow());
                    println!("  [{}] {}", "Z".bold().red(), format!("🔙 {}", t!("actions.back_to_list")).red());
                    println!("{}", "-----------------------------".dimmed());
                    print!("\n{} ", t!("prompts.select_action").bold().blue());
                    io::stdout().flush()?;
                    let mut action_input = String::new();
                    io::stdin().read_line(&mut action_input)?;

                    let action_choice = action_input.trim().to_uppercase();

                    match action_choice.as_str() {
                        "P" => {
                            log::info!("{}", t!("log.copying_password", site = entry.site));
                            copy_to_clipboard(entry.password.as_str())?;
                        }
                        "U" => {
                             if let Some(user) = &entry.username {
                                log::info!("{}", t!("log.copying_username", user = user, site = entry.site));
                                copy_to_clipboard(user)?;
                             } else {
                                log::debug!("{}", t!("log.no_username_to_copy", site = entry.site));
                                println!("{}", t!("messages.no_username_present").yellow());
                                sleep(Duration::from_secs(1));
                             }
                        }
                         "S" => {
                             log::info!("{}", t!("log.copying_site", site = entry.site));
                             copy_to_clipboard(&entry.site)?;
                         }
                         "R" => {
                             if let Some(url) = &entry.url {
                                 log::info!("{}", t!("log.copying_url", url = url, site = entry.site));
                                 copy_to_clipboard(url)?;
                             } else {
                                 log::debug!("{}", t!("log.no_url_to_copy", site = entry.site));
                                 println!("{}", t!("messages.no_url_present").yellow());
                                 sleep(Duration::from_secs(1));
                             }
                         }
                        "V" => {
                            log::warn!("{}", t!("log.viewing_password", site = entry.site));
                            clear_screen()?;
                            println!("--- {} {} ---", t!("cli.details_for"), entry.site.bold());
                            println!("  {}: {}", t!("common.site_service").dimmed(), entry.site);
                            println!("  {}: {}", t!("common.username").dimmed(), entry.username.as_deref().unwrap_or("-"));
                            println!("  {}: {}", t!("common.password").yellow().bold(), entry.password.as_str().yellow().bold());
                             let none_str_v = t!("common.none");
                             println!("  {}: {}", t!("common.category").dimmed(), entry.category.as_deref().unwrap_or(&none_str_v));
                             println!("  {}: {}", t!("common.url").dimmed(), entry.url.as_deref().unwrap_or("-"));
                             println!(
                                 "  {}: {}",
                                 t!("common.labels").dimmed(),
                                 entry.labels.as_ref().map_or_else(|| "-".to_string(), |tags| if tags.is_empty() { "-".to_string() } else { tags.join(", ") })
                             );
                            println!("-----------------------------");
                            println!("\n{}\n", t!("messages.warning_password_viewed").bold().red());
                            wait_for_enter()?;
                            continue 'action_loop;
                        }
                        "Z" => {
                            log::debug!("{}", t!("log.back_to_list"));
                            break 'action_loop;
                        }
                        _ => {
                            log::warn!("{}", t!("log.invalid_action", action = action_input.trim()));
                            println!("{}", t!("errors.invalid_action").red());
                            sleep(Duration::from_secs(1));
                            continue 'action_loop;
                        }
                    }
                     if ["P", "U", "S", "R"].contains(&action_choice.as_str()) {
                         sleep(Duration::from_secs(1));
                         continue 'action_loop; // Stay on details page
                     }
                }
                clear_screen()?;
                let _ = show_passwords_cli(vault)?;
            }
            _ => {
                log::warn!("{}", t!("log.invalid_entry_number", input = input.trim()));
                println!("{}", t!("errors.invalid_number_from_list").red());
            }
        }
    }
}



pub fn delete_password_cli(vault: &mut Vault) -> Result<bool, VaultError> {
    let filtered_indices = show_passwords_cli(vault)?;

    if filtered_indices.is_empty() {
        wait_for_enter()?;
        return Ok(false);
    }

    loop {
        print!("\n{} ", t!("prompts.select_entry_delete"));
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().parse::<usize>() {
            Ok(0) => {
                log::debug!("{}", t!("log.delete_cancelled"));
                println!("{}", t!("actions.cancelled"));
                return Ok(false);
            }
            Ok(num) if num > 0 && num <= filtered_indices.len() => {
                let original_index = filtered_indices[num - 1];
                let entry_site = vault.passwords[original_index].site.clone();

                println!(
                    "{} {} '{}' {}?",
                    t!("common.warning").yellow().bold(),
                    t!("prompts.confirm_delete_entry_prefix", num = num),
                    entry_site.bold(),
                    t!("prompts.confirm_delete_entry_suffix"),
                );

                if prompt_yes_no(&t!("prompts.confirm_action"), Some(false))? {
                    let removed_entry = vault.passwords.remove(original_index);
                    log::info!("{}", t!("log.password_deleted", site = removed_entry.site));
                    println!(
                        "{}",
                        t!("messages.password_deleted", site = removed_entry.site).green()
                    );
                    wait_for_enter()?;
                    return Ok(true);
                } else {
                    log::debug!("{}", t!("log.delete_action_cancelled", site = entry_site));
                    println!("{}", t!("actions.delete_cancelled"));
                     return Ok(false);
                }
            }
            _ => {
                log::warn!("{}", t!("log.invalid_delete_number", input = input.trim()));
                println!("{}", t!("errors.invalid_number_from_list").red());
            }
        }
    }
}


pub fn edit_password_cli(vault: &mut Vault, custom_symbols: Option<&str>) -> Result<bool, VaultError> {
    clear_screen()?;
    println!("\n--- {} ---", t!("cli.edit_password_title").yellow());

    let filtered_indices = show_passwords_cli(vault)?;

    if filtered_indices.is_empty() {
        wait_for_enter()?;
        return Ok(false);
    }

    loop {
        print!("\n{} ", t!("prompts.select_entry_edit"));
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().parse::<usize>() {
            Ok(0) => return Ok(false),
            Ok(num) if num > 0 && num <= filtered_indices.len() => {
                let original_index = filtered_indices[num - 1];

                println!("\n{}:", t!("messages.current_details"));
                println!("  {}", format_password_entry_summary(&vault.passwords[original_index]));
                println!("-----------------------------");
                println!("{}", t!("prompts.edit_instructions_empty"));

                let entry = &mut vault.passwords[original_index];
                let old_site = entry.site.clone();


                let current_user = entry.username.as_deref().unwrap_or("");
                if let Some(new_username_input) = prompt_optional(&format!("{}: [{}]", t!("prompts.edit_username"), current_user))? {
                     entry.username = Some(new_username_input).filter(|s| !s.is_empty());
                 }

                if prompt_yes_no(&t!("prompts.edit_change_password"), Some(false))? {
                     loop {
                         let password_input_opt = prompt_optional(&t!("prompts.new_password_or_generate"))?;
                         match password_input_opt {
                             Some(pw_input) if !pw_input.trim().is_empty() => {
                                 let pw_zeroizing = Zeroizing::new(pw_input);
                                 match zxcvbn(pw_zeroizing.as_str(), &[]) {
                                      Ok(estimate) => {
                                          display_strength_feedback(&pw_zeroizing, &estimate)?;
                                          if estimate.score() >= 1 {
                                              entry.password = pw_zeroizing;
                                              break;
                                          } else { println!("{}", t!("messages.password_extremely_weak").red()); }
                                      }
                                      Err(e) => return Err(VaultError::ZxcvbnError(t!("errors.zxcvbn_internal_error", error=e.to_string()))),
                                  }
                             }
                             _ => {
                                 println!("{}", t!("messages.generating_password"));
                                 let length = prompt_numeric(&t!("prompts.gen_length"), 8, 128, Some(16))?;
                                 let use_lowercase = prompt_yes_no(&t!("prompts.gen_use_lowercase"), Some(true))?;
                                 let use_uppercase = prompt_yes_no(&t!("prompts.gen_use_uppercase"), Some(true))?;
                                 let use_digits = prompt_yes_no(&t!("prompts.gen_use_digits"), Some(true))?;
                                 let use_symbols = prompt_yes_no(&t!("prompts.gen_use_symbols"), Some(true))?;
                                 let options = PasswordOptions { length, use_lowercase, use_uppercase, use_digits, use_symbols };

                                 entry.password = Zeroizing::new(crypto::generate_password_custom(&options, custom_symbols)?);
                                 println!("{} {}", t!("messages.generated_password_prefix"), format!("{}", *entry.password).green());
                                 if let Ok(estimate) = zxcvbn(entry.password.as_str(), &[]) { display_strength_feedback(&entry.password, &estimate)?; }
                                 break;
                             }
                         }
                     }
                }

                let current_cat = entry.category.as_deref().unwrap_or("");
                if let Some(new_category_input) = prompt_optional(&format!("{}: [{}]", t!("prompts.edit_category"), current_cat))? {
                    entry.category = Some(new_category_input).filter(|s| !s.is_empty());
                }

                let current_url = entry.url.as_deref().unwrap_or("");
                if let Some(new_url_input) = prompt_optional(&format!("{}: [{}]", t!("prompts.edit_url"), current_url))? {
                    entry.url = Some(new_url_input).filter(|s| !s.is_empty());
                }

                 let current_labels_str = entry.labels.as_ref().map_or("".to_string(), |tags| tags.join(", "));
                if let Some(new_labels_str) = prompt_optional(&format!("{}: [{}]", t!("prompts.edit_labels"), current_labels_str))? {
                     entry.labels = Some(new_labels_str.split(',')
                                       .map(|tag| tag.trim().to_string())
                                       .filter(|t| !t.is_empty())
                                       .collect::<Vec<String>>())
                                       .filter(|v| !v.is_empty());
                 }

                println!("{}", t!("messages.entry_updated", site=entry.site).green());
                log::info!("Passworteintrag bearbeitet: '{}' (ursprünglicher Site-Name: '{}')", entry.site, old_site);
                wait_for_enter()?;
                return Ok(true);
            }
            _ => println!("{}", t!("errors.invalid_number_from_list").red()),
        }
    }
}

pub fn add_note_cli(vault: &mut Vault) -> Result<bool, VaultError> {
    clear_screen()?;
    println!("\n--- {} ---", t!("cli.add_note_title").cyan());
    let title = prompt_non_empty(&t!("prompts.note_title"))?;
    if title.trim().to_lowercase() == "q" {
        println!("{}", t!("actions.cancelled"));
        return Ok(false);
    }

     if vault.notes.iter().any(|n| n.title.eq_ignore_ascii_case(&title)) {
         println!("{}", t!("errors.note_title_exists", title = title).red());
         if !prompt_yes_no(&t!("prompts.confirm_add_duplicate_note"), Some(false))? {
             println!("{}", t!("actions.cancelled"));
             return Ok(false);
         }
         log::warn!("Füge Notiz mit doppeltem Titel '{}' hinzu.", title);
     }

    println!("{}", t!("prompts.note_content_instructions"));
    let mut content_lines = Vec::new();
    let stdin = io::stdin();
    for line_result in stdin.lock().lines() {
        let line = line_result?;
        if line.trim().to_uppercase() == "EOF" {
            break;
        }
        content_lines.push(line);
    }
    let content = content_lines.join("\n");

    if content.trim().is_empty() {
        println!("{}", t!("messages.warning_empty_note").yellow());
        if !prompt_yes_no(&t!("prompts.confirm_save_empty_note"), Some(false))? {
            println!("{}", t!("messages.empty_note_not_saved"));
            return Ok(false);
        }
         log::warn!("Speichere leere Notiz '{}'.", title);
    }

    let new_note = crate::models::NoteEntry { title: title.clone(), content };
    vault.notes.push(new_note);
    log::info!("{}", t!("log.note_added", title = title));
    println!("{}", t!("messages.note_added", title = title).green());
    Ok(true)
}


pub fn show_notes_cli(vault: &Vault) -> Result<(), VaultError> {
    clear_screen()?;
    println!("{}", t!("cli.list_notes_title").bold().cyan());

    if vault.notes.is_empty() {
        log::debug!("{}", t!("log.no_notes_to_show"));
        println!("\n{}", t!("messages.no_notes_saved").yellow());
    } else {
        log::debug!("{}", t!("log.showing_notes", count = vault.notes.len()));

        let mut table = Table::new();
        table.set_format(*FORMAT_BOX_CHARS);
        table.add_row(Row::new(vec![
            Cell::new(&t!("cli.table_header_num")).with_style(Attr::Bold),
            Cell::new(&t!("cli.table_header_title")).with_style(Attr::Bold),
            Cell::new(&t!("cli.table_header_content_preview")).with_style(Attr::Bold),
        ]));

        for (index, note) in vault.notes.iter().enumerate() {
            let preview_chars = 70;
            let mut content_preview = note.content.lines().next().unwrap_or("").to_string();
            if content_preview.chars().count() > preview_chars {
                content_preview = content_preview.chars().take(preview_chars).collect::<String>() + "...";
            } else if note.content.lines().nth(1).is_some() {
                 content_preview += "...";
            }

            if content_preview.is_empty() && !note.content.is_empty() {
                content_preview = "[...]".to_string();
            } else if note.content.is_empty() {
                content_preview = format!("({})", t!("common.empty").dimmed());
            }


            table.add_row(Row::new(vec![
                Cell::new(&format!("{}.", index + 1)).style_spec("r"),
                Cell::new(&note.title),
                Cell::new(&content_preview),
            ]));
        }
        println!();
        table.printstd();
        println!("\n{}", t!("messages.notes_displayed_count", count=vault.notes.len()));
        println!("{}", t!("messages.use_edit_note_for_details"));
    }
    Ok(())
}


pub fn delete_note_cli(vault: &mut Vault) -> Result<bool, VaultError> {
    clear_screen()?;
    println!("{}", t!("cli.delete_note_title").bold().red());
    if vault.notes.is_empty() {
        log::debug!("{}", t!("log.no_notes_to_delete"));
        println!("\n{}", t!("messages.no_notes_to_delete").yellow());
        wait_for_enter()?;
        return Ok(false);
    }

    println!("{}:", t!("prompts.select_note_to_delete"));
    for (index, note) in vault.notes.iter().enumerate() {
        println!(
            "  {} {}",
            format!("{:>3}.", index + 1).dimmed(),
            note.title.bold()
        );
    }
    println!("  {} {}", " 0.".dimmed(), t!("actions.cancel"));

    loop {
        print!("\n{} ", t!("prompts.enter_number"));
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        match input.trim().parse::<usize>() {
            Ok(0) => {
                log::debug!("{}", t!("log.note_delete_cancelled"));
                println!("{}", t!("actions.cancelled"));
                return Ok(false);
            }
            Ok(num) if num > 0 && num <= vault.notes.len() => {
                let index_to_remove = num - 1;
                let note_title = vault.notes[index_to_remove].title.clone();

                println!(
                     "{} {} ('{}') {}?",
                     t!("common.warning").yellow().bold(),
                     t!("prompts.confirm_delete_note_prefix", num = num),
                     note_title.bold(),
                     t!("prompts.confirm_delete_note_suffix")
                 );

                if prompt_yes_no(&t!("prompts.confirm_action"), Some(false))? {
                    let removed_note = vault.notes.remove(index_to_remove);
                    log::info!("{}", t!("log.note_deleted", title = removed_note.title));
                    println!("{}", t!("messages.note_deleted", title = removed_note.title).green());
                    wait_for_enter()?;
                    return Ok(true);
                } else {
                    log::debug!("{}", t!("log.delete_action_cancelled_note", title = note_title));
                    println!("{}", t!("actions.delete_cancelled"));
                    return Ok(false);
                }
            }
            _ => {
                log::warn!("{}", t!("log.invalid_note_delete_number", input = input.trim()));
                println!("{}", t!("errors.invalid_number_from_list").red());
            }
        }
    }
}

pub fn unlock_vault_cli(app_state_arc: &Arc<RwLock<AppState>>, config: &VaultConfig) -> Result<(), VaultError> {
    clear_screen()?;
    println!("--- {} ---", t!("menu.unlock_vault").bold().green());

    let entered_password = prompt_single_password(&t!("prompts.enter_master_password"))?;

    match vault_logic::unlock_and_load_vault(config, entered_password) {
        Ok(unlocked_state) => {
            match app_state_arc.write() {
                Ok(mut state) => {
                    *state = unlocked_state;
                    log::info!("Vault erfolgreich durch Menüoption entsperrt und AppState aktualisiert.");
                    Ok(())
                }
                Err(e) => {
                    log::error!("Kritischer Fehler: Konnte App-Zustand nach Entsperren nicht schreiben: {}", e);
                    Err(VaultError::VaultLockError(t!("errors.critical_state_lock_failed")))
                }
            }
        }
        Err(e) => {
            log::error!("Fehler beim Entsperren des Vaults via Menü: {}", e);
            Err(e)
        }
    }
}



pub fn edit_note_cli(vault: &mut Vault) -> Result<bool, VaultError> {
     clear_screen()?;
     println!("\n--- {} ---", t!("cli.edit_note_title").yellow());

     if vault.notes.is_empty() {
         println!("\n{}", t!("messages.no_notes_to_edit").yellow());
         wait_for_enter()?;
         return Ok(false);
     }

     println!("{}:", t!("prompts.select_note_to_edit"));
     for (index, note) in vault.notes.iter().enumerate() {
         println!("  {} {}", format!("{:>3}.", index + 1).dimmed(), note.title.bold());
     }
     println!("  {} {}", " 0.".dimmed(), t!("actions.cancel"));

     loop {
         print!("\n{} ", t!("prompts.enter_number"));
         io::stdout().flush()?;
         let mut input = String::new();
         io::stdin().read_line(&mut input)?;

         match input.trim().parse::<usize>() {
             Ok(0) => return Ok(false),
             Ok(num) if num > 0 && num <= vault.notes.len() => {
                 let index_to_edit = num - 1;
                 let old_title = vault.notes[index_to_edit].title.clone();

                 println!("\n{}: '{}'", t!("messages.editing_note"), old_title.bold());
                 println!("{}\n{}", t!("messages.current_content_note"), vault.notes[index_to_edit].content.dimmed());
                 println!("-----------------------------");
                 println!("{}", t!("prompts.edit_instructions_empty_note"));

                 let current_title_display = &old_title;
                 let mut new_title_opt: Option<String> = None;

                 if let Some(input_title) = prompt_optional(&format!("{}: [{}]", t!("prompts.edit_note_title_field"), current_title_display))? {
                      if !input_title.is_empty() && input_title != old_title {
                          let title_exists = vault.notes.iter().enumerate().any(|(i, n)| {
                              i != index_to_edit && n.title.eq_ignore_ascii_case(&input_title)
                          });

                          if title_exists {
                              println!("{}", t!("errors.note_title_exists", title = input_title).red());
                          } else {
                               new_title_opt = Some(input_title);
                          }
                      }
                  }

                 let note_to_edit = &mut vault.notes[index_to_edit];
                 if let Some(new_title) = new_title_opt {
                     log::info!("Ändere Notiztitel von '{}' zu '{}'", old_title, new_title);
                     note_to_edit.title = new_title;
                 }

                 println!("{}", t!("prompts.edit_note_content_instructions"));

                 let mut new_content_lines = Vec::new();
                 let mut user_entered_content = false;

                 let stdin = io::stdin();
                 for line_result in stdin.lock().lines() {
                     let line = line_result?;
                     if line.trim().to_uppercase() == "EOF" {
                         break;
                     }
                     user_entered_content = true;
                     new_content_lines.push(line);
                 }

                 if user_entered_content {
                      note_to_edit.content = new_content_lines.join("\n");
                      log::info!("Notizinhalt für '{}' aktualisiert.", note_to_edit.title);
                 } else {
                     println!("{}", t!("messages.note_content_unchanged").dimmed());
                 }
                 println!("{}", t!("messages.note_updated", title = note_to_edit.title).green());
                 wait_for_enter()?;
                 return Ok(true);
             }
             _ => println!("{}", t!("errors.invalid_number_from_list").red()),
         }
     }
}


pub fn show_charlie_memorial_upgraded() -> io::Result<()> {
    clear_screen()?;
    println!("\n{}", t!("charlie.upgrade.title").bold().cyan());
    println!("{}", "-----------------------------------------".dimmed());
    thread::sleep(Duration::from_millis(500));

    let hamster_art = r#"
⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⢀⣀⣀⣀⣀⣀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣴⢋⣩⣌⣩⠹⠖⠉⠁⠀⠀⠀⠀⠈⠉⠓⠟⣉⣡⣭⡙⣷⠀⠀⠀⠀
⠀⠀⠀⣿⢸⣏⡾⠛⠀⢀⣀⡀⠀⠀⠀⠀⢀⣠⡄⠀⠉⢻⣜⡿⣸⡇⠀⠀⠀
⠀⠀⠀⢻⣾⣟⣀⡀⢀⣸⣦⠝⠀⠀⠀⠀⠺⣤⣞⡀⠀⣀⣽⣷⡿⠁⠀⠀⠀
⠀⣠⠖⠈⠀⠀⠀⠉⠛⠫⠿⡶⠒⢾⣶⠒⠲⠿⠟⠟⠋⠁⠀⠀⠉⠲⣤⠀⠀
⣼⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣶⡞⠟⣶⣾⠃⠀⠀⠀⠀⠀⠀⠀⠀⠈⢷⠀
⣟⠀⠀⠀⠀⣀⢀⠀⠀⠀⠀⠘⢿⣏⣛⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇
⣿⠀⠀⢠⡞⢫⠙⠦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠞⡹⢳⣆⠀⠀⣸⠇
⠘⣧⡢C⡏⠀⠀⠀⠱⠄⠀⠀⠀⠀⠀⠀⠀⠀⢀⠜⠀⠀⠀⠈⡅⢠⣾⠟⠀
⠀⠈⢻⡷⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⢲⣿⠉⠀⠀
⠀⠀⣼⠃⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⢿⠀⠀⠀
⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀
⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⡇⠀⠀
⠀⠀⠹⣧⢄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡿⠀⠀⠀
⠀⠀⠀⠙⣳⣭⣐⡂⢀⠀⠀⣀⣀⣀⣀⣐⣀⠄⡀⠀⣀⣀⣤⣽⡟⠀⠀⠀⠀
⠀⠀⠀⢸⣇⣀⣨⣽⡿⠿⠛⠉⠉⠉⠉⠉⠉⠙⠻⢿⣭⣄⣀⣨⡷⠀⠀⠀⠀
⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀
    "#.bright_yellow().bold(); // Gelb und fett für gute Sichtbarkeit

    println!("\n{}\n", hamster_art);
    thread::sleep(Duration::from_millis(2500));


    let stars = ["*", ".", "o", " ", " ", " ", " "];
    let mut rng = rand::thread_rng();
    for y in 0..5 {
        for _ in 0..45 {
            if rng.gen_bool(0.06) {
                print!("{}", stars.choose(&mut rng).unwrap_or(&" ").to_string().dimmed());
            } else {
                print!(" ");
            }
        }
        println!();
        if y < 2 { thread::sleep(Duration::from_millis(200)); }
        else { thread::sleep(Duration::from_millis(150)); }
    }
    println!();
    thread::sleep(Duration::from_millis(400));

    let messages: Vec<String> = vec![
        format!("🌠 {}", t!("charlie.upgrade.line1", name = "Charlie").magenta().bold()),
        t!("charlie.upgrade.line2").cyan().italic().to_string(),
        t!("charlie.upgrade.line3").italic().to_string(),
        t!("charlie.upgrade.line4").yellow().bold().to_string(),
    ];

    for msg in messages {
        for char_c in msg.chars() {
            print!("{}", char_c);
            io::stdout().flush()?;
            thread::sleep(Duration::from_millis(30));
        }
        println!();
        thread::sleep(Duration::from_millis(800));
    }

    println!();
    for i in 0..5 {
        print!("{}🐾   ", " ".repeat(i * 2));
        io::stdout().flush()?;
        thread::sleep(Duration::from_millis(450));
        if i < 4 {
            print!("\r{}", " ".repeat((i * 2) + 5));
            io::stdout().flush()?;
        }
    }
    println!("\n\n{}", t!("charlie.upgrade.line5").dimmed());
    println!("{}", "-----------------------------------------".dimmed());
    thread::sleep(Duration::from_millis(1500));
    wait_for_enter()?;
    Ok(())
}

fn apply_atbash_cipher(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                (base + (25 - (c as u8 - base))) as char
            } else {
                c
            }
        })
        .collect()
}

fn apply_reverse_cipher(text: &str) -> String {
    text.chars().rev().collect()
}

fn type_out_message_cipher(message: &str, delay_ms: u64) -> io::Result<()> {
    for char_c in message.chars() {
        print!("{}", char_c);
        io::stdout().flush()?;
        thread::sleep(Duration::from_millis(delay_ms));
    }
    println!();
    Ok(())
}

fn apply_caesar_cipher(text: &str, shift: i8) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_uppercase() { b'A' } else { b'a' };
                let c_val = c as i16;
                let base_val = base as i16;
                let shift_val = shift as i16;
                ( ( (c_val - base_val) + shift_val ).rem_euclid(26) + base_val ) as u8 as char
            } else {
                c
            }
        })
        .collect()
}


pub fn run_cipher_challenge_upgraded() -> Result<(), VaultError> {
    clear_screen()?;
    println!("\n{}", t!("secret.cipher_ultra.title").bold().red());
    println!("{}", "---------------------------------------------------".dimmed());
    thread::sleep(Duration::from_millis(500));

    type_out_message_cipher(&t!("secret.cipher_ultra.briefing_intro"), 50)?;
    thread::sleep(Duration::from_millis(800));

    let scan_message = t!("secret.cipher_ultra.briefing_scan");
    for i in 0..=3 {
        print!("\r{}", " ".repeat(scan_message.len() + 5));
        print!("\r{}{}", scan_message, ".".repeat(i));
        io::stdout().flush()?;
        thread::sleep(Duration::from_millis(400));
    }
    println!();
    thread::sleep(Duration::from_millis(600));
    println!("\n{}\n", t!("secret.cipher_ultra.transmission_detected").yellow().bold());
    thread::sleep(Duration::from_millis(1000));

    let mut rng = rand::thread_rng();

    let cipher_types = [CipherType::Caesar, CipherType::Atbash, CipherType::Reverse];
    let selected_cipher = cipher_types.choose(&mut rng).unwrap_or(&CipherType::Caesar);

    let plaintext_key = "secret.cipher_upgrade.plaintext_options";
    let plaintext_options: Vec<String> = t!(plaintext_key)
        .split('|')
        .map(String::from)
        .collect();
    let plaintext = plaintext_options.choose(&mut rng).unwrap_or(&"DEFAULT ULTRA SECRET".to_string()).to_uppercase();
    let ciphertext: String;
    let mut caesar_shift: i8 = 0;

    let intel_report: String;
    let hint_key: String;
    let fail_final_key: String;

    match selected_cipher {
        CipherType::Caesar => {
            loop {
                caesar_shift = rng.gen_range(-7..=7);
                if caesar_shift != 0 { break; }
            }
            ciphertext = apply_caesar_cipher(&plaintext, caesar_shift);
            intel_report = t!("secret.cipher_ultra.intel_caesar");
            hint_key = "secret.cipher_ultra.hint_caesar".to_string();
            fail_final_key = "secret.cipher_ultra.fail_final_caesar".to_string();
        }
        CipherType::Atbash => {
            ciphertext = apply_atbash_cipher(&plaintext);
            intel_report = t!("secret.cipher_ultra.intel_atbash");
            hint_key = "secret.cipher_ultra.hint_atbash".to_string();
             fail_final_key = "secret.cipher_ultra.fail_final_atbash".to_string();
        }
        CipherType::Reverse => {
            ciphertext = apply_reverse_cipher(&plaintext);
            intel_report = t!("secret.cipher_ultra.intel_reverse");
            hint_key = "secret.cipher_ultra.hint_reverse".to_string();
            fail_final_key = "secret.cipher_ultra.fail_final_reverse".to_string();
        }
    }

    println!("{}", t!("secret.cipher_ultra.intel_report_title").cyan().bold());
    type_out_message_cipher(&intel_report.italic(), 30)?;
    println!("{}", "---------------------------------------------------".dimmed());
    thread::sleep(Duration::from_millis(800));

    println!("\n{}", t!("secret.cipher_ultra.encoded_transmission_label").yellow());
    println!("{}\n", ciphertext.purple().bold());

    let max_attempts = 3;
    for attempt_num in 1..=max_attempts {
        println!("{}", t!("secret.cipher_ultra.attempt_info", current = attempt_num, max = max_attempts).dimmed());
        let user_input = prompt_optional(&t!("secret.cipher_ultra.prompt_solution"))?;

        match user_input {
            Some(input_str) if !input_str.trim().is_empty() => {
                print!("{}", "Analysiere Eingabe: ".dimmed());
                for _ in 0..3 {
                    print!("{}", ".".dimmed());
                    io::stdout().flush()?;
                    thread::sleep(Duration::from_millis(300));
                }
                println!();

                if input_str.trim().to_uppercase() == plaintext {
                    println!("\n🎉 {}\n", t!("secret.cipher_ultra.success", text = plaintext).green().bold());
                    wait_for_enter()?;
                    return Ok(());
                } else {
                    println!("{}", t!("secret.cipher_ultra.fail_attempt").red());
                    if attempt_num == 1 {
                        println!("{}\n", t!(&hint_key).yellow().italic());
                    } else if attempt_num == 2 && matches!(selected_cipher, CipherType::Caesar) {
                        let direction = if caesar_shift > 0 { t!("secret.cipher_upgrade.direction_right")} else {t!("secret.cipher_upgrade.direction_left")};
                        println!("Zusatzhinweis: Die Verschiebung ist {}.", direction.italic().yellow());
                    }
                }
            }
            _ => {
                println!("{}", t!("secret.cipher_ultra.mission_aborted").dimmed());
                wait_for_enter()?;
                return Ok(());
            }
        }
        println!("{}", "---------------------------------------------------".dimmed());
    }
    
    let final_message = match selected_cipher {
        CipherType::Caesar => {
            let direction = if caesar_shift > 0 { t!("secret.cipher_upgrade.direction_right")} else {t!("secret.cipher_upgrade.direction_left")};
            t!(&fail_final_key, solution = plaintext, shift = caesar_shift.abs(), direction = direction)
        }
        _ => t!(&fail_final_key, solution = plaintext)
    };

    println!("\n{}\n", final_message.red().bold());
    wait_for_enter()?;
    Ok(())
}

fn text_to_binary_string(text: &str) -> String {
    text.bytes()
        .map(|byte| format!("{:08b}", byte))
        .collect::<Vec<String>>()
        .join(" ")
}

pub fn show_binary_whispers_upgraded() -> Result<(), VaultError> {
    clear_screen()?;
    println!("\n{}", t!("secret.binary_upgrade.title").bold().blue());
    println!("{}", "=================================================".dimmed());
    thread::sleep(Duration::from_millis(400));

    let original_text = t!("secret.binary_upgrade.plaintext");
    let binary_representation = text_to_binary_string(&original_text);

    println!("\n{}", t!("secret.binary_upgrade.transmission_start").italic().dimmed());
    thread::sleep(Duration::from_millis(600));

    print!("  ");
    let chunks: Vec<&str> = binary_representation.split(' ').collect();
    for (i, chunk) in chunks.iter().enumerate() {
        print!("{}", chunk.green().bold());
        io::stdout().flush()?;
        thread::sleep(Duration::from_millis(80));
        if (i + 1) % 6 == 0 && i < chunks.len() - 1 {
            println!();
            print!("  ");
            thread::sleep(Duration::from_millis(150));
        } else if i < chunks.len() - 1 {
            print!("{} ", if (i+1) % 2 == 0 {" "} else {""});
        }
    }
    println!();
    thread::sleep(Duration::from_millis(600));
    println!("\n{}", t!("secret.binary_upgrade.transmission_end").italic().dimmed());
    println!("{}", "=================================================".dimmed());

    if prompt_yes_no(&t!("secret.binary_upgrade.decode_prompt"), Some(true))? {
        println!("\n{}", t!("secret.binary_upgrade.decode_initiated").yellow());
        thread::sleep(Duration::from_millis(800));
        print!("  > ");
        for char_c in original_text.chars() {
            print!("{}", char_c.to_string().purple().bold());
            io::stdout().flush()?;
            thread::sleep(Duration::from_millis(100));
        }
        println!();
        println!("\n{}", t!("secret.binary_upgrade.decoded_success").green());
    } else {
        println!("\n{}", t!("secret.binary_upgrade.decode_skipped").dimmed());
    }

    wait_for_enter()?;
    Ok(())
}

pub fn prompt_for_keyfile_setup() -> Result<Option<String>, VaultError> {
    clear_screen()?;
    println!("--- {} ---", t!("config.keyfile_section_title").cyan().bold());

    if !prompt_yes_no(&t!("config.prompt_use_keyfile"), Some(false))? {
        println!("ℹ️  {}", t!("config.info_no_keyfile"));
        log::info!("Benutzer hat sich gegen die Verwendung eines Keyfiles entschieden.");
        return Ok(None);
    }

    println!("\n--- {} ---", t!("config.keyfile_options_title").yellow());
    println!("  [{}] {}", "1".bold().green(), t!("config.keyfile_option_generate"));
    println!("  [{}] {}", "2".bold().blue(), t!("config.keyfile_option_existing"));
    println!("  [{}] {}", "0".bold().red(), t!("actions.cancel_keyfile_setup"));

    loop {
        print!("\n{} ", t!("prompts.select_option_numbered").blue().bold());
        io::stdout().flush()?;
        let mut choice_input = String::new();
        io::stdin().read_line(&mut choice_input)?;

        match choice_input.trim() {
            "1" => {
                log::debug!("Benutzer möchte ein neues Keyfile generieren.");
                loop {
                    let path_str = prompt_non_empty(&t!("config.prompt_keyfile_generate_path"))?;
                    if path_str.trim().to_lowercase() == "q" {
                        println!("{}", t!("actions.cancelled").dimmed());
                        return Ok(None);
                    }
                    let keyfile_path = PathBuf::from(&path_str);

                    if keyfile_path.is_dir() {
                        println!("{}", t!("config.error_path_is_dir", path=keyfile_path.display()).red());
                        continue;
                    }

                    if keyfile_path.exists() {
                        println!("{}", t!("warnings.file_exists_prompt", path=keyfile_path.display()).yellow());
                        if !prompt_yes_no(&t!("prompts.confirm_overwrite_generic", path=keyfile_path.display()), Some(false))? {
                            log::warn!("Überschreiben von Keyfile '{}' durch Benutzer abgelehnt.", keyfile_path.display());
                            println!("{}", t!("actions.cancelled_overwrite_select_new_path").dimmed());
                            continue;
                        }
                        log::info!("Benutzer bestätigt Überschreiben von Keyfile '{}'.", keyfile_path.display());
                        if let Err(e) = fs::remove_file(&keyfile_path) {
                            log::warn!("Konnte existierendes Keyfile '{}' vor Neuerstellung nicht löschen: {}. Überschreibversuch wird trotzdem gestartet.", keyfile_path.display(), e);
                        }
                    }

                    match generate_and_save_keyfile(&keyfile_path, DEFAULT_KEYFILE_SIZE_BYTES) {
                        Ok(_) => {
                            println!("{}", t!("config.keyfile_generated_success", path=keyfile_path.display(), size=DEFAULT_KEYFILE_SIZE_BYTES).green().bold());
                            println!("{}", t!("warnings.backup_keyfile_critical", path=keyfile_path.display()).red().bold().blink());
                            wait_for_enter()?;
                            return Ok(Some(path_str));
                        }
                        Err(e) => {
                            log::error!("Fehler beim Generieren/Speichern des Keyfiles '{}': {}", keyfile_path.display(), e);
                            eprintln!("{}", t!("errors.keyfile_generation_failed_details", path=keyfile_path.display(), error=e.to_string()).red());
                            if !prompt_yes_no(&t!("prompts.try_again_generic"), Some(true))? {
                                println!("{}", t!("actions.cancelled_keyfile_setup_info").dimmed());
                                return Ok(None);
                            }
                        }
                    }
                }
            }
            "2" => {
                log::debug!("Benutzer möchte ein existierendes Keyfile verwenden.");
                loop {
                    let path_str = prompt_non_empty(&t!("config.prompt_keyfile_path_existing"))?;
                    if path_str.trim().to_lowercase() == "q" {
                        println!("{}", t!("actions.cancelled").dimmed());
                        return Ok(None);
                    }
                    let keyfile_path = PathBuf::from(&path_str);

                    if !keyfile_path.exists() {
                        println!("{}", t!("config.error_keyfile_not_exist", path=keyfile_path.display()).red());
                        if !prompt_yes_no(&t!("prompts.try_again_enter_path"), Some(true))? {
                            return Ok(None);
                        }
                        continue;
                    }
                    if !keyfile_path.is_file() {
                        println!("{}", t!("config.error_path_not_file", path=keyfile_path.display()).red());
                        if !prompt_yes_no(&t!("prompts.try_again_enter_path"), Some(true))? {
                            return Ok(None);
                        }
                        continue;
                    }

                    config::check_keyfile_permissions(&keyfile_path);
                    log::info!("Verwende existierendes Keyfile: {}", keyfile_path.display());
                    println!("✅ {}", t!("config.info_keyfile_path_used", path=keyfile_path.display()).green());
                    return Ok(Some(path_str));
                }
            }
            "0" => {
                println!("{}", t!("actions.cancelled_keyfile_setup_info").dimmed());
                return Ok(None);
            }
            _ => {
                println!("{}", t!("errors.invalid_choice").red());
            }
        }
    }
}