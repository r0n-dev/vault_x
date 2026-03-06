use crate::cli;
use crate::errors::VaultError;
use colored::*;
use rand::seq::SliceRandom;
use rust_i18n::t;
use std::collections::HashSet;
use std::io::{self, Write};

const CODEWORDS: &[&str] = &[
    "FIREWALL", "ENCRYPTION", "PROTOCOL", "DATABASE", "SERVER", "CLIENT",
    "NETWORK", "PASSWORD", "KEYFILE", "ALGORITHM", "SECURITY", "BACKDOOR",
    "ROOTKIT", "MALWARE", "AUTHENTICATION", "AUTHORIZATION", "VAULT", "CRYPTO",
    "RUSTLANG", "SECURECODE", "BINARY", "HEXADECIMAL", "CIPHERTEXT", "PLAINTEXT",
];

const MAX_TRIES: u32 = 7;

const HANGMAN_STAGES: [&str; MAX_TRIES as usize + 1] = [
    "  +---+\n  |   |\n      |\n      |\n      |\n      |\n=========",
    "  +---+\n  |   |\n  O   |\n      |\n      |\n      |\n=========",
    "  +---+\n  |   |\n  O   |\n  |   |\n      |\n      |\n=========",
    "  +---+\n  |   |\n  O   |\n /|   |\n      |\n      |\n=========",
    "  +---+\n  |   |\n  O   |\n /|\\  |\n      |\n      |\n=========",
    "  +---+\n  |   |\n  O   |\n /|\\  |\n /    |\n      |\n=========",
    "  +---+\n  |   |\n  O   |\n /|\\  |\n / \\  |\n      |\n=========",
    "  +---+\n  |   |\n  O   |\n /|\\  |\n / \\  |\n      |\n=========  <-- R.I.P.",
];

fn display_state(word_display: &str, guessed_letters: &HashSet<char>, tries_left: u32) {
    println!("\n{}", "====================================".cyan());

    let stage_index = (MAX_TRIES - tries_left) as usize;
    if stage_index < HANGMAN_STAGES.len() {
        println!("{}", HANGMAN_STAGES[stage_index].yellow());
    }

    println!("{}: {}", t!("game.target_word_label"), word_display.yellow().bold());
    let guessed_str: String = guessed_letters.iter().map(|c| c.to_string()).collect::<Vec<String>>().join(" ");
    println!("{}: {}", t!("game.guessed_letters_label"), guessed_str.dimmed());
    println!("{}: {}", t!("game.tries_left_label"), tries_left.to_string().red().bold());
    println!("{}", "====================================".cyan());
}

pub fn start_game() -> Result<(), VaultError> {
    cli::clear_screen()?;
    println!("\n{}\n", t!("game.welcome").cyan().bold());
    println!("{}", t!("game.intro").italic());
    println!("{}", t!("game.rules", max_tries = MAX_TRIES).dimmed());

    let mut rng = rand::thread_rng();
    let word_to_guess = CODEWORDS.choose(&mut rng).unwrap_or(&"VAULTX").to_uppercase();
    let word_chars: HashSet<char> = word_to_guess.chars().collect();

    let mut guessed_letters: HashSet<char> = HashSet::new();
    let mut tries_left = MAX_TRIES;
    let mut word_display: String = word_to_guess.chars().map(|_| '_').collect();


    loop {
        display_state(&word_display, &guessed_letters, tries_left);

        if !word_display.contains('_') {
            println!("\n🎉 {}\n", t!("game.win", word = word_to_guess).green().bold());
            break;
        }

        if tries_left == 0 {
            println!("\n💥 {}\n", t!("game.lose", word = word_to_guess).red().bold());
            break;
        }

        print!("{} ", t!("game.prompt_guess").yellow());
        io::stdout().flush()?;
        let mut guess = String::new();
        io::stdin().read_line(&mut guess)?;
        let guess = guess.trim().to_uppercase();

        if guess.is_empty() {
            println!("{}", t!("game.invalid_empty_guess").yellow());
            cli::wait_for_enter()?;
            cli::clear_screen()?;
            continue;
        }

        if guess.len() > 1 {
            if guess == word_to_guess {
                word_display = word_to_guess.to_string();
            } else {
                println!("{}", t!("game.wrong_word").red());
                tries_left = tries_left.saturating_sub(1); 
            }
            cli::wait_for_enter()?;
            cli::clear_screen()?;
            continue;
        }

        let guess_char = guess.chars().next().unwrap();
        if !guess_char.is_ascii_alphabetic() {
            println!("{}", t!("game.invalid_guess_char", guess = guess_char).red());
            cli::wait_for_enter()?;
            cli::clear_screen()?;
            continue;
        }

        if guessed_letters.contains(&guess_char) {
            println!("{}", t!("game.already_guessed", letter = guess_char).dimmed());
            cli::wait_for_enter()?;
            cli::clear_screen()?;
            continue;
        }

        guessed_letters.insert(guess_char);

        if word_chars.contains(&guess_char) {
            println!("{}", t!("game.hit", letter = guess_char).green());
            word_display = word_to_guess
                .chars()
                .map(|c| if c == guess_char || guessed_letters.contains(&c) { c } else { '_' })
                .collect();
        } else {
            println!("{}", t!("game.miss", letter = guess_char).red());
            tries_left = tries_left.saturating_sub(1);
        }
        if tries_left > 0 && word_display.contains('_') {
             std::thread::sleep(std::time::Duration::from_millis(1200));
             cli::clear_screen()?;
        }
    }

    println!("\n{}\n", t!("game.exit").cyan());
    cli::wait_for_enter()?; 
    cli::clear_screen()?;
    Ok(())
}