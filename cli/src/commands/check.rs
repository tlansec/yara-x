use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{fs, io, process};

use anyhow::Context;
use clap::{ArgAction, ArgMatches, Command, arg, value_parser};
use crossterm::tty::IsTty;
use superconsole::{Component, Line, Lines, Span};
use yansi::Color::{Green, Red, Yellow};
use yansi::Paint;
use yara_x::SourceCode;
use yara_x::check_config::apply_check_config;

use crate::config::Config;
use crate::walk::Message;
use crate::{help, walk};

pub fn check() -> Command {
    super::command("check")
        .about("Check if source files are syntactically correct")
        // The `check` command is not ready yet.
        .hide(true)
        .long_about(help::CHECK_LONG_HELP)
        // Keep options sorted alphabetically by their long name.
        // For instance, --bar goes before --foo.
        .arg(
            arg!(<RULES_PATH>)
                .help("Path to YARA source file or directory")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            arg!(-f --filter <PATTERN>)
                .help("Check files that match the given pattern only")
                .long_help(help::FILTER_LONG_HELP)
                .action(ArgAction::Append),
        )
        .arg(
            arg!(-r - -"recursive"[MAX_DEPTH])
                .help("Walk directories recursively up to a given depth")
                .long_help(help::RECURSIVE_LONG_HELP)
                .default_missing_value("1000")
                .require_equals(true)
                .value_parser(value_parser!(usize)),
        )
        .arg(
            arg!(-p --"threads" <NUM_THREADS>)
                .help("Use the given number of threads")
                .long_help(help::THREADS_LONG_HELP)
                .required(false)
                .value_parser(value_parser!(u8).range(1..)),
        )
}

pub fn exec_check(args: &ArgMatches, config: &Config) -> anyhow::Result<()> {
    let rules_path = args.get_one::<PathBuf>("RULES_PATH").unwrap();
    let recursive = args.get_one::<usize>("recursive");
    let filters = args.get_many::<String>("filter");
    let num_threads = args.get_one::<u8>("threads");

    let mut w = walk::ParWalker::path(rules_path);

    if let Some(num_threads) = num_threads {
        w.num_threads(*num_threads);
    }

    if let Some(filters) = filters {
        for filter in filters {
            w.filter(filter);
        }
    } else {
        // Default filters are `**/*.yar` and `**/*.yara`.
        w.filter("**/*.yar").filter("**/*.yara");
    }

    w.max_depth(*recursive.unwrap_or(&0));

    let state = w.walk(
        CheckState::new(),
        // Initialization
        |_, _| {},
        // Action
        |state, output, file_path, _| {
            let src = fs::read(file_path.clone())
                .with_context(|| {
                    format!("can not read `{}`", file_path.display())
                })
                .unwrap();

            let src = SourceCode::from(src.as_slice())
                .with_origin(file_path.as_os_str().to_str().unwrap());

            let mut lines = Vec::new();
            let mut compiler = yara_x::Compiler::new();

            apply_check_config(&mut compiler, &config.check)?;

            compiler.colorize_errors(io::stdout().is_tty());

            let _ = compiler.add_source(src);

            if !compiler.errors().is_empty() {
                state.errors.fetch_add(
                    compiler.errors().len(),
                    Ordering::Relaxed,
                );
                lines.push(format!(
                    "[ {} ] {}",
                    "FAIL".paint(Red).bold(),
                    file_path.display()
                ));
                for error in compiler.errors() {
                    eprintln!("{error}");
                }
            } else if !compiler.warnings().is_empty() {
                state.warnings.fetch_add(
                    compiler.warnings().len(),
                    Ordering::Relaxed,
                );
                lines.push(format!(
                    "[ {} ] {}",
                    "WARN".paint(Yellow).bold(),
                    file_path.display()
                ));
                for warning in compiler.warnings() {
                    eprintln!("{warning}");
                }
            } else {
                state.files_passed.fetch_add(1, Ordering::Relaxed);
                lines.push(format!(
                    "[ {} ] {}",
                    "PASS".paint(Green).bold(),
                    file_path.display()
                ));
            }

            output.send(Message::Info(lines.join("\n")))?;

            Ok(())
        },
        // Finalization
        |_, _| {},
        // Walk done
        |_| {},
        // Error handling
        |err, output| {
            let _ = output.send(Message::Error(format!(
                "{} {}",
                "error:".paint(Red).bold(),
                err
            )));

            Ok(())
        },
    )
        .unwrap();

    // Exit code is 1 if errors were found.
    if state.errors.load(Ordering::Relaxed) > 0 {
        process::exit(1)
    }

    // Exit code is 2 if no error was found, but warnings were found.
    if state.warnings.load(Ordering::Relaxed) > 0 {
        process::exit(2);
    }

    Ok(())
}

#[derive(Debug)]
struct CheckState {
    files_passed: AtomicUsize,
    warnings: AtomicUsize,
    errors: AtomicUsize,
}

impl CheckState {
    fn new() -> Self {
        Self {
            files_passed: AtomicUsize::new(0),
            warnings: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        }
    }
}

impl Component for CheckState {
    fn draw_unchecked(
        &self,
        _dimensions: superconsole::Dimensions,
        mode: superconsole::DrawMode,
    ) -> anyhow::Result<superconsole::Lines> {
        let res = match mode {
            superconsole::DrawMode::Normal | superconsole::DrawMode::Final => {
                let ok = format!(
                    "{} file(s) ok. ",
                    self.files_passed.load(Ordering::Relaxed)
                );

                let warnings = format!(
                    "warnings: {}. ",
                    self.warnings.load(Ordering::Relaxed)
                );

                let errors = format!(
                    "errors: {}.",
                    self.errors.load(Ordering::Relaxed)
                );

                Line::from_iter([
                    Span::new_unstyled(ok.paint(Green).bold())?,
                    Span::new_unstyled(warnings.paint(Yellow).bold())?,
                    Span::new_unstyled(errors.paint(Red).bold())?,
                ])
            }
        };
        Ok(Lines(vec![res]))
    }
}
