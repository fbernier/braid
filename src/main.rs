use braid_client::forward::ForwardSpec;
use braid_client::predict::Prediction;
use std::env;
use std::ffi::OsString;
use std::process::ExitCode;

const USAGE: &str = "usage: brd [--predict=MODE] [-L SPEC] <destination> [-- command ...]
       brd -N -L SPEC [-L SPEC ...] <destination>
       brd attach <destination> <id>
       brd ls <destination>
       brd kill <destination> <id>
       brd grep <destination> <pattern>
       brd --help | --version

`brd <destination>` resumes the newest session on that host, or starts one.
`brd attach` names an older session by any unambiguous prefix of its id.
`brd grep` searches every session's scrollback on that host, where it lives.
`--predict` is never, adaptive or always and defaults to adaptive: a keystroke
is drawn before the session echoes it only on a link slow enough for the round
trip to be worth hiding. `BRD_PREDICT` names the same three.
`-L [bind_address:]port:host:hostport` forwards a local port, repeatable, in
ssh's own syntax and binding loopback unless the spec names an address. The
forward is carried by the session, so it survives the reconnects that end an
`ssh -L` tunnel outright.
`-N` carries the forwards and nothing else: no terminal, no shell, and no
controlling terminal to need one, so it backgrounds with `&` and runs under a
unit file. It requires a `-L` and refuses a command.
In a session, Ctrl-] r repaints, Ctrl-] z suspends, Ctrl-] d detaches and
Ctrl-] . quits.
`BRD_LOG` names a file this client appends a line to for each reconnect,
transport change and detach, which is what a bug report needs and a terminal
cannot carry. Unset, nothing is opened and nothing is written.
Transport options belong in ssh_config: brd runs your `ssh`, and your
`~/.ssh/config` is already the complete answer for ports, jump hosts and keys.";

/// Kept apart from 1 so a script can tell misuse from a session that failed.
const MISUSE: u8 = 2;

fn main() -> ExitCode {
    let mut args = env::args_os();
    let _program = args.next();
    let (options, first) = match options(&mut args) {
        Ok(parsed) => parsed,
        Err(code) => return code,
    };
    let Options {
        chosen,
        forwards,
        headless,
    } = options;
    let prediction = match chosen {
        Some(mode) => mode,
        None => match predict_env() {
            Ok(mode) => mode.unwrap_or_default(),
            Err(code) => return code,
        },
    };
    let Some(first) = first else {
        return usage();
    };
    // These three open a management connection carrying no session for a
    // forward to ride on.
    if !forwards.is_empty()
        && let Some(word @ ("ls" | "kill" | "grep")) = first.to_str()
    {
        eprintln!("brd: -L does not apply to `{word}`");
        return ExitCode::from(MISUSE);
    }
    if headless && let Some(word @ ("ls" | "kill" | "grep" | "attach")) = first.to_str() {
        eprintln!("brd: -N does not apply to `{word}`");
        return ExitCode::from(MISUSE);
    }
    match first.to_str() {
        Some("--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            println!("brd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        // Both are invoked over `ssh` by this binary itself, never by a user.
        Some("--server") => report("brd server", braid_server::run_server()),
        Some("--daemon") => report("brd daemon", braid_server::run_daemon()),
        Some("ls") => match destination(args.next()) {
            Ok(destination) => report("brd", braid_client::manage::list(&destination)),
            Err(code) => code,
        },
        Some("kill") => match destination_and(&mut args, "session id") {
            Ok((destination, id)) => report("brd", braid_client::manage::kill(&destination, &id)),
            Err(code) => code,
        },
        Some("grep") => match destination_and(&mut args, "pattern") {
            Ok((destination, pattern)) => {
                report("brd", braid_client::manage::grep(&destination, &pattern))
            }
            Err(code) => code,
        },
        Some("attach") => match destination_and(&mut args, "session id") {
            Ok((destination, id)) => report(
                "brd",
                braid_client::run(&destination, &[], Some(id.as_str()), prediction, &forwards),
            ),
            Err(code) => code,
        },
        _ => match (destination(Some(first)), command(args)) {
            (Ok(destination), Ok(command)) => {
                if headless {
                    if let Some(refusal) = headless_refusal(&command, &forwards) {
                        eprintln!("brd: {refusal}");
                        return ExitCode::from(MISUSE);
                    }
                    return report("brd", braid_client::forward_only(&destination, &forwards));
                }
                report(
                    "brd",
                    braid_client::run(&destination, &command, None, prediction, &forwards),
                )
            }
            (Err(code), _) | (_, Err(code)) => code,
        },
    }
}

#[derive(Default)]
struct Options {
    chosen: Option<Prediction>,
    forwards: Vec<ForwardSpec>,
    headless: bool,
}

/// The options, and the first word that is not one. Nothing after the
/// destination is examined: `--` already separates the command.
fn options(args: &mut env::ArgsOs) -> Result<(Options, Option<OsString>), ExitCode> {
    let mut options = Options::default();
    let mut first = args.next();
    while let Some(argument) = first.as_ref().and_then(|argument| argument.to_str()) {
        if let Some(name) = argument.strip_prefix("--predict=") {
            let Some(mode) = Prediction::parse(name) else {
                eprintln!("brd: --predict takes never, adaptive or always");
                return Err(ExitCode::from(MISUSE));
            };
            options.chosen = Some(mode);
            first = args.next();
            continue;
        }
        if let Some(glued) = argument.strip_prefix("-L") {
            // Glued or apart, because `ssh` takes both.
            let spec = if glued.is_empty() {
                let Some(spec) = text(args.next(), "-L")? else {
                    eprintln!("brd: -L takes [bind_address:]port:host:hostport");
                    return Err(ExitCode::from(MISUSE));
                };
                spec
            } else {
                glued.to_owned()
            };
            match ForwardSpec::parse(&spec) {
                Ok(forward) => options.forwards.push(forward),
                Err(error) => {
                    eprintln!("brd: -L {spec}: {error}");
                    return Err(ExitCode::from(MISUSE));
                }
            }
            first = args.next();
            continue;
        }
        if argument == "-N" {
            options.headless = true;
            first = args.next();
            continue;
        }
        break;
    }
    Ok((options, first))
}

fn headless_refusal(command: &[String], forwards: &[ForwardSpec]) -> Option<&'static str> {
    if !command.is_empty() {
        return Some("-N carries forwards and nothing else: it runs no command");
    }
    if forwards.is_empty() {
        return Some("-N needs at least one -L: without one it forwards nothing");
    }
    None
}

/// An unrecognised value is refused rather than ignored, so an exported
/// `BRD_PREDICT=off` does not silently do nothing.
fn predict_env() -> Result<Option<Prediction>, ExitCode> {
    let Some(value) = env::var_os("BRD_PREDICT") else {
        return Ok(None);
    };
    let Some(mode) = value.to_str().and_then(Prediction::parse) else {
        eprintln!("brd: BRD_PREDICT takes never, adaptive or always");
        return Err(ExitCode::from(MISUSE));
    };
    Ok(Some(mode))
}

/// `ssh` reads a leading `-` as an option, and `-oProxyCommand=...` is a
/// command it runs locally.
fn destination(argument: Option<OsString>) -> Result<String, ExitCode> {
    let Some(destination) = text(argument, "destination")? else {
        return Err(usage());
    };
    if destination.starts_with('-') {
        eprintln!("brd: destination must not begin with '-'");
        return Err(ExitCode::from(MISUSE));
    }
    Ok(destination)
}

/// Both words are examined even when the first is wrong, so a command line
/// with two mistakes says so about both.
fn destination_and(rest: &mut env::ArgsOs, what: &str) -> Result<(String, String), ExitCode> {
    match (destination(rest.next()), text(rest.next(), what)) {
        (Ok(destination), Ok(Some(word))) => Ok((destination, word)),
        (Ok(_), Ok(None)) => Err(usage()),
        (Err(code), _) | (_, Err(code)) => Err(code),
    }
}

/// argv to run instead of the login shell. A bare word before the `--` is a
/// typo, and taking it as part of the command would run it.
fn command(mut rest: env::ArgsOs) -> Result<Vec<String>, ExitCode> {
    let Some(separator) = rest.next() else {
        return Ok(Vec::new());
    };
    if separator != "--" {
        eprintln!("brd: unexpected argument; a command must follow '--'");
        return Err(ExitCode::from(MISUSE));
    }
    let mut command = Vec::new();
    for word in rest {
        let Some(word) = word.to_str() else {
            eprintln!("brd: command is not valid UTF-8");
            return Err(ExitCode::from(MISUSE));
        };
        command.push(word.to_owned());
    }
    if command.is_empty() {
        eprintln!("brd: '--' must be followed by a command");
        return Err(ExitCode::from(MISUSE));
    }
    Ok(command)
}

fn text(argument: Option<OsString>, what: &str) -> Result<Option<String>, ExitCode> {
    argument
        .map(|argument| {
            argument.into_string().map_err(|_| {
                eprintln!("brd: {what} is not valid UTF-8");
                ExitCode::from(MISUSE)
            })
        })
        .transpose()
}

fn report<E: std::fmt::Display>(role: &str, outcome: Result<(), E>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{role}: {error}");
            ExitCode::from(1)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(MISUSE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_headless_session_refuses_what_it_cannot_carry() {
        let forwards = [ForwardSpec::parse("8080:localhost:80").expect("a well-formed spec")];
        let command = ["top".to_owned()];
        let cases: [(&[String], &[ForwardSpec], Option<&str>); 3] = [
            (&[], &[], Some("-L")),
            (&command, &forwards, Some("no command")),
            (&[], &forwards, None),
        ];
        for (command, forwards, expected) in cases {
            let refusal = headless_refusal(command, forwards);
            match expected {
                Some(named) => assert!(
                    refusal.is_some_and(|refusal| refusal.contains(named)),
                    "{refusal:?} does not name {named}"
                ),
                None => assert!(refusal.is_none(), "refused a forward it can carry"),
            }
        }
    }
}
