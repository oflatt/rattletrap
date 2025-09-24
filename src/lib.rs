use std::{
    env,
    fs::File,
    io::{BufReader, BufWriter, Cursor, Read, Write},
    path::PathBuf,
    process::{exit, Command, ExitStatus, Stdio},
    str::FromStr,
};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[cfg(target_os = "linux")]
use inferno::collapse::perf::{Folder, Options as CollapseOptions};

#[cfg(target_os = "macos")]
use inferno::collapse::xctrace::Folder;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use inferno::collapse::dtrace::{Folder, Options as CollapseOptions};

#[cfg(unix)]
use signal_hook::consts::{SIGINT, SIGTERM};

use anyhow::{anyhow, bail, Context};
use clap::{
    builder::{PossibleValuesParser, TypedValueParser},
    Args,
};
use inferno::{collapse::Collapse, flamegraph::color::Palette, flamegraph::from_reader};
use rustc_demangle::demangle_stream;

pub enum Workload {
    Command(Vec<String>),
    Pid(Vec<u32>),
    ReadPerf(PathBuf),
}

#[cfg(target_os = "linux")]
mod arch {
    use std::time::Duration;

    use indicatif::{ProgressBar, ProgressStyle};

    use super::*;

    pub const SPAWN_ERROR: &str = "could not spawn perf";
    pub const WAIT_ERROR: &str = "unable to wait for perf child command to exit";

    pub(crate) fn initial_command(
        workload: Workload,
        sudo: Option<Option<&str>>,
        freq: u32,
        custom_cmd: Option<String>,
        verbose: bool,
        ignore_status: bool,
    ) -> anyhow::Result<Option<PathBuf>> {
        let perf = if let Ok(path) = env::var("PERF") {
            path
        } else {
            if Command::new("perf")
                .arg("--help")
                .stderr(Stdio::null())
                .stdout(Stdio::null())
                .status()
                .is_err()
            {
                bail!("perf is not installed or not present in $PATH");
            }

            String::from("perf")
        };
        let mut command = sudo_command(&perf, sudo);

        let args = custom_cmd.unwrap_or(format!("record -F {freq} --call-graph dwarf,64000 -g"));

        let mut perf_output = None;
        let mut args = args.split_whitespace();
        while let Some(arg) = args.next() {
            command.arg(arg);

            // Detect if user is setting `perf record`
            // output file with `-o`. If so, save it in
            // order to correctly compute perf's output in
            // `Self::output`.
            if arg == "-o" {
                let next_arg = args.next().context("missing '-o' argument")?;
                command.arg(next_arg);
                perf_output = Some(PathBuf::from(next_arg));
            }
        }

        let perf_output = match perf_output {
            Some(path) => path,
            None => {
                command.arg("-o");
                command.arg("perf.data");
                PathBuf::from("perf.data")
            }
        };

        match workload {
            Workload::Command(c) => {
                command.args(&c);
            }
            Workload::Pid(p) => {
                if let Some((first, pids)) = p.split_first() {
                    let mut arg = first.to_string();

                    for pid in pids {
                        arg.push(',');
                        arg.push_str(&pid.to_string());
                    }

                    command.arg("-p");
                    command.arg(arg);
                }
            }
            Workload::ReadPerf(_) => (),
        }

        run(command, verbose, ignore_status);
        Ok(Some(perf_output))
    }

    pub fn output(
        perf_output: Option<PathBuf>,
        script_no_inline: bool,
        sudo: Option<Option<&str>>,
    ) -> anyhow::Result<Vec<u8>> {
        // We executed `perf record` with sudo, and will be executing `perf script` with sudo,
        // so that we can resolve privileged kernel symbols from /proc/kallsyms.
        let perf = env::var("PERF").unwrap_or_else(|_| "perf".to_string());
        let mut command = sudo_command(&perf, sudo);

        command.arg("script");

        // Force reading perf.data owned by another uid if it happened to be created earlier.
        command.arg("--force");

        if script_no_inline {
            command.arg("--no-inline");
        }

        if let Some(perf_output) = perf_output {
            command.arg("-i");
            command.arg(perf_output);
        }

        // perf script can take a long time to run. Notify the user that it is running
        // by using a spinner. Note that if this function exits before calling
        // spinner.finish(), then the spinner will be completely removed from the terminal.
        let spinner = ProgressBar::new_spinner().with_prefix("Running perf script");
        spinner.set_style(
            ProgressStyle::with_template("{prefix} [{elapsed}]: {spinner:.green}").unwrap(),
        );
        spinner.enable_steady_tick(Duration::from_millis(500));

        let result = command.output().context("unable to call perf script");
        spinner.finish();
        let output = result?;
        if !output.status.success() {
            bail!(
                "unable to run 'perf script': ({}) {}",
                output.status,
                std::str::from_utf8(&output.stderr)?
            );
        }
        Ok(output.stdout)
    }
}

#[cfg(target_os = "macos")]
mod arch {
    use super::*;

    pub const SPAWN_ERROR: &str = "could not spawn xctrace";
    pub const WAIT_ERROR: &str = "unable to wait for xctrace record child command to exit";

    pub(crate) fn initial_command(
        workload: Workload,
        sudo: Option<Option<&str>>,
        freq: u32,
        custom_cmd: Option<String>,
        verbose: bool,
        ignore_status: bool,
    ) -> anyhow::Result<Option<PathBuf>> {
        if freq != 997 {
            bail!("xctrace doesn't support custom frequency");
        }
        if custom_cmd.is_some() {
            bail!("xctrace doesn't support custom command");
        }
        let xctrace = env::var("XCTRACE").unwrap_or_else(|_| "xctrace".to_string());
        let trace_file = PathBuf::from("cargo-flamegraph.trace");
        let mut command = sudo_command(&xctrace, sudo);
        command
            .arg("record")
            .arg("--template")
            .arg("Time Profiler")
            .arg("--output")
            .arg(&trace_file);
        match workload {
            Workload::Command(args) => {
                command
                    .arg("--target-stdout")
                    .arg("-")
                    .arg("--launch")
                    .arg("--")
                    .args(args);
            }
            Workload::Pid(pid) => {
                match &*pid {
                    [pid] => {
                        // xctrace could accept multiple --attach <pid> arguments,
                        // but it will only profile the last pid provided.
                        command.arg("--attach").arg(pid.to_string());
                    }
                    _ => {
                        bail!("xctrace only supports profiling a single process at a time");
                    }
                }
            }
            Workload::ReadPerf(_) => {}
        }
        run(command, verbose, ignore_status);
        Ok(Some(trace_file))
    }

    pub fn output(
        trace_file: Option<PathBuf>,
        script_no_inline: bool,
        _sudo: Option<Option<&str>>,
    ) -> anyhow::Result<Vec<u8>> {
        if script_no_inline {
            bail!("--no-inline is only supported on Linux");
        }

        let xctrace = env::var("XCTRACE").unwrap_or_else(|_| "xctrace".to_string());
        let trace_file = trace_file.context("no trace file found.")?;
        let output = Command::new(xctrace)
            .arg("export")
            .arg("--input")
            .arg(&trace_file)
            .arg("--xpath")
            .arg(r#"/trace-toc/*/data/table[@schema="time-profile"]"#)
            .output()
            .context("run xctrace export failed.")?;
        std::fs::remove_dir_all(&trace_file)
            .with_context(|| anyhow!("remove trace({}) failed.", trace_file.to_string_lossy()))?;
        if !output.status.success() {
            bail!(
                "unable to run 'xctrace export': ({}) {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(output.stdout)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod arch {
    use super::*;

    pub const SPAWN_ERROR: &str = "could not spawn dtrace";
    pub const WAIT_ERROR: &str = "unable to wait for dtrace child command to exit";

    #[cfg(target_os = "macos")]
    fn base_dtrace_command(sudo: Option<Option<&str>>) -> Command {
        // If DTrace is spawned from a parent process (or grandparent process etc.) running in Rosetta-emulated x86 mode
        // on an ARM mac, it will fail to trace the child process with a confusing syntax error in its stdlib .d file.
        // If the flamegraph binary, or the cargo binary, have been compiled as x86, this can cause all tracing to fail.
        // To work around that, we unconditionally wrap dtrace on MacOS in the "arch -64/-32" wrapper so it's always
        // running in the native architecture matching the bit width (32 oe 64) with which "flamegraph" was compiled.
        // NOTE that dtrace-as-x86 won't trace a deliberately-cross-compiled x86 binary running under Rosetta regardless
        // of "arch" wrapping; attempts to do that will fail with "DTrace cannot instrument translated processes".
        // NOTE that using the ARCHPREFERENCE environment variable documented here
        // (https://www.unix.com/man-page/osx/1/arch/) would be a much simpler solution to this issue, but it does not
        // seem to have any effect on dtrace when set (via Command::env, shell export, or std::env in the spawning
        // process).
        let mut command = sudo_command("arch", sudo);

        #[cfg(target_pointer_width = "64")]
        command.arg("-64".to_string());
        #[cfg(target_pointer_width = "32")]
        command.arg("-32".to_string());

        command.arg(env::var("DTRACE").unwrap_or_else(|_| "dtrace".to_string()));
        command
    }

    #[cfg(not(target_os = "macos"))]
    fn base_dtrace_command(sudo: Option<Option<&str>>) -> Command {
        let dtrace = env::var("DTRACE").unwrap_or_else(|_| "dtrace".to_string());
        sudo_command(&dtrace, sudo)
    }

    pub(crate) fn initial_command(
        workload: Workload,
        sudo: Option<Option<&str>>,
        freq: u32,
        custom_cmd: Option<String>,
        verbose: bool,
        ignore_status: bool,
    ) -> anyhow::Result<Option<PathBuf>> {
        let mut command = base_dtrace_command(sudo);

        let dtrace_script = custom_cmd.unwrap_or(format!(
            "profile-{freq} /pid == $target/ \
             {{ @[ustack(100)] = count(); }}",
        ));

        command.arg("-x");
        command.arg("ustackframes=100");

        command.arg("-n");
        command.arg(&dtrace_script);

        command.arg("-o");
        command.arg("cargo-flamegraph.stacks");

        match workload {
            Workload::Command(c) => {
                let mut escaped = String::new();
                for (i, arg) in c.iter().enumerate() {
                    if i > 0 {
                        escaped.push(' ');
                    }
                    escaped.push_str(&arg.replace(' ', "\\ "));
                }

                command.arg("-c");
                command.arg(&escaped);

                #[cfg(target_os = "windows")]
                {
                    let mut help_test = crate::arch::base_dtrace_command(None);

                    let dtrace_found = help_test
                        .arg("--help")
                        .stderr(Stdio::null())
                        .stdout(Stdio::null())
                        .status()
                        .is_ok();
                    if !dtrace_found {
                        let mut command_builder = Command::new(&c[0]);
                        command_builder.args(&c[1..]);
                        print_command(&command_builder, verbose);

                        let trace = blondie::trace_command(command_builder, false)
                            .map_err(|err| anyhow!("could not find dtrace and could not profile using blondie: {err:?}"))?;

                        let f = std::fs::File::create("./cargo-flamegraph.stacks")
                            .context("unable to create temporary file 'cargo-flamegraph.stacks'")?;
                        let mut f = std::io::BufWriter::new(f);
                        trace.write_dtrace(&mut f).map_err(|err| {
                            anyhow!("unable to write dtrace output to 'cargo-flamegraph.stacks': {err:?}")
                        })?;

                        return Ok(None);
                    }
                }
            }
            Workload::Pid(p) => {
                for p in p {
                    command.arg("-p");
                    command.arg(p.to_string());
                }
            }
            Workload::ReadPerf(_) => (),
        }

        run(command, verbose, ignore_status);
        Ok(None)
    }

    pub fn output(
        _: Option<PathBuf>,
        script_no_inline: bool,
        sudo: Option<Option<&str>>,
    ) -> anyhow::Result<Vec<u8>> {
        if script_no_inline {
            bail!("--no-inline is only supported on Linux");
        }

        // Ensure the file is readable by the current user if dtrace was run
        // with sudo.
        if sudo.is_some() {
            #[cfg(unix)]
            if let Ok(user) = env::var("USER") {
                Command::new("sudo")
                    .args(["chown", user.as_str(), "cargo-flamegraph.stacks"])
                    .spawn()
                    .expect(arch::SPAWN_ERROR)
                    .wait()
                    .expect(arch::WAIT_ERROR);
            }
        }

        let mut buf = vec![];
        let mut f = File::open("cargo-flamegraph.stacks")
            .context("failed to open dtrace output file 'cargo-flamegraph.stacks'")?;

        f.read_to_end(&mut buf)
            .context("failed to read dtrace expected output file 'cargo-flamegraph.stacks'")?;

        std::fs::remove_file("cargo-flamegraph.stacks")
            .context("unable to remove temporary file 'cargo-flamegraph.stacks'")?;

        // Workaround #32 - fails parsing invalid utf8 dtrace output
        //
        // Intermittently, invalid utf-8 is found in cargo-flamegraph.stacks, which
        // causes parsing to blow up with the error:
        //
        // > unable to collapse generated profile data: Custom { kind: InvalidData, error: StringError("stream did not contain valid UTF-8") }
        //
        // So here we just lossily re-encode to hopefully work around the underlying problem
        let string = String::from_utf8_lossy(&buf);
        let reencoded_buf = string.as_bytes().to_owned();

        if reencoded_buf != buf {
            println!("Lossily converted invalid utf-8 found in cargo-flamegraph.stacks");
        }

        Ok(reencoded_buf)
    }
}

fn sudo_command(command: &str, sudo: Option<Option<&str>>) -> Command {
    let sudo = match sudo {
        Some(sudo) => sudo,
        None => return Command::new(command),
    };

    let mut c = Command::new("sudo");
    if let Some(sudo_args) = sudo {
        c.arg(sudo_args);
    }
    c.arg(command);
    c
}

fn run(mut command: Command, verbose: bool, ignore_status: bool) {
    print_command(&command, verbose);
    let mut recorder = command.spawn().expect(arch::SPAWN_ERROR);
    let exit_status = recorder.wait().expect(arch::WAIT_ERROR);

    // only stop if perf exited unsuccessfully, but
    // was not killed by a signal (assuming that the
    // latter case usually means the user interrupted
    // it in some way)
    if !ignore_status && terminated_by_error(exit_status) {
        eprintln!(
            "failed to sample program, exited with code: {:?}",
            exit_status.code()
        );
        exit(1);
    }
}

#[cfg(unix)]
fn terminated_by_error(status: ExitStatus) -> bool {
    status
        .signal() // the default needs to be true because that's the neutral element for `&&`
        .map_or(true, |code| code != SIGINT && code != SIGTERM)
        && !status.success()
        // on macOS, xctrace captures Ctrl+C and exits with code 54
        && !(cfg!(target_os = "macos") && status.code() == Some(54))
}

#[cfg(not(unix))]
fn terminated_by_error(status: ExitStatus) -> bool {
    !status.success()
}

fn print_command(cmd: &Command, verbose: bool) {
    if verbose {
        println!("command {:?}", cmd);
    }
}

pub fn generate_flamegraph_for_workload(workload: Workload, opts: Options) -> anyhow::Result<()> {
    // Handle SIGINT with an empty handler. This has the
    // implicit effect of allowing the signal to reach the
    // process under observation while we continue to
    // generate our flamegraph.  (ctrl+c will send the
    // SIGINT signal to all processes in the foreground
    // process group).
    #[cfg(unix)]
    let handler = unsafe {
        signal_hook::low_level::register(SIGINT, || {}).expect("cannot register signal handler")
    };

    let sudo = opts.root.as_ref().map(|inner| inner.as_deref());

    #[cfg(unix)]
    signal_hook::low_level::unregister(handler);

    // Compute collapsed stacks via streaming (Linux/macOS). Batch is allowed only for ReadPerf.
    let mut collapsed: Vec<u8> = Vec::new();
    let must_stream = !matches!(workload, Workload::ReadPerf(_));

    // Real-time mode doesn't support custom perf/dtrace commands.
    if must_stream && opts.custom_cmd.is_some() {
        panic!("real-time streaming requires default tooling; custom --cmd is not supported");
    }

    #[cfg(target_os = "linux")]
    {
        if !matches!(workload, Workload::ReadPerf(_)) && opts.custom_cmd.is_none() {
            match linux_stream_and_collapse(
                &workload,
                sudo,
                opts.frequency(),
                opts.script_no_inline,
                opts.verbose,
                opts.ignore_status,
                opts.flamegraph_options.skip_after.clone(),
            ) {
                Ok(bytes) => {
                    collapsed = bytes;
                }
                Err(e) => panic!("real-time streaming (linux/perf) failed: {}", e),
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        if collapsed.is_empty() && must_stream && opts.custom_cmd.is_none() {
            match macos_stream_and_collapse(
                &workload,
                sudo,
                opts.frequency(),
                opts.verbose,
                opts.ignore_status,
            ) {
                Ok(bytes) => {
                    collapsed = bytes;
                }
                Err(e) => panic!("real-time streaming (macOS/dtrace) failed: {}", e),
            }
        }
    }

    if collapsed.is_empty() {
        // Only allowed for ReadPerf workloads
        if must_stream {
            panic!("real-time streaming is required but not available on this platform");
        }
        let perf_output = if let Workload::ReadPerf(perf_file) = &workload {
            Some(perf_file.clone())
        } else {
            unreachable!("batch path should only be hit for ReadPerf workloads")
        };

        let output = arch::output(perf_output, opts.script_no_inline, sudo)?;

        let mut demangled_output = vec![];
        demangle_stream(&mut Cursor::new(output), &mut demangled_output, false)
            .context("unable to demangle")?;

        let perf_reader = BufReader::new(&*demangled_output);

        let mut collapsed_buf = vec![];
        let collapsed_writer = BufWriter::new(&mut collapsed_buf);

        #[cfg(target_os = "linux")]
        let mut folder = {
            let mut collapse_options = CollapseOptions::default();
            collapse_options.skip_after = opts.flamegraph_options.skip_after.clone();
            Folder::from(collapse_options)
        };

        #[cfg(target_os = "macos")]
        let mut folder = Folder::default();

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let mut folder = {
            let collapse_options = CollapseOptions::default();
            Folder::from(collapse_options)
        };

        folder
            .collapse(perf_reader, collapsed_writer)
            .context("unable to collapse generated profile data")?;

        collapsed = collapsed_buf;
    }

    if let Some(command) = opts.post_process {
        let command_vec = shlex::split(&command)
            .ok_or_else(|| anyhow!("unable to parse post-process command"))?;

        let mut child = Command::new(
            command_vec
                .first()
                .ok_or_else(|| anyhow!("unable to parse post-process command"))?,
        )
        .args(command_vec.get(1..).unwrap_or(&[]))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .with_context(|| format!("unable to execute {:?}", command_vec))?;

        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("unable to capture post-process stdin"))?;

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("unable to capture post-process stdout"))?;

        let thread_handle = std::thread::spawn(move || -> anyhow::Result<_> {
            let mut collapsed_processed = Vec::new();
            stdout.read_to_end(&mut collapsed_processed).context(
                "unable to read the processed stacks from the stdout of the post-process process",
            )?;
            Ok(collapsed_processed)
        });

        stdin
            .write_all(&collapsed)
            .context("unable to write the raw stacks to the stdin of the post-process process")?;
        drop(stdin);

        anyhow::ensure!(
            child.wait()?.success(),
            "post-process exited with a non zero exit code"
        );

        collapsed = thread_handle.join().unwrap()?;
    }

    let collapsed_reader = BufReader::new(&*collapsed);

    let flamegraph_filename = opts.output;
    println!("writing flamegraph to {:?}", flamegraph_filename);
    let flamegraph_file = File::create(&flamegraph_filename)
        .context("unable to create flamegraph.svg output file")?;

    let flamegraph_writer = BufWriter::new(flamegraph_file);

    let mut inferno_opts = opts.flamegraph_options.into_inferno();
    from_reader(&mut inferno_opts, collapsed_reader, flamegraph_writer)
        .context("unable to generate a flamegraph from the collapsed stack data")?;

    if opts.open {
        opener::open(&flamegraph_filename).context(format!(
            "failed to open '{}'",
            flamegraph_filename.display()
        ))?;
    }

    Ok(())
}

/// Demangle collapsed folded lines by demangling each symbol between ';'.
fn demangle_folded(input: &[u8]) -> Vec<u8> {
    use rustc_demangle::try_demangle;
    let mut out = Vec::with_capacity(input.len());
    for line in input.split(|&b| b == b'\n') {
        if line.is_empty() {
            out.push(b'\n');
            continue;
        }
        let s = String::from_utf8_lossy(line);
        if let Some((stack, count)) = s.rsplit_once(' ') {
            let demangled_stack = stack
                .split(';')
                .map(|sym| {
                    try_demangle(sym)
                        .map(|d| d.to_string())
                        .unwrap_or_else(|_| sym.to_string())
                })
                .collect::<Vec<_>>()
                .join(";");
            out.extend_from_slice(demangled_stack.as_bytes());
            out.push(b' ');
            out.extend_from_slice(count.as_bytes());
            out.push(b'\n');
        } else {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    out
}

/// A writer that tees collapsed output into a sink and triggers sonification per line.
struct CollapsedTeeWriter<'a> {
    sink: &'a mut Vec<u8>,
    buf: Vec<u8>,
}

impl<'a> CollapsedTeeWriter<'a> {
    fn new(sink: &'a mut Vec<u8>) -> Self {
        Self {
            sink,
            buf: Vec::with_capacity(4096),
        }
    }

    fn handle_complete_line(&mut self, line: &[u8]) {
        // Push the line (with newline) to sink
        self.sink.extend_from_slice(line);
        // Call sonifier on this one line
        if let Ok(s) = std::str::from_utf8(line) {
            let s = s.trim_end_matches(['\n', '\r']);
            if !s.is_empty() {
                if let Some((stack, count_str)) = s.rsplit_once(' ') {
                    let count: u64 = count_str.parse().unwrap_or(1);
                    let leaf = match stack.rsplit_once(';') {
                        Some((_, leaf)) => leaf,
                        None => stack,
                    };
                    on_function_activity(leaf, count);
                }
            }
        } else {
            // Fallback lossy parse
            let s = String::from_utf8_lossy(line);
            let s = s.trim_end_matches(['\n', '\r']);
            if !s.is_empty() {
                if let Some((stack, count_str)) = s.rsplit_once(' ') {
                    let count: u64 = count_str.parse().unwrap_or(1);
                    let leaf = match stack.rsplit_once(';') {
                        Some((_, leaf)) => leaf,
                        None => stack,
                    };
                    on_function_activity(leaf, count);
                }
            }
        }
    }
}

impl<'a> Write for CollapsedTeeWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Write-through to sink
        self.sink.extend_from_slice(buf);
        // Also scan for line breaks in local buffer for parsing
        self.buf.extend_from_slice(buf);
        while let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
            // Split at newline inclusive
            let line = self.buf.drain(..=pos).collect::<Vec<u8>>();
            self.handle_complete_line(&line);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            // Treat remaining bytes as a final line
            let line = std::mem::take(&mut self.buf);
            self.handle_complete_line(&line);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn linux_stream_and_collapse(
    workload: &Workload,
    sudo: Option<Option<&str>>,
    freq: u32,
    script_no_inline: bool,
    verbose: bool,
    ignore_status: bool,
    skip_after: Vec<String>,
) -> anyhow::Result<Vec<u8>> {
    // Do not support custom perf command in streaming path.
    let perf = env::var("PERF").unwrap_or_else(|_| "perf".to_string());

    // Build `perf record ... -o -` command
    let mut record_cmd = sudo_command(&perf, sudo);
    record_cmd.arg("record");
    record_cmd.arg("-F").arg(freq.to_string());
    record_cmd.arg("--call-graph").arg("dwarf,64000");
    record_cmd.arg("-g");
    record_cmd.arg("-o").arg("-");

    match workload {
        Workload::Command(args) => {
            record_cmd.args(args);
        }
        Workload::Pid(pids) => {
            if let Some((first, rest)) = pids.split_first() {
                let mut arg = first.to_string();
                for pid in rest {
                    arg.push(',');
                    arg.push_str(&pid.to_string());
                }
                record_cmd.arg("-p").arg(arg);
            }
        }
        Workload::ReadPerf(_) => unreachable!("streaming not used for ReadPerf"),
    }

    if verbose {
        println!("command {:?}", record_cmd);
    }
    let mut record_child = record_cmd
        .stdout(Stdio::piped())
        .spawn()
        .expect(arch::SPAWN_ERROR);

    // Build `perf script --force [--no-inline] -i -` command
    let mut script_cmd = sudo_command(&perf, sudo);
    script_cmd.arg("script");
    script_cmd.arg("--force");
    if script_no_inline {
        script_cmd.arg("--no-inline");
    }
    script_cmd.arg("-i").arg("-");
    script_cmd.stdin(
        record_child
            .stdout
            .take()
            .expect("failed to capture perf record stdout"),
    );
    script_cmd.stdout(Stdio::piped());

    if verbose {
        println!("command {:?}", script_cmd);
    }
    let mut script_child = script_cmd.spawn().expect(arch::SPAWN_ERROR);
    let script_stdout = script_child
        .stdout
        .take()
        .expect("failed to capture perf script stdout");

    // Collapse streaming output, teeing each folded line to a buffer and our sonifier.
    let mut collapsed_sink = Vec::<u8>::new();
    let mut tee_writer = CollapsedTeeWriter::new(&mut collapsed_sink);

    let mut collapse_options = CollapseOptions::default();
    collapse_options.skip_after = skip_after;
    let mut folder = Folder::from(collapse_options);

    let collapse_res = folder.collapse(BufReader::new(script_stdout), &mut tee_writer);
    if let Err(err) = collapse_res {
        // Ensure children are terminated and reaped on error to avoid zombies
        let _ = script_child.kill();
        let _ = record_child.kill();
        let _ = script_child.wait();
        let _ = record_child.wait();
        return Err(err).context("unable to collapse generated profile data (streaming)");
    }

    // Ensure processes are reaped
    let status_script = script_child.wait().expect(arch::WAIT_ERROR);
    let status_record = record_child.wait().expect(arch::WAIT_ERROR);
    if !ignore_status && terminated_by_error(status_script) {
        bail!("perf script exited with error: {:?}", status_script);
    }
    if !ignore_status && terminated_by_error(status_record) {
        bail!("perf record exited with error: {:?}", status_record);
    }

    // Finalize any trailing buffered line
    tee_writer.flush().ok();

    // Demangle the folded lines token-wise to match batch output expectations.
    let demangled = demangle_folded(&collapsed_sink);
    Ok(demangled)
}

#[cfg(target_os = "macos")]
fn macos_stream_and_collapse(
    workload: &Workload,
    sudo: Option<Option<&str>>,
    freq: u32,
    verbose: bool,
    ignore_status: bool,
) -> anyhow::Result<Vec<u8>> {
    use inferno::collapse::dtrace::{Folder as DtraceFolder, Options as DtraceCollapseOptions};

    // Build base dtrace command with arch wrapper to avoid Rosetta traps
    let mut cmd = macos_base_dtrace_command(sudo);

    // Configure user stack frames and quiet output, and increase delivery rates so data
    // is flushed to userland frequently (avoid ~1s bursts).
    cmd.arg("-x").arg("ustackframes=100");
    cmd.arg("-x").arg("switchrate=100hz");
    cmd.arg("-x").arg("aggrate=100hz");
    cmd.arg("-q");

    // Aggregation and periodic print
    let profile_clause = format!(
        "profile-{} /pid == $target/ {{ @[ustack(100)] = count(); }}",
        freq
    );
    cmd.arg("-n").arg(profile_clause);
    // Add a sentinel after each 25ms aggregate to delimit windows for incremental collapse.
    cmd.arg("-n")
        .arg("tick-25ms { printa(@); printf(\"__RT_END__\\n\"); trunc(@); }");

    match workload {
        Workload::Command(args) => {
            // Escape command into a single string for -c
            let mut escaped = String::new();
            for (i, arg) in args.iter().enumerate() {
                if i > 0 {
                    escaped.push(' ');
                }
                escaped.push_str(&arg.replace(' ', "\\ "));
            }
            cmd.arg("-c").arg(escaped);
        }
        Workload::Pid(pids) => {
            for pid in pids {
                cmd.arg("-p").arg(pid.to_string());
            }
        }
        Workload::ReadPerf(_) => unreachable!("streaming not used for ReadPerf"),
    }

    if verbose {
        println!("command {:?}", cmd);
    }

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect(arch::SPAWN_ERROR);
    let mut stdout = child
        .stdout
        .take()
        .expect("failed to capture dtrace stdout");
    let mut dtrace_stderr = child
        .stderr
        .take()
        .expect("failed to capture dtrace stderr");
    let stderr_handle = std::thread::spawn(move || -> String {
        let mut buf = String::new();
        let _ = std::io::Read::read_to_string(&mut dtrace_stderr, &mut buf);
        buf
    });

    // Stream-collapse DTrace output in windows delimited by the sentinel string.
    let sentinel: &[u8] = b"__RT_END__\n";
    let mut collapsed_sink = Vec::<u8>::new();
    let mut buf: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut tmp = [0u8; 8192];

    loop {
        match std::io::Read::read(&mut stdout, &mut tmp) {
            Ok(0) => break, // EOF
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let stderr_text = stderr_handle.join().unwrap_or_default();
                return Err(anyhow!(
                    "error reading dtrace stdout: {}\n{}",
                    e,
                    stderr_text
                ));
            }
        }

        // Process all complete windows in the buffer
        loop {
            // Find sentinel position
            let mut found = None;
            if buf.len() >= sentinel.len() {
                for i in 0..=buf.len() - sentinel.len() {
                    if &buf[i..i + sentinel.len()] == sentinel {
                        found = Some(i);
                        break;
                    }
                }
            }
            let Some(pos) = found else { break };

            // Take the window up to the sentinel (exclusive)
            let window: Vec<u8> = buf.drain(..pos).collect();
            // Remove the sentinel itself
            let _ = buf.drain(..sentinel.len());

            if window.is_empty() {
                continue;
            }

            // Collapse this window using inferno's DTrace folder
            let d_opts = DtraceCollapseOptions::default();
            let mut folder = DtraceFolder::from(d_opts);
            let mut folded = Vec::<u8>::new();
            if let Err(err) = folder.collapse(BufReader::new(Cursor::new(window)), &mut folded) {
                eprintln!("warning: collapse error for dtrace window: {}", err);
                continue;
            }

            // Demangle folded lines, pick the deepest function present in all samples
            // in this window (the "stem" the program spent the whole time in),
            // and emit a single real-time activity event.
            let demangled = demangle_folded(&folded);
            if let Some((stem, count)) = stem_spanning_entire_window(&demangled) {
                on_function_activity(&stem, count);
            }
            // Accumulate for final SVG
            collapsed_sink.extend_from_slice(&demangled);
        }
    }

    let status = child.wait().expect(arch::WAIT_ERROR);
    let stderr_text = stderr_handle.join().unwrap_or_default();
    if !ignore_status && terminated_by_error(status) {
        if stderr_text.trim().is_empty() {
            bail!("dtrace exited with error: {:?}", status);
        } else {
            bail!("dtrace exited with error: {:?}: {}", status, stderr_text);
        }
    }

    Ok(collapsed_sink)
}

#[cfg(target_os = "macos")]
fn macos_base_dtrace_command(sudo: Option<Option<&str>>) -> Command {
    // Run dtrace in native arch to avoid Rosetta issues
    let mut command = sudo_command("arch", sudo);
    #[cfg(target_pointer_width = "64")]
    command.arg("-64");
    #[cfg(target_pointer_width = "32")]
    command.arg("-32");
    command.arg(env::var("DTRACE").unwrap_or_else(|_| "dtrace".to_string()));
    command
}
/// Parse the collapsed stacks (folded format) and emit per-function activity events.
/// Always enabled; currently a no-op sink so we can evolve behavior later without changing call sites.
fn sonify_collapsed_stacks(collapsed: &[u8]) {
    use std::borrow::Cow;

    let text: Cow<str> = match std::str::from_utf8(collapsed) {
        Ok(s) => Cow::from(s),
        Err(_) => String::from_utf8_lossy(collapsed),
    };

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Folded format: f1;f2;...;fN COUNT
        let (stack, count_str) = match line.rsplit_once(' ') {
            Some(parts) => parts,
            None => continue,
        };

        let count: u64 = count_str.parse().unwrap_or(1);

        let leaf = match stack.rsplit_once(';') {
            Some((_, leaf)) => leaf,
            None => stack,
        };

        on_function_activity(leaf, count);
    }
}

/// From a chunk of folded lines (one window), select the hottest leaf function and its count.
/// Returns None if no valid folded lines are present.
fn hottest_leaf_in_folded_window(bytes: &[u8]) -> Option<(String, u64)> {
    let mut best_fn: Option<String> = None;
    let mut best_count: u64 = 0;
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        // Expect: f1;f2;...;leaf COUNT
        let s = match std::str::from_utf8(line) {
            Ok(s) => s.trim_end(),
            Err(_) => continue,
        };
        let (stack, count_str) = match s.rsplit_once(' ') {
            Some(t) => t,
            None => continue,
        };
        let count: u64 = count_str.parse().unwrap_or(1);
        let leaf = match stack.rsplit_once(';') {
            Some((_, leaf)) => leaf,
            None => stack,
        };
        if count > best_count {
            best_count = count;
            best_fn = Some(leaf.to_string());
        }
    }
    best_fn.map(|f| (f, best_count))
}

/// From a chunk of folded lines (one window), compute the deepest frame that appears in all
/// stacks (longest common prefix by frames) and return that frame with the total sample count
/// across the window. If no common frame exists, returns None.
fn stem_spanning_entire_window(bytes: &[u8]) -> Option<(String, u64)> {
    let mut common_prefix: Vec<String> = Vec::new();
    let mut total_count: u64 = 0;
    let mut initialized = false;

    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let s = match std::str::from_utf8(line) {
            Ok(s) => s.trim_end(),
            Err(_) => continue,
        };
        let (stack_str, count_str) = match s.rsplit_once(' ') {
            Some(t) => t,
            None => continue,
        };
        let count: u64 = count_str.parse().unwrap_or(1);
        total_count = total_count.saturating_add(count);

        // Split stack into frames from root to leaf
        let frames: Vec<&str> = stack_str.split(';').collect();
        if !initialized {
            common_prefix = frames.iter().map(|f| f.to_string()).collect();
            initialized = true;
        } else {
            let max = common_prefix.len().min(frames.len());
            let mut new_len = 0;
            while new_len < max && common_prefix[new_len] == frames[new_len] {
                new_len += 1;
            }
            common_prefix.truncate(new_len);
            if common_prefix.is_empty() {
                // Early out: no shared frame across all samples
                // We can still return None; but continue to sum counts for consistency
                // and break to save work.
                // break; // keep scanning to consume input; not strictly necessary
            }
        }
    }

    if initialized && !common_prefix.is_empty() {
        let stem = common_prefix.pop().unwrap();
        Some((stem, total_count))
    } else {
        None
    }
}

/// Stub for future sound generation. Currently does nothing.
/// `function` is the leaf frame symbol, `count` is the sample count for that leaf in this line.
fn on_function_activity(func: &str, _count: u64) {
    // Hook for future sound generation.
    // Intentionally no stdout printing to keep real-time output quiet.
    println!("name: {}", func);
}

#[derive(Debug, Args)]
pub struct Options {
    /// Print extra output to help debug problems
    #[clap(short, long)]
    pub verbose: bool,

    /// Output file
    #[clap(short, long, default_value = "flamegraph.svg")]
    output: PathBuf,

    /// Open the output .svg file with default program
    #[clap(long)]
    open: bool,

    /// Run with root privileges (using `sudo`). Accepts an optional argument containing command line options which will be passed to sudo
    #[clap(long, value_name = "SUDO FLAGS")]
    pub root: Option<Option<String>>,

    /// Sampling frequency in Hz [default: 997]
    #[clap(short = 'F', long = "freq")]
    frequency: Option<u32>,

    /// Custom command for invoking perf/dtrace
    #[clap(short, long = "cmd")]
    custom_cmd: Option<String>,

    #[clap(flatten)]
    flamegraph_options: FlamegraphOptions,

    /// Ignores perf's exit code
    #[clap(long)]
    ignore_status: bool,

    /// Disable inlining for perf script because of performance issues
    #[clap(long = "no-inline")]
    script_no_inline: bool,

    /// Run a command to process the folded stacks, taking the input from stdin and outputting to
    /// stdout.
    #[clap(long)]
    post_process: Option<String>,
}

impl Options {
    pub fn check(&self) -> anyhow::Result<()> {
        // Manually checking conflict because structopts `conflicts_with` leads
        // to a panic in completion generation for zsh at the moment (see #158)
        match self.frequency.is_some() && self.custom_cmd.is_some() {
            true => Err(anyhow!(
                "Cannot pass both a custom command and a frequency."
            )),
            false => Ok(()),
        }
    }

    pub fn frequency(&self) -> u32 {
        // Use a higher default sampling frequency for more responsiveness.
        // Users can still override via -F/--freq.
        self.frequency.unwrap_or(1997)
    }
}

#[derive(Debug, Args)]
pub struct FlamegraphOptions {
    /// Set title text in SVG
    #[clap(long, value_name = "STRING")]
    pub title: Option<String>,

    /// Set second level title text in SVG
    #[clap(long, value_name = "STRING")]
    pub subtitle: Option<String>,

    /// Colors are selected such that the color of a function does not change between runs
    #[clap(long)]
    pub deterministic: bool,

    /// Plot the flame graph up-side-down
    #[clap(short, long)]
    pub inverted: bool,

    /// Generate stack-reversed flame graph
    #[clap(long)]
    pub reverse: bool,

    /// Set embedded notes in SVG
    #[clap(long, value_name = "STRING")]
    pub notes: Option<String>,

    /// Omit functions smaller than <FLOAT> pixels
    #[clap(long, default_value = "0.01", value_name = "FLOAT")]
    pub min_width: f64,

    /// Image width in pixels
    #[clap(long)]
    pub image_width: Option<usize>,

    /// Color palette
    #[clap(
        long,
        value_parser = PossibleValuesParser::new(Palette::VARIANTS).map(|s| Palette::from_str(&s).unwrap())
    )]
    pub palette: Option<Palette>,

    /// Cut off stack frames below <FUNCTION>; may be repeated
    #[cfg(target_os = "linux")]
    #[clap(long, value_name = "FUNCTION")]
    pub skip_after: Vec<String>,

    /// Produce a flame chart (sort by time, do not merge stacks)
    #[clap(long = "flamechart", conflicts_with = "reverse")]
    pub flame_chart: bool,
}

impl FlamegraphOptions {
    pub fn into_inferno(self) -> inferno::flamegraph::Options<'static> {
        let mut options = inferno::flamegraph::Options::default();
        if let Some(title) = self.title {
            options.title = title;
        }
        options.subtitle = self.subtitle;
        options.deterministic = self.deterministic;
        if self.inverted {
            options.direction = inferno::flamegraph::Direction::Inverted;
        }
        options.reverse_stack_order = self.reverse;
        options.notes = self.notes.unwrap_or_default();
        options.min_width = self.min_width;
        options.image_width = self.image_width;
        if let Some(palette) = self.palette {
            options.colors = palette;
        }
        options.flame_chart = self.flame_chart;

        options
    }
}
