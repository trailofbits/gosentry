use clap::{Parser, Subcommand};
use libafl::{
    corpus::{CachedOnDiskCorpus, Corpus, CorpusId, OnDiskCorpus, Testcase},
    events::{
        Event, EventFirer, EventManagerHook, EventWithStats, LlmpRestartingEventManager,
        ProgressReporter, SendExiting, ShouldSaveState,
    },
    executors::{inprocess::InProcessExecutor, ExitKind, ShadowExecutor},
    feedback_or_fast,
    feedbacks::{
        CrashFeedback, DifferentIsNovel, Feedback, MapFeedback, MaxMapFeedback, StateInitializer,
    },
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    mutators::scheduled::HavocScheduledMutator,
    prelude::{
        havoc_mutations, powersched::PowerSchedule, tokens_mutations, CalibrationStage, CanTrack,
        ClientDescription, EventConfig, GitAwareStdWeightedScheduler, GitRecencyMapMetadata,
        GitRecencyConfigMetadata, I2SRandReplace, IndexesLenTimeMinimizerScheduler, Launcher,
        MultiMapObserver, RandBytesGenerator, SimpleMonitor, StdMOptMutator, StdMapObserver,
        TimeFeedback, TimeObserver, Tokens, TuiMonitor,
    },
    stages::{mutational::StdMutationalStage, ShadowTracingStage, StdPowerMutationalStage},
    state::{HasCorpus, HasExecutions, HasSolutions, StdState, Stoppable},
    schedulers::Scheduler,
    Error, HasMetadata,
};
use libafl_bolts::{
    prelude::{Cores, StdShMemProvider},
    rands::StdRand,
    shmem::ShMemProvider,
    simd::MaxReducer,
    tuples::{tuple_list, MatchName, Merge},
    ClientId,
};
use libafl_targets::{
    autotokens, extra_counters, libfuzzer::libfuzzer_test_one_input, libfuzzer_initialize,
    CmpLogObserver, COUNTERS_MAPS,
};
use mimalloc::MiMalloc;
use serde::{Deserialize, Serialize};
use std::panic;
use std::{
    collections::{HashMap, HashSet},
    env, fs,
    fs::read_dir,
    io::{BufRead, BufReader, BufWriter, IsTerminal, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc, Arc, Mutex,
};

use object::{Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind};

type NonSimdMaxMapFeedback<C, O> = MapFeedback<C, DifferentIsNovel, O, MaxReducer>;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Copy, Clone, Debug)]
struct StopOnObjectiveHook {
    enabled: bool,
}

impl<I, S> EventManagerHook<I, S> for StopOnObjectiveHook
where
    S: Stoppable,
{
    fn pre_receive(
        &mut self,
        state: &mut S,
        _client_id: ClientId,
        event: &EventWithStats<I>,
    ) -> Result<bool, Error> {
        // `go test -fuzz` semantics: stop the whole fuzz run once a crash is found.
        if self.enabled && matches!(event.event(), Event::Objective { .. }) {
            state.request_stop();
        }
        Ok(true)
    }
}

#[derive(Debug, Clone)]
struct EnsureTestcaseIdsScheduler<Inner> {
    inner: Inner,
}

impl<Inner> EnsureTestcaseIdsScheduler<Inner> {
    fn new(inner: Inner) -> Self {
        Self { inner }
    }
}

impl<I, S, Inner> Scheduler<I, S> for EnsureTestcaseIdsScheduler<Inner>
where
    Inner: Scheduler<I, S>,
    S: HasCorpus<I>,
{
    fn on_add(&mut self, state: &mut S, id: CorpusId) -> Result<(), Error> {
        {
            let mut testcase = state.corpus().get(id)?.borrow_mut();
            testcase.set_corpus_id(Some(id));
        }
        self.inner.on_add(state, id)
    }

    fn on_evaluation<OT>(
        &mut self,
        state: &mut S,
        input: &I,
        observers: &OT,
    ) -> Result<(), Error>
    where
        OT: MatchName,
    {
        self.inner.on_evaluation(state, input, observers)
    }

    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        self.inner.next(state)
    }

    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<CorpusId>,
    ) -> Result<(), Error> {
        self.inner.set_current_scheduled(state, next_id)
    }
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct LibAflFuzzConfig {
    cores: Option<String>,
    exec_timeout_ms: Option<u64>,
    catch_hangs: Option<bool>,
    hang_timeout_ms: Option<u64>,
    hang_confirm_runs: Option<usize>,
    stop_all_fuzzers_on_panic: Option<bool>,
    power_schedule: Option<String>,
    git_recency_alpha: Option<f64>,
    corpus_cache_size: Option<usize>,
    initial_generated_inputs: Option<usize>,
    initial_input_max_len: Option<usize>,
    go_maxprocs_single: Option<bool>,
    tui_monitor: Option<bool>,
    debug_output: Option<bool>,
    grammar_actions: Option<bool>,
    grammarinator_dir: Option<PathBuf>,
    grammar_max_depth: Option<usize>,
    grammar_max_tokens: Option<usize>,
}

#[derive(Debug, Clone)]
struct GrammarinatorConfig {
    grammar: Vec<PathBuf>,
    start_rule: String,
    actions: bool,
    serializer: Option<String>,
    grammarinator_dir: Option<PathBuf>,
    max_depth: usize,
    max_tokens: usize,
}

const GRAMMARINATOR_SERVER_PY: &str = r#"#!/usr/bin/env python3
import argparse
import importlib
import json
import logging
import shutil
import sys
import traceback
from collections import OrderedDict
from copy import deepcopy
from pathlib import Path


def import_object(path: str):
    mod_name, _, attr = path.rpartition(".")
    if not mod_name or not attr:
        raise ValueError(f"invalid python ref: {path!r} (expected package.module.attr)")
    mod = importlib.import_module(mod_name)
    return getattr(mod, attr)


def main() -> int:
    # Grammarinator can emit parse warnings for invalid candidates during
    # mutation. In gosentry we treat these as expected and retry silently.
    logging.getLogger().setLevel(logging.ERROR)

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="output dir for generated python generator")
    ap.add_argument("--grammar", action="append", required=True, help="ANTLRv4 .g4 grammar file (repeatable)")
    ap.add_argument("--start-rule", required=True, help="start rule name")
    ap.add_argument("--actions", action="store_true", help="allow inline actions/predicates in grammar")
    ap.add_argument(
        "--serializer",
        default="grammarinator.runtime.simple_space_serializer",
        help="python serializer function (package.module.function)",
    )
    ap.add_argument("--max-depth", type=int, default=32)
    ap.add_argument("--max-tokens", type=int, default=512)
    args = ap.parse_args()

    out_dir = Path(args.out)
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    from grammarinator.tool import ProcessorTool

    ProcessorTool("py", str(out_dir)).process(
        args.grammar,
        options={},
        default_rule=args.start_rule,
        encoding="utf-8",
        errors="strict",
        lib_dir=None,
        actions=args.actions,
        pep8=False,
    )

    gen_files = sorted(out_dir.glob("*Generator.py"))
    if not gen_files:
        raise RuntimeError(f"no *Generator.py produced in {out_dir}")
    gen_mod_name = gen_files[0].stem

    sys.path.insert(0, str(out_dir))
    gen_mod = importlib.import_module(gen_mod_name)
    gen_cls = getattr(gen_mod, gen_mod_name)

    serializer = import_object(args.serializer) if args.serializer else str

    from grammarinator.runtime import RuleSize

    # Optional: keep a best-effort cache so we don't have to parse strings
    # generated by this server again when they get selected from the corpus.
    try:
        import xxhash
    except Exception:  # pragma: no cover
        xxhash = None

    # Cache parsed trees by hash(input). Keep it bounded to avoid unbounded
    # growth in long fuzz campaigns.
    CACHE_MAX = 512
    tree_cache = OrderedDict()

    def key_for(s: str) -> int:
        if xxhash is None:
            return hash(s)
        return xxhash.xxh3_64_intdigest(s.encode("utf-8"))

    def cache_get(s: str):
        key = key_for(s)
        item = tree_cache.get(key)
        if item is None:
            return None
        cached_s, cached_root = item
        if cached_s != s:
            return None
        tree_cache.move_to_end(key)
        return cached_root

    def cache_put(s: str, root):
        key = key_for(s)
        tree_cache[key] = (s, root)
        tree_cache.move_to_end(key)
        while len(tree_cache) > CACHE_MAX:
            tree_cache.popitem(last=False)

    def generate_one() -> str:
        gen = gen_cls(limit=RuleSize(depth=args.max_depth, tokens=args.max_tokens))
        root = getattr(gen, args.start_rule)()
        s = serializer(root)
        cache_put(s, root)
        return s

    parser_tool = None
    generator_tool = None

    def ensure_mutation_tools():
        nonlocal parser_tool, generator_tool
        if parser_tool is not None and generator_tool is not None:
            return

        import antlerinator
        from grammarinator.tool import GeneratorTool, ParserTool

        antlr_jar = antlerinator.download(lazy=True)

        parser_dir = out_dir / "parser"
        parser_tool = ParserTool(
            grammars=args.grammar,
            parser_dir=str(parser_dir),
            antlr=antlr_jar,
            population=None,
            rule=args.start_rule,
            hidden=None,
            transformers=None,
            max_depth=args.max_depth,
            strict=True,
            lib_dir=None,
            cleanup=False,
            encoding="utf-8",
            errors="strict",
        )

        generator_tool = GeneratorTool(
            gen_cls,
            out_format="",
            rule=args.start_rule,
            limit=RuleSize(depth=args.max_depth, tokens=args.max_tokens),
            population=None,
            keep_trees=False,
            generate=False,
            mutate=True,
            recombine=False,
            unrestricted=False,
            serializer=serializer,
            memo_size=0,
            unique_attempts=1,
            cleanup=False,
            encoding="utf-8",
            errors="strict",
            dry_run=True,
        )

    def mutate_one(s: str) -> str:
        ensure_mutation_tools()
        from antlr4 import InputStream
        from grammarinator.runtime import Individual

        def generate_valid_one() -> str:
            # Fall back to generation-from-scratch (still grammar-valid) so the
            # fuzzer can keep making progress.
            MAX_GENERATE_ATTEMPTS = 64
            for _ in range(MAX_GENERATE_ATTEMPTS):
                out = generate_one()
                parsed = parser_tool._create_tree(InputStream(out), "<generated>")
                if parsed is None:
                    continue
                cache_put(out, parsed)
                return out
            raise RuntimeError("failed to generate a valid input")

        root = cache_get(s)
        if root is None:
            root = parser_tool._create_tree(InputStream(s), "<seed>")
            if root is None:
                # Don't abort fuzzing on an unparseable corpus seed; just fall
                # back to generation so the campaign can continue.
                return generate_valid_one()
            cache_put(s, root)

        # Grammarinator mutation is best-effort and may emit invalid outputs in
        # rare cases. Validate outputs by parsing them back with the same
        # grammar and retry.
        if generator_tool is None or parser_tool is None:
            raise RuntimeError("mutation tools not initialized")

        MAX_MUTATE_ATTEMPTS = 64
        for _ in range(MAX_MUTATE_ATTEMPTS):
            mutated_root = generator_tool.mutate(Individual(deepcopy(root)))
            mutated = serializer(mutated_root)
            if mutated == s:
                return mutated

            cached = cache_get(mutated)
            if cached is not None:
                return mutated

            parsed = parser_tool._create_tree(InputStream(mutated), "<mutated>")
            if parsed is None:
                continue
            cache_put(mutated, parsed)
            return mutated

        return generate_valid_one()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        req = json.loads(line)
        op = req.get("op")
        if op == "generate":
            s = generate_one()
            sys.stdout.write(json.dumps(s, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue
        if op == "mutate":
            src = req.get("input")
            if not isinstance(src, str):
                raise ValueError("mutate request missing string 'input'")
            out = mutate_one(src)
            sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue

        raise ValueError(f"unknown request op: {op!r}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc(file=sys.stderr)
        raise
"#;

struct GrammarinatorEngine {
    child: std::process::Child,
    stdin: BufWriter<std::process::ChildStdin>,
    stdout: BufReader<std::process::ChildStdout>,
}

#[derive(Serialize)]
struct GrammarinatorRequest<'a> {
    op: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    input: Option<&'a str>,
}

impl GrammarinatorEngine {
    fn spawn(cfg: &GrammarinatorConfig, workdir: &Path) -> Result<Self, Error> {
        fs::create_dir_all(workdir)
            .map_err(|err| Error::os_error(err, "grammarinator: failed to create workdir"))?;

        let script_path = workdir.join("gosentry_grammarinator_server.py");
        fs::write(&script_path, GRAMMARINATOR_SERVER_PY)
            .map_err(|err| Error::os_error(err, "grammarinator: failed to write server script"))?;

        let out_dir = workdir.join("out");
        if out_dir.exists() {
            let _ = fs::remove_dir_all(&out_dir);
        }

        let mut cmd = Command::new("python3");
        cmd.arg(&script_path)
            .arg("--out")
            .arg(&out_dir)
            .arg("--start-rule")
            .arg(&cfg.start_rule)
            .arg("--max-depth")
            .arg(cfg.max_depth.to_string())
            .arg("--max-tokens")
            .arg(cfg.max_tokens.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .env("PYTHONUNBUFFERED", "1")
            .env("PYTHONIOENCODING", "utf-8");

        if cfg.actions {
            cmd.arg("--actions");
        }
        if let Some(serializer) = cfg.serializer.as_ref() {
            cmd.arg("--serializer").arg(serializer);
        }
        for g in cfg.grammar.iter() {
            cmd.arg("--grammar").arg(g);
        }

        if let Some(dir) = cfg.grammarinator_dir.as_ref() {
            let mut paths = vec![dir.clone()];
            if let Some(old) = env::var_os("PYTHONPATH") {
                paths.extend(env::split_paths(&old));
            }
            let joined = env::join_paths(paths.iter())
                .map_err(|_| Error::illegal_argument("grammarinator: invalid PYTHONPATH"))?;
            cmd.env("PYTHONPATH", joined);
        }

        let mut child = cmd
            .spawn()
            .map_err(|err| Error::os_error(err, "grammarinator: failed to spawn python3"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::illegal_state("grammarinator: failed to capture stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::illegal_state("grammarinator: failed to capture stdout"))?;

        Ok(Self {
            child,
            stdin: BufWriter::new(stdin),
            stdout: BufReader::new(stdout),
        })
    }

    fn request_bytes(&mut self, req: &GrammarinatorRequest<'_>) -> Result<Vec<u8>, Error> {
        let req_json = serde_json::to_string(req).map_err(|err| {
            Error::illegal_state(format!("grammarinator: failed to encode request JSON: {err}"))
        })?;
        self.stdin.write_all(req_json.as_bytes()).map_err(|err| {
            Error::os_error(err, "grammarinator: failed to write request json")
        })?;
        self.stdin.write_all(b"\n").map_err(|err| {
            Error::os_error(err, "grammarinator: failed to write request newline")
        })?;
        self.stdin.flush().map_err(|err| {
            Error::os_error(err, "grammarinator: failed to flush request")
        })?;

        let mut line = String::new();
        let n = self
            .stdout
            .read_line(&mut line)
            .map_err(|err| Error::os_error(err, "grammarinator: failed to read response"))?;
        if n == 0 {
            let status = self.child.try_wait().ok().flatten();
            let msg = match status {
                Some(s) => format!("grammarinator: server exited ({s})"),
                None => "grammarinator: server closed stdout".to_string(),
            };
            return Err(Error::illegal_state(msg));
        }

        let s: String = serde_json::from_str(line.trim_end()).map_err(|err| {
            Error::illegal_state(format!(
                "grammarinator: invalid response JSON: {err} (line={line:?})"
            ))
        })?;
        Ok(s.into_bytes())
    }

    fn generate_bytes(&mut self) -> Result<Vec<u8>, Error> {
        self.request_bytes(&GrammarinatorRequest {
            op: "generate",
            input: None,
        })
    }

    fn mutate_bytes(&mut self, input: &BytesInput) -> Result<Vec<u8>, Error> {
        let target = input.target_bytes();
        let s = std::str::from_utf8(target.as_ref()).map_err(|_| {
            Error::illegal_argument(
                "grammarinator: input is not valid UTF-8 (grammar fuzzing currently expects UTF-8 text inputs)",
            )
        })?;
        self.request_bytes(&GrammarinatorRequest {
            op: "mutate",
            input: Some(s),
        })
    }
}

impl Drop for GrammarinatorEngine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Clone)]
struct GrammarinatorGenerator {
    engine: Arc<Mutex<GrammarinatorEngine>>,
}

impl GrammarinatorGenerator {
    fn new(engine: Arc<Mutex<GrammarinatorEngine>>) -> Self {
        Self { engine }
    }
}

impl<S> libafl::generators::Generator<BytesInput, S> for GrammarinatorGenerator {
    fn generate(&mut self, _state: &mut S) -> Result<BytesInput, Error> {
        let mut eng = self
            .engine
            .lock()
            .map_err(|_| Error::illegal_state("grammarinator: engine lock poisoned"))?;
        let bytes = eng.generate_bytes()?;
        Ok(BytesInput::new(bytes))
    }
}

#[derive(Clone)]
struct GrammarinatorMutator {
    engine: Arc<Mutex<GrammarinatorEngine>>,
}

impl GrammarinatorMutator {
    fn new(engine: Arc<Mutex<GrammarinatorEngine>>) -> Self {
        Self { engine }
    }
}

impl libafl_bolts::Named for GrammarinatorMutator {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Borrowed("GrammarinatorMutator");
        &NAME
    }
}

impl<S> libafl::mutators::Mutator<BytesInput, S> for GrammarinatorMutator {
    fn mutate(&mut self, _state: &mut S, input: &mut BytesInput) -> Result<libafl::mutators::MutationResult, Error> {
        let mut eng = self
            .engine
            .lock()
            .map_err(|_| Error::illegal_state("grammarinator: engine lock poisoned"))?;
        let bytes = eng.mutate_bytes(input)?;
        *input = BytesInput::new(bytes);
        Ok(libafl::mutators::MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct CrashAndHangObjective {
    crash: CrashFeedback,
    catch_hangs: bool,
    timeout_candidate_path: PathBuf,
}

impl CrashAndHangObjective {
    fn new(catch_hangs: bool, timeout_candidate_path: PathBuf) -> Self {
        Self {
            crash: CrashFeedback::new(),
            catch_hangs,
            timeout_candidate_path,
        }
    }
}

impl<S> StateInitializer<S> for CrashAndHangObjective {}

impl libafl_bolts::Named for CrashAndHangObjective {
    fn name(&self) -> &std::borrow::Cow<'static, str> {
        static NAME: std::borrow::Cow<'static, str> =
            std::borrow::Cow::Borrowed("CrashAndHangObjective");
        &NAME
    }
}

impl<EM, OT, S> Feedback<EM, BytesInput, OT, S> for CrashAndHangObjective {
    fn is_interesting(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &BytesInput,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        if self.catch_hangs && matches!(exit_kind, ExitKind::Timeout) {
            let bytes = input.target_bytes();
            write_atomic_bytes_best_effort(&self.timeout_candidate_path, bytes.as_ref());
            return Ok(false);
        }

        self.crash
            .is_interesting(state, manager, input, observers, exit_kind)
    }

    fn append_metadata(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<BytesInput>,
    ) -> Result<(), Error> {
        self.crash
            .append_metadata(state, manager, observers, testcase)
    }
}

fn write_atomic_bytes_best_effort(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    if fs::write(&tmp, bytes).is_ok() {
        let _ = fs::rename(&tmp, path);
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum RunOnceOutcome {
    Ok,
    Crash,
    Timeout,
}

fn run_once_with_timeout(exe: &Path, input: &Path, timeout: Duration) -> RunOnceOutcome {
    let mut child = Command::new(exe)
        .args(["run", "--input"])
        .arg(input)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|err| {
            eprintln!("golibafl: failed to spawn {}: {err}", exe.display());
            std::process::exit(2);
        });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    RunOnceOutcome::Ok
                } else {
                    RunOnceOutcome::Crash
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return RunOnceOutcome::Timeout;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return RunOnceOutcome::Crash;
            }
        }
    }
}

#[derive(Debug, Clone)]
enum TimeoutCandidateVerdict {
    NotHang,
    Hang(PathBuf),
    Crash(PathBuf),
}

fn confirm_timeout_candidate(
    exe: &Path,
    candidate: &Path,
    hang_timeout: Duration,
    hang_confirm_runs: usize,
    hangs_dir: &Path,
    crashes_dir: &Path,
    client_id: &str,
) -> TimeoutCandidateVerdict {
    let mut saw_crash = false;
    for _ in 0..hang_confirm_runs {
        match run_once_with_timeout(exe, candidate, hang_timeout) {
            RunOnceOutcome::Ok => {
                let _ = fs::remove_file(candidate);
                return TimeoutCandidateVerdict::NotHang;
            }
            RunOnceOutcome::Crash => {
                saw_crash = true;
                break;
            }
            RunOnceOutcome::Timeout => (),
        }
    }

    fn move_file_best_effort(src: &Path, dst: &Path) {
        if fs::rename(src, dst).is_ok() {
            return;
        }
        if fs::copy(src, dst).is_ok() {
            let _ = fs::remove_file(src);
        }
    }

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    if saw_crash {
        let _ = fs::create_dir_all(crashes_dir);
        let dst = crashes_dir.join(format!("timeout-confirmed-crash-{ts}-client{client_id}.bin"));
        move_file_best_effort(candidate, &dst);
        return TimeoutCandidateVerdict::Crash(dst);
    }

    let _ = fs::create_dir_all(hangs_dir);
    let dst = hangs_dir.join(format!("hang-{ts}-client{client_id}.bin"));
    move_file_best_effort(candidate, &dst);
    TimeoutCandidateVerdict::Hang(dst)
}

fn launch_diagnostics(err: &Error) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let _ = writeln!(&mut out, "golibafl: launcher failure diagnostics:");
    let _ = writeln!(&mut out, "  err={err:?}");
    if let Error::OsError(io_err, msg, _) = err {
        let _ = writeln!(
            &mut out,
            "  os_error kind={:?} raw_os_error={:?} msg={msg:?}",
            io_err.kind(),
            io_err.raw_os_error(),
        );
    }
    let _ = writeln!(
        &mut out,
        "  AFL_LAUNCHER_CLIENT={:?}",
        env::var_os("AFL_LAUNCHER_CLIENT")
    );
    let _ = writeln!(&mut out, "  PWD={:?}", env::var_os("PWD"));
    let _ = writeln!(&mut out, "  argv={:?}", env::args().collect::<Vec<_>>());

    match env::current_dir() {
        Ok(cwd) => {
            let _ = writeln!(&mut out, "  current_dir={}", cwd.display());
            let _ = writeln!(&mut out, "  current_dir_exists={}", cwd.exists());
        }
        Err(e) => {
            let _ = writeln!(&mut out, "  current_dir_err={e}");
        }
    }

    match env::current_exe() {
        Ok(exe) => {
            let _ = writeln!(&mut out, "  current_exe={}", exe.display());
            let _ = writeln!(&mut out, "  current_exe_exists={}", exe.exists());
        }
        Err(e) => {
            let _ = writeln!(&mut out, "  current_exe_err={e}");
        }
    }

    #[cfg(target_os = "linux")]
    {
        match fs::read_link("/proc/self/exe") {
            Ok(link) => {
                let _ = writeln!(&mut out, "  /proc/self/exe={}", link.display());
            }
            Err(e) => {
                let _ = writeln!(&mut out, "  /proc/self/exe_err={e}");
            }
        }
        match fs::read_link("/proc/self/cwd") {
            Ok(link) => {
                let _ = writeln!(&mut out, "  /proc/self/cwd={}", link.display());
            }
            Err(e) => {
                let _ = writeln!(&mut out, "  /proc/self/cwd_err={e}");
            }
        }
    }

    let _ = writeln!(
        &mut out,
        "  LD_LIBRARY_PATH={:?}",
        env::var_os("LD_LIBRARY_PATH")
    );
    let _ = writeln!(
        &mut out,
        "  HARNESS_LINK_SEARCH={:?}",
        env::var_os("HARNESS_LINK_SEARCH")
    );
    let _ = writeln!(
        &mut out,
        "  HARNESS_LINK_LIBS={:?}",
        env::var_os("HARNESS_LINK_LIBS")
    );

    out
}

fn strip_jsonc_comments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escape = false;

    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => escape = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            '/' => match chars.peek() {
                Some('/') => {
                    // Line comment: keep the newline so error line numbers are still useful.
                    chars.next();
                    while let Some(next) = chars.next() {
                        if next == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                }
                Some('*') => {
                    // Block comment: keep any newlines for better diagnostics.
                    chars.next();
                    let mut prev = '\0';
                    while let Some(next) = chars.next() {
                        if prev == '*' && next == '/' {
                            break;
                        }
                        if next == '\n' {
                            out.push('\n');
                        }
                        prev = next;
                    }
                }
                _ => out.push(ch),
            },
            _ => out.push(ch),
        }
    }

    out
}

fn strip_trailing_commas(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    let mut escape = false;

    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escape {
                escape = false;
                continue;
            }
            match ch {
                '\\' => escape = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                out.push(ch);
            }
            ',' => {
                let mut lookahead = chars.clone();
                while let Some(next) = lookahead.peek().copied() {
                    if next.is_whitespace() {
                        lookahead.next();
                        continue;
                    }
                    if next == '}' || next == ']' {
                        // Trailing comma, ignore.
                    } else {
                        out.push(ch);
                    }
                    break;
                }
                if lookahead.peek().is_none() {
                    out.push(ch);
                }
            }
            _ => out.push(ch),
        }
    }

    out
}

fn read_fuzz_config(path: &Path) -> LibAflFuzzConfig {
    let contents = fs::read_to_string(path).unwrap_or_else(|err| {
        eprintln!("golibafl: failed to read config {}: {err}", path.display());
        std::process::exit(2);
    });
    let json = strip_trailing_commas(&strip_jsonc_comments(&contents));
    serde_json::from_str(&json).unwrap_or_else(|err| {
        eprintln!("golibafl: invalid JSONC config {}: {err}", path.display());
        std::process::exit(2);
    })
}

fn cores_ids_csv(cores: &Cores) -> String {
    cores
        .ids
        .iter()
        .map(|id| id.0.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

const GOLIBAFL_BROKER_PORT_ENV: &str = "GOLIBAFL_BROKER_PORT";
const GOLIBAFL_FOCUS_ON_NEW_CODE_ENV: &str = "GOLIBAFL_FOCUS_ON_NEW_CODE";
const GOLIBAFL_TARGET_DIR_ENV: &str = "GOLIBAFL_TARGET_DIR";
const LIBAFL_GIT_RECENCY_MAPPING_ENV: &str = "LIBAFL_GIT_RECENCY_MAPPING_PATH";

fn notify_restarting_mgr_exit() {
    // When running under LibAFL's restarting manager in exec mode, exiting the child process
    // without writing the StateRestorer page causes the parent to panic.
    //
    // Best-effort mark the parent as "do not respawn" before exiting.
    if env::var_os(libafl::events::restarting::_ENV_FUZZER_SENDER).is_none() {
        return;
    }

    // This is best-effort, and should never block process shutdown (especially in CI).
    // Some shared memory providers may wedge when the broker is already shutting down.
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        let Ok(mut shmem_provider) = StdShMemProvider::new() else {
            let _ = tx.send(());
            return;
        };

        if let Ok(mut staterestorer) = libafl_bolts::staterestore::StateRestorer::from_env(
            &mut shmem_provider,
            libafl::events::restarting::_ENV_FUZZER_SENDER,
        ) {
            staterestorer.send_exiting();
        }

        let _ = tx.send(());
    });
    let _ = rx.recv_timeout(Duration::from_millis(200));
}

fn resolve_broker_port(broker_port: Option<u16>) -> u16 {
    if let Some(port) = broker_port {
        return port;
    }

    match env::var(GOLIBAFL_BROKER_PORT_ENV) {
        Ok(val) => {
            return val.parse::<u16>().unwrap_or_else(|_| {
                eprintln!("golibafl: invalid {GOLIBAFL_BROKER_PORT_ENV}={val} (expected a TCP port number)");
                std::process::exit(2);
            });
        }
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => {
            eprintln!("golibafl: {GOLIBAFL_BROKER_PORT_ENV} must be valid unicode");
            std::process::exit(2);
        }
    }

    let port = TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|addr| addr.port())
        .unwrap_or_else(|err| {
            eprintln!("golibafl: failed to pick a random broker TCP port: {err}");
            std::process::exit(2);
        });

    env::set_var(GOLIBAFL_BROKER_PORT_ENV, port.to_string());
    port
}

fn git(repo_root: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .unwrap_or_else(|err| {
            eprintln!("golibafl: failed to run git: {err}");
            std::process::exit(2);
        })
}

fn repo_root(target_dir: &Path) -> PathBuf {
    let out = git(target_dir, &["rev-parse", "--show-toplevel"]);
    if !out.status.success() {
        eprintln!(
            "golibafl: git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::process::exit(2);
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if root.is_empty() {
        eprintln!("golibafl: git rev-parse --show-toplevel returned empty output");
        std::process::exit(2);
    }
    PathBuf::from(root)
}

fn head_time_epoch_seconds(repo_root: &Path) -> u64 {
    let out = git(repo_root, &["show", "-s", "--format=%ct", "HEAD"]);
    if !out.status.success() {
        eprintln!(
            "golibafl: git show failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        std::process::exit(2);
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    s.parse::<u64>().unwrap_or_else(|err| {
        eprintln!("golibafl: failed to parse HEAD time '{s}': {err}");
        std::process::exit(2);
    })
}

fn read_mapping_header(path: &Path) -> Option<(u64, u64)> {
    let mut f = fs::File::open(path).ok()?;
    let mut header = [0u8; 16];
    f.read_exact(&mut header).ok()?;
    let head_time = u64::from_le_bytes(header[0..8].try_into().unwrap());
    let len = u64::from_le_bytes(header[8..16].try_into().unwrap());
    Some((head_time, len))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct GitRecencyMapSidecar {
    version: u32,
    go_o_hash_fnv1a64: u64,
    counters_len: u64,
}

fn git_recency_map_sidecar_path(mapping_path: &Path) -> PathBuf {
    mapping_path.with_extension("bin.meta.json")
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 14695981039346656037;
    const PRIME: u64 = 1099511628211;
    let mut hash = OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn read_git_recency_map_sidecar(path: &Path) -> Option<GitRecencyMapSidecar> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_atomic_bytes(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!(
                "golibafl: failed to create directory {}: {err}",
                parent.display()
            );
            std::process::exit(2);
        }
    }

    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, bytes).unwrap_or_else(|err| {
        eprintln!("golibafl: failed to write {}: {err}", tmp.display());
        std::process::exit(2);
    });
    fs::rename(&tmp, path).unwrap_or_else(|err| {
        eprintln!(
            "golibafl: failed to rename {} to {}: {err}",
            tmp.display(),
            path.display()
        );
        std::process::exit(2);
    });
}

fn is_header_line(line: &str) -> bool {
    let mut it = line.split_whitespace();
    let Some(hash) = it.next() else {
        return false;
    };
    let Some(orig_line) = it.next() else {
        return false;
    };
    let Some(final_line) = it.next() else {
        return false;
    };

    if !hash.chars().all(|c| c == '^' || c.is_ascii_hexdigit()) {
        return false;
    }
    if orig_line.parse::<u32>().is_err() {
        return false;
    }
    if final_line.parse::<u32>().is_err() {
        return false;
    }
    true
}

fn blame_times_for_lines(
    repo_root: &Path,
    file_rel: &str,
    needed_lines: &HashSet<u32>,
) -> HashMap<u32, u64> {
    let (min_line, max_line) = needed_lines
        .iter()
        .fold((u32::MAX, 0u32), |acc, &v| (acc.0.min(v), acc.1.max(v)));
    if min_line == u32::MAX || max_line == 0 {
        return HashMap::new();
    }

    let range = format!("{min_line},{max_line}");
    let out = git(
        repo_root,
        &["blame", "--line-porcelain", "-L", &range, "--", file_rel],
    );
    if !out.status.success() {
        // Treat failures as "unknown/old".
        return HashMap::new();
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut res: HashMap<u32, u64> = HashMap::new();

    let mut current_final_line: Option<u32> = None;
    let mut current_committer_time: Option<u64> = None;

    for line in text.lines() {
        if current_final_line.is_none() && is_header_line(line) {
            let mut it = line.split_whitespace();
            let _hash = it.next().unwrap();
            let _orig = it.next().unwrap();
            let final_line = it.next().unwrap();
            current_final_line = final_line.parse::<u32>().ok();
            current_committer_time = None;
            continue;
        }

        if let Some(rest) = line.strip_prefix("committer-time ") {
            current_committer_time = rest.trim().parse::<u64>().ok();
            continue;
        }

        if line.starts_with('\t') {
            if let (Some(final_line), Some(time)) = (current_final_line, current_committer_time) {
                if needed_lines.contains(&final_line) {
                    res.insert(final_line, time);
                }
            }
            current_final_line = None;
            current_committer_time = None;
        }
    }

    res
}

fn extract_go_o_from_harness(harness_lib: &Path) -> Vec<u8> {
    let out = Command::new("ar")
        .arg("p")
        .arg(harness_lib)
        .arg("go.o")
        .output()
        .unwrap_or_else(|err| {
            eprintln!("golibafl: failed to run ar: {err}");
            std::process::exit(2);
        });
    if !out.status.success() {
        eprintln!(
            "golibafl: failed to extract go.o from {}",
            harness_lib.display()
        );
        std::process::exit(2);
    }
    out.stdout
}

fn go_tool_locations_worker(
    go_bin: &str,
    obj_path: &Path,
    addrs: Vec<u64>,
    sent_counter: Arc<AtomicUsize>,
    received_counter: Arc<AtomicUsize>,
) -> HashMap<u64, (String, u32)> {
    if addrs.is_empty() {
        return HashMap::new();
    }

    let addrs = Arc::new(addrs);

    let mut child = Command::new(go_bin)
        .args(["tool", "addr2line"])
        .arg(obj_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| {
            eprintln!("golibafl: failed to run '{go_bin} tool addr2line': {err}");
            std::process::exit(2);
        });

    let mut stderr = child.stderr.take().unwrap();
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stdout = std::io::BufReader::new(stdout);

    // Drain stdout while feeding stdin: `go tool addr2line` may start emitting output
    // before stdin is fully closed (buffer flushes), and stdout backpressure can
    // block further stdin reads.
    let addrs_reader = Arc::clone(&addrs);
    let received_counter_reader = Arc::clone(&received_counter);
    let stdout_thread = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut res: HashMap<u64, (String, u32)> = HashMap::new();
        let mut idx = 0usize;
        while idx < addrs_reader.len() {
            let mut _fn_line = String::new();
            let n = stdout.read_line(&mut _fn_line).unwrap_or(0);
            if n == 0 {
                break;
            }

            let mut loc_line = String::new();
            let n = stdout.read_line(&mut loc_line).unwrap_or(0);
            if n == 0 {
                break;
            }
            received_counter_reader.fetch_add(1, Ordering::Relaxed);

            let addr = addrs_reader[idx];
            idx += 1;

            let loc_tok = loc_line.split_whitespace().next().unwrap_or("");
            if let Some((file, line)) = loc_tok.rsplit_once(':') {
                if let Ok(line) = line.parse::<u32>() {
                    if file != "??" && line != 0 {
                        res.insert(addr, (file.to_string(), line));
                    }
                }
            }
        }
        res
    });

    for addr in addrs.iter() {
        if let Err(err) = writeln!(stdin, "0x{addr:x}") {
            eprintln!("golibafl: failed to write to go addr2line stdin: {err}");
            std::process::exit(2);
        }
        sent_counter.fetch_add(1, Ordering::Relaxed);
    }
    drop(stdin);

    let status = child.wait().unwrap_or_else(|err| {
        eprintln!("golibafl: failed to wait for go addr2line: {err}");
        std::process::exit(2);
    });
    let stderr = stderr_thread.join().unwrap_or_default();
    if !status.success() {
        eprintln!(
            "golibafl: go addr2line failed: {}",
            String::from_utf8_lossy(&stderr)
        );
        std::process::exit(2);
    }

    let res = stdout_thread.join().unwrap_or_else(|_| {
        eprintln!("golibafl: addr2line stdout reader panicked");
        std::process::exit(2);
    });
    res
}

fn go_tool_locations(obj_path: &Path, addrs: &[u64]) -> HashMap<u64, (String, u32)> {
    if addrs.is_empty() {
        return HashMap::new();
    }

    let go_bin = env::var("GO_PATH")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            env::var_os("GOROOT")
                .filter(|s| !s.is_empty())
                .and_then(|goroot| {
                    let p = PathBuf::from(goroot).join("bin").join("go");
                    if p.exists() {
                        Some(p.to_string_lossy().to_string())
                    } else {
                        None
                    }
                })
        })
        .unwrap_or_else(|| "go".to_string());
    let total = addrs.len();
    let sent_counter = Arc::new(AtomicUsize::new(0));
    let received_counter = Arc::new(AtomicUsize::new(0));
    let heartbeat = if total > 10_000 {
        let sent_counter = Arc::clone(&sent_counter);
        let received_counter = Arc::clone(&received_counter);
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || {
            let started = Instant::now();
            loop {
                match stop_rx.recv_timeout(Duration::from_secs(15)) {
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        let sent = sent_counter.load(Ordering::Relaxed);
                        let received = received_counter.load(Ordering::Relaxed);
                        eprintln!(
                            concat!(
                                "golibafl: addr2line sent {sent}/{total} ",
                                "got {received}/{total} elapsed {elapsed}s"
                            ),
                            sent = sent,
                            total = total,
                            received = received,
                            elapsed = started.elapsed().as_secs()
                        );
                    }
                }
            }
        });
        Some((stop_tx, handle))
    } else {
        None
    };

    let max_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let workers = max_workers.max(1).min(total.max(1));
    let chunk_size = total.div_ceil(workers);

    let mut handles = Vec::new();
    for chunk in addrs.chunks(chunk_size) {
        let obj_path = obj_path.to_path_buf();
        let chunk_addrs = chunk.to_vec();
        let sent_counter = Arc::clone(&sent_counter);
        let received_counter = Arc::clone(&received_counter);
        let go_bin = go_bin.clone();
        handles.push(std::thread::spawn(move || {
            go_tool_locations_worker(
                &go_bin,
                &obj_path,
                chunk_addrs,
                sent_counter,
                received_counter,
            )
        }));
    }
    let mut res: HashMap<u64, (String, u32)> = HashMap::new();
    for h in handles {
        res.extend(h.join().unwrap_or_else(|_| {
            eprintln!("golibafl: addr2line worker panicked");
            std::process::exit(2);
        }));
    }

    if let Some((stop_tx, handle)) = heartbeat {
        let _ = stop_tx.send(());
        let _ = handle.join();
    }

    res
}

fn resolve_repo_relative_path(
    path_str: &str,
    target_dir: &Path,
    repo_root: &Path,
    cache: &mut HashMap<String, Option<String>>,
) -> Option<String> {
    if let Some(v) = cache.get(path_str) {
        return v.clone();
    }

    let p = Path::new(path_str);
    let abs = if p.is_absolute() {
        fs::canonicalize(p).ok()
    } else {
        fs::canonicalize(target_dir.join(p))
            .or_else(|_| fs::canonicalize(repo_root.join(p)))
            .ok()
    };

    let rel = abs.and_then(|abs| {
        if !abs.starts_with(repo_root) {
            return None;
        }
        abs.strip_prefix(repo_root).ok().and_then(|p| {
            let s = p.to_string_lossy().replace('\\', "/");
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        })
    });

    cache.insert(path_str.to_string(), rel.clone());
    rel
}

fn ensure_git_recency_mapping(mapping_path: &Path, target_dir: &Path) {
    let repo_root = repo_root(target_dir);
    let repo_root = fs::canonicalize(&repo_root).unwrap_or_else(|err| {
        eprintln!(
            "golibafl: failed to canonicalize repo root {}: {err}",
            repo_root.display()
        );
        std::process::exit(2);
    });
    let head_time = head_time_epoch_seconds(&repo_root);

    let harness_lib = env::var_os("HARNESS_LIB").unwrap_or_else(|| {
        eprintln!("golibafl: HARNESS_LIB must be set when {GOLIBAFL_FOCUS_ON_NEW_CODE_ENV}=true");
        std::process::exit(2);
    });
    let harness_lib = PathBuf::from(harness_lib);
    let go_o_bytes = extract_go_o_from_harness(&harness_lib);
    let go_o_hash = fnv1a64(&go_o_bytes);

    let obj = object::File::parse(&*go_o_bytes).unwrap_or_else(|err| {
        eprintln!(
            "golibafl: failed to parse go.o from {}: {err}",
            harness_lib.display()
        );
        std::process::exit(2);
    });

    let counters_section = obj.section_by_name(".go.fuzzcntrs").unwrap_or_else(|| {
        eprintln!(
            "golibafl: go.o does not contain .go.fuzzcntrs; cannot generate git recency mapping"
        );
        std::process::exit(2);
    });
    let counters_len = usize::try_from(counters_section.size()).unwrap_or_else(|_| {
        eprintln!("golibafl: .go.fuzzcntrs is too large");
        std::process::exit(2);
    });

    let existing = read_mapping_header(mapping_path).and_then(|(old_head_time, old_len)| {
        let expected_size = 16u64.checked_add(old_len.checked_mul(8)?)?;
        let actual_size = fs::metadata(mapping_path).ok()?.len();
        if expected_size != actual_size {
            return None;
        }
        let old_len = usize::try_from(old_len).ok()?;
        Some((old_head_time, old_len))
    });

    let sidecar_path = git_recency_map_sidecar_path(mapping_path);
    let sidecar = read_git_recency_map_sidecar(&sidecar_path);
    let sidecar_matches = match sidecar.as_ref() {
        Some(meta) => {
            meta.version == 1
                && meta.go_o_hash_fnv1a64 == go_o_hash
                && meta.counters_len == counters_len as u64
        }
        None => false,
    };

    if let Some((old_head_time, old_len)) = existing {
        if old_len == counters_len && (sidecar_matches || sidecar.is_none()) {
            if sidecar.is_none() {
                let meta = GitRecencyMapSidecar {
                    version: 1,
                    go_o_hash_fnv1a64: go_o_hash,
                    counters_len: counters_len as u64,
                };
                let bytes = serde_json::to_vec(&meta).unwrap_or_else(|err| {
                    eprintln!("golibafl: failed to serialize git recency sidecar: {err}");
                    std::process::exit(2);
                });
                write_atomic_bytes(&sidecar_path, &bytes);
            }

            if old_head_time != head_time {
                eprintln!("golibafl: updating git recency map head_time (reusing existing mapping)");
                let mut out = fs::OpenOptions::new()
                    .write(true)
                    .open(mapping_path)
                    .unwrap_or_else(|err| {
                        eprintln!(
                            "golibafl: failed to open mapping file {}: {err}",
                            mapping_path.display()
                        );
                        std::process::exit(2);
                    });
                out.write_all(&head_time.to_le_bytes())
                    .unwrap_or_else(|err| {
                        eprintln!("golibafl: failed to update mapping file: {err}");
                        std::process::exit(2);
                    });
            }

            return;
        }
    }

    eprintln!(
        "golibafl: generating git recency mapping ({} counters); this may take a while",
        counters_len
    );
    let tmp_go_o = env::temp_dir().join(format!("golibafl_gitrec_go_{}.o", std::process::id()));
    fs::write(&tmp_go_o, &go_o_bytes).unwrap_or_else(|err| {
        eprintln!("golibafl: failed to write {}: {err}", tmp_go_o.display());
        std::process::exit(2);
    });

    let mut counter_locs: HashMap<usize, (String, u32)> = HashMap::new();
    let mut counter_addrs: HashMap<usize, u64> = HashMap::new();
    let mut path_cache: HashMap<String, Option<String>> = HashMap::new();

    for section in obj.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        let section_base = section.address();
        for (offset, reloc) in section.relocations() {
            let RelocationTarget::Symbol(sym_idx) = reloc.target() else {
                continue;
            };
            let Ok(sym) = obj.symbol_by_index(sym_idx) else {
                continue;
            };
            if sym.section_index() != Some(counters_section.index()) {
                continue;
            }
            let idx = usize::try_from(sym.address().saturating_sub(counters_section.address()))
                .unwrap_or(usize::MAX);
            if idx >= counters_len || counter_locs.contains_key(&idx) {
                continue;
            }

            let addr = section_base + offset;
            counter_addrs.insert(idx, addr);
        }
    }

    if !counter_addrs.is_empty() {
        let mut addrs: Vec<u64> = counter_addrs.values().copied().collect();
        addrs.sort_unstable();
        addrs.dedup();
        eprintln!("golibafl: running go tool addr2line on {} addresses", addrs.len());
        let locs = go_tool_locations(&tmp_go_o, &addrs);
        for (idx, addr) in counter_addrs {
            let Some((file, line)) = locs.get(&addr).cloned() else {
                continue;
            };
            let Some(file_rel) =
                resolve_repo_relative_path(&file, target_dir, &repo_root, &mut path_cache)
            else {
                continue;
            };
            counter_locs.insert(idx, (file_rel, line));
        }
    }
    let _ = fs::remove_file(&tmp_go_o);

    let mut needed_by_file: HashMap<String, HashSet<u32>> = HashMap::new();
    for (_idx, (file, line)) in &counter_locs {
        needed_by_file
            .entry(file.clone())
            .or_default()
            .insert(*line);
    }

    let mut times_by_file: HashMap<String, HashMap<u32, u64>> = HashMap::new();
    let total_files = needed_by_file.len();
    if total_files > 0 {
        eprintln!("golibafl: running git blame on {total_files} file(s)");
    }
    let started_blame = Instant::now();
    let mut last_blame_progress = Instant::now();
    let mut blamed_files = 0usize;
    for (file, needed_lines) in &needed_by_file {
        blamed_files += 1;
        if total_files > 50
            && (last_blame_progress.elapsed() >= Duration::from_secs(10)
                || blamed_files == total_files)
        {
            let elapsed = started_blame.elapsed().as_secs_f64().max(0.001);
            let pct = (blamed_files as f64) * 100.0 / (total_files as f64);
            eprintln!(
                "golibafl: git blame progress {blamed_files}/{total_files} ({pct:.1}%), elapsed {elapsed:.0}s"
            );
            last_blame_progress = Instant::now();
        }
        let times = blame_times_for_lines(&repo_root, file, needed_lines);
        times_by_file.insert(file.clone(), times);
    }

    let mut timestamps = vec![0u64; counters_len];
    for (idx, (file, line)) in counter_locs {
        if let Some(time) = times_by_file.get(&file).and_then(|m| m.get(&line)).copied() {
            if let Some(slot) = timestamps.get_mut(idx) {
                *slot = time;
            }
        }
    }

    if let Some(parent) = mapping_path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!(
                "golibafl: failed to create mapping directory {}: {err}",
                parent.display()
            );
            std::process::exit(2);
        }
    }

    let tmp_mapping_path =
        mapping_path.with_extension(format!("bin.tmp-{}", std::process::id()));
    let mut out = fs::File::create(&tmp_mapping_path).unwrap_or_else(|err| {
        eprintln!(
            "golibafl: failed to create mapping file {}: {err}",
            tmp_mapping_path.display()
        );
        std::process::exit(2);
    });

    out.write_all(&head_time.to_le_bytes())
        .unwrap_or_else(|err| {
            eprintln!("golibafl: failed to write mapping file: {err}");
            std::process::exit(2);
        });
    out.write_all(&(timestamps.len() as u64).to_le_bytes())
        .unwrap_or_else(|err| {
            eprintln!("golibafl: failed to write mapping file: {err}");
            std::process::exit(2);
        });
    for t in timestamps {
        out.write_all(&t.to_le_bytes()).unwrap_or_else(|err| {
            eprintln!("golibafl: failed to write mapping file: {err}");
            std::process::exit(2);
        });
    }
    drop(out);

    fs::rename(&tmp_mapping_path, mapping_path).unwrap_or_else(|err| {
        eprintln!(
            "golibafl: failed to rename {} to {}: {err}",
            tmp_mapping_path.display(),
            mapping_path.display()
        );
        std::process::exit(2);
    });

    let meta = GitRecencyMapSidecar {
        version: 1,
        go_o_hash_fnv1a64: go_o_hash,
        counters_len: counters_len as u64,
    };
    let meta_bytes = serde_json::to_vec(&meta).unwrap_or_else(|err| {
        eprintln!("golibafl: failed to serialize git recency sidecar: {err}");
        std::process::exit(2);
    });
    write_atomic_bytes(&sidecar_path, &meta_bytes);
}

// Command line arguments with clap
#[derive(Subcommand, Debug, Clone)]
enum Mode {
    Run {
        #[clap(short, long, value_name = "DIR", default_value = "./input")]
        input: PathBuf,
    },
    Fuzz {
        #[clap(
            long,
            value_name = "FILE",
            help = "JSONC config file path (JSON with // comments)"
        )]
        config: Option<PathBuf>,

        #[clap(
            short = 'j',
            long,
            value_parser = Cores::from_cmdline,
            help = "Spawn clients in each of the provided cores. Broker runs in the 0th core. 'all' to select all available cores. 'none' to run a client without binding to any core. eg: '1,2-4,6' selects the cores 1,2,3,4,6.",
            name = "CORES",
            default_value = "all",
            )]
        cores: Cores,

        #[clap(
            short = 'p',
            long,
            help = "Choose the broker TCP port (default: random free port)",
            name = "PORT"
        )]
        broker_port: Option<u16>,

        #[clap(
            short,
            long,
            value_name = "DIR",
            default_value = "./input",
            help = "Initial corpus directory (will only be read)"
        )]
        input: PathBuf,

        #[clap(
            short,
            long,
            value_name = "OUTPUT",
            default_value = "./output",
            help = "Fuzzer's output directory"
        )]
        output: PathBuf,

        #[clap(long, help = "Enable grammar-based input generation via Grammarinator (ANTLRv4)")]
        use_grammar: bool,

        #[clap(long, value_name = "FILE", help = "ANTLRv4 grammar file (.g4). Repeatable.")]
        grammar: Vec<PathBuf>,

        #[clap(long, value_name = "RULE", help = "Start rule for grammar generation")]
        start_rule: Option<String>,

        #[clap(long, help = "Allow inline actions and semantic predicates in the grammar")]
        grammar_actions: bool,

        #[clap(
            long,
            value_name = "PY_REF",
            help = "Python serializer function (package.module.function). Default: grammarinator.runtime.simple_space_serializer"
        )]
        grammar_serializer: Option<String>,

        #[clap(
            long,
            value_name = "DIR",
            help = "Add DIR to PYTHONPATH when running Grammarinator (useful for a local checkout)"
        )]
        grammarinator_dir: Option<PathBuf>,

        #[clap(long, value_name = "NUM", default_value = "32", help = "Max recursion depth for grammar generation")]
        grammar_max_depth: usize,

        #[clap(long, value_name = "NUM", default_value = "512", help = "Max token count for grammar generation")]
        grammar_max_tokens: usize,
    },
    Cov {
        #[clap(short, long, value_name = "OUTPUT", help = "Fuzzer's output directory")]
        output: PathBuf,
        #[clap(
            short,
            long,
            value_name = "HARNESS",
            help = "Fuzzer's harness directory"
        )]
        fuzzer_harness: PathBuf,
        #[clap(
            short,
            long,
            value_name = "COV_PACKAGE",
            help = "Package name the coverage should be filtered for"
        )]
        coverage_filter: Option<String>,
    },
}
// Clap top level struct for args
// `Parser` is needed for the top-level command-line interface
#[derive(Parser, Debug, Clone)]
struct Cli {
    #[command(subcommand)]
    mode: Mode,
}

// Run the corpus without fuzzing
fn run(input: PathBuf) {
    let files = if input.is_dir() {
        input
            .read_dir()
            .expect("Unable to read dir")
            .filter_map(core::result::Result::ok)
            .map(|e| e.path())
            .collect()
    } else {
        vec![input]
    };

    // Call LLVMFuzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    for f in &files {
        println!("\x1b[33mRunning: {}\x1b[0m", f.display());
        let inp =
            std::fs::read(f).unwrap_or_else(|_| panic!("Unable to read file {}", &f.display()));
        unsafe {
            libfuzzer_test_one_input(&inp);
        }
    }
}

// Fuzzing function, wrapping the exported libfuzzer functions from golang
#[allow(clippy::too_many_lines)]
#[allow(static_mut_refs)]
fn fuzz(
    cores: &Cores,
    broker_port: u16,
    input: &PathBuf,
    output: &Path,
    config_path: Option<&PathBuf>,
    grammar_cfg: Option<&GrammarinatorConfig>,
) {
    let args: Vec<String> = env::args().collect();
    let is_launcher_client = env::var_os("AFL_LAUNCHER_CLIENT").is_some();
    let verbose = env::var_os("GOSENTRY_VERBOSE_AFL").is_some();

    // In launcher mode, `launch_with_hooks` installs signal handlers and starts background
    // threads before running the client closure. When fuzzing Go harnesses linked as a static
    // archive, calling `LLVMFuzzerInitialize` from inside the client closure may deadlock.
    // Call it once early in the launcher client process to make sure Go runtime initialization
    // completes before LibAFL sets up the launcher.
    if is_launcher_client {
        if verbose {
            eprintln!("golibafl: launcher client early init (calling LLVMFuzzerInitialize)");
        }
        let init_ret = unsafe { libfuzzer_initialize(&args) };
        if verbose {
            eprintln!("golibafl: LLVMFuzzerInitialize returned {init_ret}");
        }
        if init_ret == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1");
        }
    }

    let rand_seed = env::var("LIBAFL_RAND_SEED")
        .ok()
        .map(|s| {
            s.parse::<u64>().unwrap_or_else(|_| {
                eprintln!("golibafl: invalid LIBAFL_RAND_SEED={s} (expected u64)");
                std::process::exit(2);
            })
        });


    let focus_on_new_code = env::var(GOLIBAFL_FOCUS_ON_NEW_CODE_ENV)
        .ok()
        .map(|v| {
            v.parse::<bool>().unwrap_or_else(|_| {
                eprintln!(
                    "golibafl: invalid {GOLIBAFL_FOCUS_ON_NEW_CODE_ENV}={v} (expected true/false)"
                );
                std::process::exit(2);
            })
        })
        .unwrap_or(false);

    let needs_cwd = !input.is_absolute()
        || !output.is_absolute()
        || config_path.as_ref().is_some_and(|p| p.is_relative())
        || grammar_cfg.as_ref().is_some_and(|cfg| {
            cfg.grammar.iter().any(|p| p.is_relative())
                || cfg
                    .grammarinator_dir
                    .as_ref()
                    .is_some_and(|p| p.is_relative())
        });
    let cwd = if needs_cwd {
        env::current_dir().ok()
    } else {
        None
    };
    let input = if input.is_absolute() {
        input.clone()
    } else {
        cwd.as_ref()
            .map(|cwd| cwd.join(input))
            .unwrap_or_else(|| input.clone())
    };
    let output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        cwd.as_ref()
            .map(|cwd| cwd.join(output))
            .unwrap_or_else(|| output.to_path_buf())
    };
    let target_dir = env::var_os(GOLIBAFL_TARGET_DIR_ENV).map(PathBuf::from);
    let git_recency_map_path = env::var_os(LIBAFL_GIT_RECENCY_MAPPING_ENV)
        .map(PathBuf::from)
        .map(|p| {
            if p.is_absolute() {
                p
            } else {
                cwd.as_ref().map(|cwd| cwd.join(&p)).unwrap_or(p)
            }
        });
    let config_path = config_path.map(|config_path| {
        if config_path.is_absolute() {
            config_path.clone()
        } else {
            cwd.as_ref()
                .map(|cwd| cwd.join(config_path))
                .unwrap_or_else(|| config_path.clone())
        }
    });

    let mut grammar_cfg = grammar_cfg.cloned().map(|mut cfg| {
        cfg.grammar = cfg
            .grammar
            .into_iter()
            .map(|p| {
                if p.is_absolute() {
                    p
                } else {
                    cwd.as_ref().map(|cwd| cwd.join(&p)).unwrap_or(p)
                }
            })
            .collect();
        cfg.grammarinator_dir = cfg.grammarinator_dir.map(|p| {
            if p.is_absolute() {
                p
            } else {
                cwd.as_ref().map(|cwd| cwd.join(&p)).unwrap_or(p)
            }
        });
        if cfg.max_depth == 0 {
            eprintln!("golibafl: --grammar-max-depth must be > 0");
            std::process::exit(2);
        }
        if cfg.max_tokens == 0 {
            eprintln!("golibafl: --grammar-max-tokens must be > 0");
            std::process::exit(2);
        }
        cfg
    });

    let mut effective_cores = cores.clone();
    let mut exec_timeout = Duration::new(1, 0);
    let mut catch_hangs = true;
    let mut hang_timeout = Duration::from_secs(10);
    let mut hang_confirm_runs = 3usize;
    let mut stop_all_fuzzers_on_panic = true;
    let mut power_schedule = PowerSchedule::fast();
    let mut git_recency_alpha: Option<f64> = None;
    let mut corpus_cache_size = 4096usize;
    let mut initial_generated_inputs = 8usize;
    let mut initial_input_max_len = 32usize;
    let mut go_maxprocs_single = true;
    let mut tui_monitor = std::io::stdout().is_terminal();
    let mut debug_output_override: Option<bool> = None;

    if let Some(config_path) = config_path.as_ref() {
        let config = read_fuzz_config(config_path);
        if let Some(cores) = config.cores.as_deref() {
            effective_cores = Cores::from_cmdline(cores).unwrap_or_else(|err| {
                eprintln!(
                    "golibafl: invalid cores in config {}: {err}",
                    config_path.display()
                );
                std::process::exit(2);
            });
        }
        if let Some(ms) = config.exec_timeout_ms {
            if ms == 0 {
                eprintln!(
                    "golibafl: exec_timeout_ms must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            exec_timeout = Duration::from_millis(ms);
        }
        if let Some(v) = config.catch_hangs {
            catch_hangs = v;
        }
        if let Some(ms) = config.hang_timeout_ms {
            if ms == 0 {
                eprintln!(
                    "golibafl: hang_timeout_ms must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            hang_timeout = Duration::from_millis(ms);
        }
        if let Some(n) = config.hang_confirm_runs {
            if n == 0 {
                eprintln!(
                    "golibafl: hang_confirm_runs must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            hang_confirm_runs = n;
        }
        if let Some(v) = config.stop_all_fuzzers_on_panic {
            stop_all_fuzzers_on_panic = v;
        }
        if let Some(ps) = config.power_schedule.as_deref() {
            let ps_norm = ps.trim().to_ascii_lowercase();
            power_schedule = match ps_norm.as_str() {
                "explore" => PowerSchedule::explore(),
                "exploit" => PowerSchedule::exploit(),
                "fast" => PowerSchedule::fast(),
                "coe" => PowerSchedule::coe(),
                "lin" => PowerSchedule::lin(),
                "quad" => PowerSchedule::quad(),
                _ => {
                    eprintln!(
                        "golibafl: invalid power_schedule in config {}: {ps} (expected explore/exploit/fast/coe/lin/quad)",
                        config_path.display()
                    );
                    std::process::exit(2);
                }
            };
        }
        if let Some(alpha) = config.git_recency_alpha {
            if !(0.0..=10.0).contains(&alpha) {
                eprintln!(
                    "golibafl: git_recency_alpha must be in [0.0, 10.0] (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            git_recency_alpha = Some(alpha);
        }
        if let Some(sz) = config.corpus_cache_size {
            if sz == 0 {
                eprintln!(
                    "golibafl: corpus_cache_size must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            corpus_cache_size = sz;
        }
        if let Some(n) = config.initial_generated_inputs {
            if n == 0 {
                eprintln!(
                    "golibafl: initial_generated_inputs must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            initial_generated_inputs = n;
        }
        if let Some(n) = config.initial_input_max_len {
            if n == 0 {
                eprintln!(
                    "golibafl: initial_input_max_len must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            initial_input_max_len = n;
        }
        if let Some(v) = config.go_maxprocs_single {
            go_maxprocs_single = v;
        }
        if let Some(v) = config.tui_monitor {
            tui_monitor = v;
        }
        debug_output_override = config.debug_output;

        if let Some(n) = config.grammar_max_depth {
            if n == 0 {
                eprintln!(
                    "golibafl: grammar_max_depth must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            if let Some(grammar_cfg) = grammar_cfg.as_mut() {
                grammar_cfg.max_depth = n;
            }
        }
        if let Some(n) = config.grammar_max_tokens {
            if n == 0 {
                eprintln!(
                    "golibafl: grammar_max_tokens must be > 0 (config: {})",
                    config_path.display()
                );
                std::process::exit(2);
            }
            if let Some(grammar_cfg) = grammar_cfg.as_mut() {
                grammar_cfg.max_tokens = n;
            }
        }
        if let Some(grammar_cfg) = grammar_cfg.as_mut() {
            if let Some(v) = config.grammar_actions {
                grammar_cfg.actions = v;
            }
            if let Some(dir) = config.grammarinator_dir.as_ref() {
                let dir = if dir.is_absolute() {
                    dir.clone()
                } else {
                    let cwd = cwd.as_ref().cloned().or_else(|| env::current_dir().ok()).unwrap_or_else(|| {
                        eprintln!(
                            "golibafl: failed to resolve grammarinator_dir (config: {})",
                            config_path.display()
                        );
                        std::process::exit(2);
                    });
                    cwd.join(dir)
                };
                grammar_cfg.grammarinator_dir = Some(dir);
            }
        }

        println!(
            "GOLIBAFL_CONFIG_APPLIED cores_ids={} exec_timeout_ms={} catch_hangs={} hang_timeout_ms={} hang_confirm_runs={}",
            cores_ids_csv(&effective_cores),
            exec_timeout.as_millis(),
            catch_hangs,
            hang_timeout.as_millis(),
            hang_confirm_runs,
        );
    }

    match debug_output_override {
        Some(true) => env::set_var("LIBAFL_DEBUG_OUTPUT", "1"),
        Some(false) => env::remove_var("LIBAFL_DEBUG_OUTPUT"),
        None => {
            if effective_cores.ids.len() == 1 {
                env::set_var("LIBAFL_DEBUG_OUTPUT", "1");
            }
        }
    }

    if focus_on_new_code && !is_launcher_client {
        let target_dir = target_dir.unwrap_or_else(|| {
            panic!(
                "{GOLIBAFL_TARGET_DIR_ENV} must be set when {GOLIBAFL_FOCUS_ON_NEW_CODE_ENV}=true"
            )
        });
        let map_path = git_recency_map_path.as_ref().unwrap_or_else(|| {
            panic!("{LIBAFL_GIT_RECENCY_MAPPING_ENV} must be set when {GOLIBAFL_FOCUS_ON_NEW_CODE_ENV}=true")
        });
        ensure_git_recency_mapping(map_path, &target_dir);
    }

    // LibAFL's restarting manager uses `std::env::current_dir()` when re-spawning itself in
    // non-fork mode. If the current working directory is deleted/unlinked (common with temp dirs),
    // this will fail with ENOENT and abort the whole fuzz run on the first crash/timeout.
    //
    // Use a stable workdir under the output directory to make respawns reliable.
    //
    // On macOS, LibAFL's shared memory provider uses a unix socket at
    // `./libafl_unix_shmem_server` (relative path). All broker/clients must share the
    // same working directory for this to work, so we use a shared `workdir/`.
    //
    // On other unix systems, the shared memory provider uses an abstract domain socket,
    // so a per-process workdir avoids cross-process surprises if multiple fuzz runs share
    // the same output directory.
    let workdir = if cfg!(target_vendor = "apple") {
        output.join("workdir")
    } else {
        output.join("workdir").join(std::process::id().to_string())
    };
    let _ = fs::create_dir_all(&workdir);
    let _ = env::set_current_dir(&workdir);

    let initial_input_max_len =
        std::num::NonZeroUsize::new(initial_input_max_len).unwrap_or_else(|| {
            panic!("initial_input_max_len must be > 0");
        });
    let monitor_timeout = Duration::from_secs(15);
    let crashes_dir = output.join("crashes");
    let list_crash_inputs = |dir: &Path| -> Vec<PathBuf> {
        fs::read_dir(dir)
            .ok()
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| {
                        !e.file_name().to_string_lossy().starts_with('.')
                            && e.file_type().is_ok_and(|t| t.is_file())
                    })
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default()
    };
    let count_crash_inputs = |dir: &Path| -> usize { list_crash_inputs(dir).len() };
    let hang_candidates_dir = output.join("hang_candidates");
    let hangs_dir = output.join("hangs");
    let list_hang_inputs = |dir: &Path| -> Vec<PathBuf> {
        fs::read_dir(dir)
            .ok()
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| {
                        !e.file_name().to_string_lossy().starts_with('.')
                            && e.file_type().is_ok_and(|t| t.is_file())
                    })
                    .map(|e| e.path())
                    .collect()
            })
            .unwrap_or_default()
    };
    let count_hang_inputs = |dir: &Path| -> usize { list_hang_inputs(dir).len() };
    if !is_launcher_client && count_crash_inputs(&crashes_dir) > 0 {
        // `go test -fuzz` semantics: if there are pre-existing crashing inputs, replay them.
        // If they no longer crash (because the harness was fixed/recompiled), move them aside
        // so they don't cause the run to fail spuriously.
        let exe = env::current_exe().ok();
        let stale_dir = output.join("crashes.stale");
        let can_archive = fs::create_dir_all(&stale_dir).is_ok();

        let crash_inputs: Vec<PathBuf> = list_crash_inputs(&crashes_dir);
        let mut reproduced: Vec<PathBuf> = Vec::new();

        let crash_dir_entries: Vec<PathBuf> = fs::read_dir(&crashes_dir)
            .ok()
            .map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect())
            .unwrap_or_default();

        for f in crash_inputs {
            let still_crashes = match exe.as_ref() {
                Some(exe) => match Command::new(exe)
                    .args(["run", "--input"])
                    .arg(&f)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                {
                    Ok(st) => !st.success(),
                    Err(_) => true,
                },
                None => true,
            };
            if still_crashes {
                reproduced.push(f);
                continue;
            }

            // If we got here, this input no longer reproduces the crash.
            let file_name = f
                .file_name()
                .unwrap_or_else(|| panic!("Invalid crash file name: {}", f.display()));
            let file_name_str = file_name.to_string_lossy();
            let dst = stale_dir.join(file_name);
            if can_archive {
                let _ = fs::rename(&f, &dst);
            } else {
                let _ = fs::remove_file(&f);
            }
            let related_prefix = format!(".{}", file_name_str);
            for p in &crash_dir_entries {
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with(&related_prefix) {
                        if can_archive {
                            let _ = fs::rename(p, stale_dir.join(name));
                        } else {
                            let _ = fs::remove_file(p);
                        }
                    }
                }
            }
        }

        if stop_all_fuzzers_on_panic && !reproduced.is_empty() {
            eprintln!("Found {} pre-existing crashing input(s).", reproduced.len());
            eprintln!("libafl output dir: {}", output.display());
            eprintln!("crashes dir: {}", crashes_dir.display());
            for p in &reproduced {
                eprintln!("crash input: {}", p.display());
                if let Some(exe) = exe.as_ref() {
                    eprintln!("repro: {} run --input {}", exe.display(), p.display());
                } else {
                    eprintln!("repro: golibafl run --input {}", p.display());
                }
            }
            notify_restarting_mgr_exit();
            std::process::exit(1);
        }
    }

    let computed_initial_crash_inputs = count_crash_inputs(&crashes_dir);
    // The fuzzer process may be respawned by LibAFL's restarting manager. Propagate the initial
    // crash count across respawns so "stop on first crash" stays correct after a restart.
    let initial_crash_inputs = match env::var("GOLIBAFL_INITIAL_CRASH_INPUTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        Some(v) => v,
        None => {
            env::set_var(
                "GOLIBAFL_INITIAL_CRASH_INPUTS",
                computed_initial_crash_inputs.to_string(),
            );
            computed_initial_crash_inputs
        }
    };
    let computed_initial_hang_inputs = count_hang_inputs(&hangs_dir);
    // The fuzzer process may be respawned by LibAFL's restarting manager. Propagate the initial
    // hang count across respawns so "stop on first hang" stays correct after a restart.
    let initial_hang_inputs = match env::var("GOLIBAFL_INITIAL_HANG_INPUTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
    {
        Some(v) => v,
        None => {
            env::set_var(
                "GOLIBAFL_INITIAL_HANG_INPUTS",
                computed_initial_hang_inputs.to_string(),
            );
            computed_initial_hang_inputs
        }
    };
    // On macOS, LibAFL's `StdShMemProvider` uses a on-disk unix socket at
    // `./libafl_unix_shmem_server`. If a previous run crashed, a stale socket
    // may be left behind and prevent the shmem service from starting.
    //
    // Only attempt to remove it if this process is about to start the shmem
    // service. Child processes (when `.fork(false)` is used) inherit the
    // `AFL_SHMEM_SERVICE_STARTED` env var and must not remove the broker's
    // socket.
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if env::var("AFL_SHMEM_SERVICE_STARTED").is_err() {
            if let Ok(meta) = fs::metadata("libafl_unix_shmem_server") {
                if meta.file_type().is_socket() {
                    let _ = fs::remove_file("libafl_unix_shmem_server");
                }
            }
        }
    }
	    let shmem_provider = StdShMemProvider::new()
	        .unwrap_or_else(|err| panic!("Failed to init shared memory: {err:?}"));

	    let mut run_client = |state: Option<_>,
	                          mut restarting_mgr: LlmpRestartingEventManager<
	        _,
	        BytesInput,
	        _,
	        _,
	        _,
	    >,
	                          client_description: ClientDescription| {
	        let dir_has_visible_entries = |dir: &Path| -> bool {
	            fs::read_dir(dir)
	                .ok()
	                .map(|rd| {
	                    rd.filter_map(Result::ok).any(|e| {
	                        !e.file_name().to_string_lossy().starts_with('.')
	                            && e.file_type().is_ok_and(|t| t.is_file() || t.is_dir())
	                    })
	                })
	                .unwrap_or(false)
	        };

	        let client_id = client_description.id().to_string();
	        let queue_dir = output.join("queue").join(&client_id);
	        let resume_bucket_dir = output.join("queue.resume").join(&client_id);
	        let hang_candidate_path = hang_candidates_dir.join(format!("{client_id}.bin"));

	        // Resume on Ctrl-C by re-importing the previous queue/ corpus into a fresh
	        // on-disk corpus directory, so the fuzzer does not restart from scratch.
	        let resume_has_inputs = if state.is_none() {
	            if dir_has_visible_entries(&queue_dir) {
	                fs::create_dir_all(&resume_bucket_dir).unwrap_or_else(|err| {
	                    panic!(
	                        "golibafl: failed to create resume directory {}: {err}",
	                        resume_bucket_dir.display()
	                    )
	                });

	                let mut dst = resume_bucket_dir.join(format!("queue-{}", std::process::id()));
	                if dst.exists() {
	                    for i in 1.. {
	                        let candidate = resume_bucket_dir
	                            .join(format!("queue-{}-{i}", std::process::id()));
	                        if !candidate.exists() {
	                            dst = candidate;
	                            break;
	                        }
	                    }
	                }
	                fs::rename(&queue_dir, &dst).unwrap_or_else(|err| {
	                    panic!(
	                        "golibafl: failed to move previous corpus {} to {}: {err}",
	                        queue_dir.display(),
	                        dst.display()
	                    )
	                });
	            }
	            dir_has_visible_entries(&resume_bucket_dir)
	        } else {
	            false
	        };
	        if resume_has_inputs && verbose {
	            eprintln!(
	                "golibafl: resuming from previous corpus at {}",
	                resume_bucket_dir.display()
	            );
	        }

	        // In-process crashes abort the fuzzing instance, and the restarting manager respawns it.
	        // Implement `go test -fuzz` semantics: stop the whole run on the first crash.
	        if stop_all_fuzzers_on_panic && count_crash_inputs(&crashes_dir) > initial_crash_inputs {
	            restarting_mgr.send_exiting()?;
	            return Err(Error::shutting_down());
	        }
	        if catch_hangs
	            && stop_all_fuzzers_on_panic
	            && count_hang_inputs(&hangs_dir) > initial_hang_inputs
	        {
	            restarting_mgr.send_exiting()?;
	            return Err(Error::shutting_down());
	        }

        if go_maxprocs_single && effective_cores.ids.len() > 1 {
            env::set_var("GOMAXPROCS", "1");
        }

        // trigger Go runtime initialization, which calls __sanitizer_cov_8bit_counters_init to initialize COUNTERS_MAPS
        if verbose {
            eprintln!(
                "golibafl: client start id={} pid={} (calling LLVMFuzzerInitialize)",
                client_description.id(),
                std::process::id()
            );
        }
        let init_ret = unsafe { libfuzzer_initialize(&args) };
        if verbose {
            eprintln!("golibafl: LLVMFuzzerInitialize returned {init_ret}");
        }
        if init_ret == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1");
        }
        let counters_map_len = unsafe { COUNTERS_MAPS.len() };
        if verbose {
            eprintln!("golibafl: counters_map_len={counters_map_len}");
        }

        macro_rules! run_with_edges_observer {
                ($edges_observer:expr, $map_feedback:ident) => {{
                    let edges_observer = ($edges_observer).track_indices();

                    // Observers
                    let time_observer = TimeObserver::new("time");
                    let cmplog_observer = CmpLogObserver::new("cmplog", true);
                    let map_feedback = $map_feedback::new(&edges_observer);
                    let calibration = CalibrationStage::new(&map_feedback);

                    let mut feedback = feedback_or_fast!(
                        // New maximization map feedback linked to the edges observer and the feedback state
                        map_feedback,
                        // Time feedback, this one does not need a feedback state
                        TimeFeedback::new(&time_observer)
                    );

                    // A feedback to choose if an input is a solution or not
                    let mut objective = feedback_or_fast!(CrashAndHangObjective::new(
                        catch_hangs,
                        hang_candidate_path.clone()
                    ));

	                    // create a State from scratch
	                    let mut state = state.unwrap_or_else(|| {
	                        StdState::new(
	                            rand_seed
	                                .map(StdRand::with_seed)
	                                .unwrap_or_else(StdRand::new),
	                            // Corpus that will be evolved
	                            CachedOnDiskCorpus::new(queue_dir.clone(), corpus_cache_size)
	                            .unwrap(),
	                            // Corpus in which we store solutions
	                            OnDiskCorpus::new(format!("{}/crashes", output.display())).unwrap(),
	                            &mut feedback,
                            &mut objective,
                        )
                        .unwrap()
                    });
                    let initial_solutions = state.solutions().count();

                    let grammar_engine = if let Some(cfg) = grammar_cfg.as_ref() {
                        for g in cfg.grammar.iter() {
                            if !g.exists() {
                                eprintln!("golibafl: grammar file not found: {}", g.display());
                                std::process::exit(2);
                            }
                        }
                        if let Some(dir) = cfg.grammarinator_dir.as_ref() {
                            if !dir.is_dir() {
                                eprintln!(
                                    "golibafl: grammarinator dir not found: {}",
                                    dir.display()
                                );
                                std::process::exit(2);
                            }
                        }

                        let grammar_workdir = workdir.join("grammarinator").join(&client_id);
                        if verbose {
                            eprintln!(
                                "golibafl: grammarinator enabled (workdir={})",
                                grammar_workdir.display()
                            );
                        }
                        Some(Arc::new(Mutex::new(GrammarinatorEngine::spawn(
                            cfg,
                            &grammar_workdir,
                        )?)))
                    } else {
                        None
                    };
                    let grammar_mode = grammar_engine.is_some();

                    if focus_on_new_code {
                        let map_path = git_recency_map_path.as_ref().unwrap_or_else(|| {
                            panic!(
                                "{LIBAFL_GIT_RECENCY_MAPPING_ENV} must be set when {GOLIBAFL_FOCUS_ON_NEW_CODE_ENV}=true"
                            )
                        });
                        state.add_metadata(GitRecencyMapMetadata::load_from_file(map_path)?);
                        if let Some(alpha) = git_recency_alpha {
                            state.add_metadata(GitRecencyConfigMetadata::new(alpha));
                        }
                    }

	                    let scheduler = IndexesLenTimeMinimizerScheduler::new(
	                        &edges_observer,
	                        GitAwareStdWeightedScheduler::with_schedule(
	                            &mut state,
	                            &edges_observer,
	                            Some(power_schedule),
	                        ),
	                    );
                        let scheduler = EnsureTestcaseIdsScheduler::new(scheduler);

                    // A fuzzer with feedbacks and a corpus scheduler
                    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

                    // The closure that we want to fuzz
                    let mut printed_inputs = 0usize;
                    let mut harness = |input: &BytesInput| {
                        let target = input.target_bytes();
                        if verbose && grammar_mode && printed_inputs < 20 {
                            let lossy = String::from_utf8_lossy(target.as_ref());
                            let quoted = serde_json::to_string(&lossy.as_ref())
                                .unwrap_or_else(|_| "\"<unprintable>\"".to_string());
                            eprintln!("GOLIBAFL_MUTATED_INPUT {}", quoted);
                            printed_inputs += 1;
                        }
                        unsafe {
                            libfuzzer_test_one_input(&target);
                        }
                        ExitKind::Ok
                    };

                    let executor = InProcessExecutor::with_timeout(
                        &mut harness,
                        tuple_list!(edges_observer, time_observer),
                        &mut fuzzer,
                        &mut state,
                        &mut restarting_mgr,
                        exec_timeout,
                    )?;

                    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

                    // Setup a tracing stage in which we log comparisons
                    let tracing = ShadowTracingStage::new();

                    if state.metadata_map().get::<Tokens>().is_none() {
                        let mut toks = Tokens::default();
                        toks += autotokens()?;

                        if !toks.is_empty() {
                            state.add_metadata(toks);
                        }
                    }

                    // Load corpus from input folder
                    // In case the corpus is empty (on first run), reset
		                    if state.must_load_initial_inputs() {
		                        let (input_readable, input_is_empty) = match read_dir(&input) {
		                            Ok(mut entries) => (true, entries.next().is_none()),
		                            Err(_) => (false, true),
		                        };
		                        let all_inputs_empty = input_is_empty && !resume_has_inputs;
		                        if all_inputs_empty {
		                            if verbose {
                                        if grammar_mode {
                                            eprintln!(
                                                "golibafl: input dir empty; generating {} initial inputs (grammar mode)",
                                                initial_generated_inputs
                                            );
                                        } else {
                                            eprintln!(
                                                "golibafl: input dir empty; generating {} initial inputs (max_len={})",
                                                initial_generated_inputs,
                                                initial_input_max_len
                                            );
                                        }
                            }
		                            if let Some(engine) = grammar_engine.as_ref() {
                                        let mut generator = GrammarinatorGenerator::new(engine.clone());
                                        state
                                            .generate_initial_inputs(
                                                &mut fuzzer,
                                                &mut executor,
                                                &mut generator,
                                                &mut restarting_mgr,
                                                initial_generated_inputs,
                                            )
                                            .expect("Failed to generate the initial corpus");
                                    } else {
                                        // Generator of printable bytearrays of max size initial_input_max_len
                                        let mut generator = RandBytesGenerator::new(initial_input_max_len);
                                        state
                                            .generate_initial_inputs(
                                                &mut fuzzer,
                                                &mut executor,
                                                &mut generator,
                                                &mut restarting_mgr,
                                                initial_generated_inputs,
                                            )
                                            .expect("Failed to generate the initial corpus");
                                    }
                            if verbose {
                                eprintln!(
                                    "golibafl: generated initial corpus size={}",
                                    state.corpus().count()
                                );
                            }
                            println!(
                                "We imported {} inputs from the generator.",
                                state.corpus().count()
                            );
		                        } else {
		                            if input_readable {
		                                eprintln!("Loading from {input:?}");
		                            } else if resume_has_inputs && verbose {
		                                eprintln!(
		                                    "golibafl: input dir {input:?} missing/unreadable; resuming only"
		                                );
		                            }
		                            if resume_has_inputs {
		                                eprintln!("Resuming corpus from {}", resume_bucket_dir.display());
		                            }
		                            // Load from disk
		                            let mut in_dirs = Vec::with_capacity(
		                                usize::from(input_readable) + usize::from(resume_has_inputs),
		                            );
		                            if input_readable {
		                                in_dirs.push(input.to_path_buf());
		                            }
		                            if resume_has_inputs {
		                                in_dirs.push(resume_bucket_dir.clone());
		                            }
	                            let load_res = if resume_has_inputs {
	                                state.load_initial_inputs_forced(
	                                    &mut fuzzer,
	                                    &mut executor,
	                                    &mut restarting_mgr,
	                                    &in_dirs,
	                                )
	                            } else {
	                                state.load_initial_inputs(
	                                    &mut fuzzer,
	                                    &mut executor,
	                                    &mut restarting_mgr,
	                                    &in_dirs,
	                                )
	                            };
	                            load_res.unwrap_or_else(|err| {
	                                panic!("Failed to load initial corpus at {input:?}: {err:?}");
	                            });
	                            let disk_inputs = state.corpus().count();
	                            println!("We imported {} inputs from disk.", disk_inputs);
	                            if resume_has_inputs {
	                                if let Err(err) = fs::remove_dir_all(&resume_bucket_dir) {
	                                    eprintln!(
	                                        "golibafl: warning: failed to remove resume directory {}: {err}",
	                                        resume_bucket_dir.display()
	                                    );
	                                }
	                            }
		                            if disk_inputs == 0 {
		                                // If importing the initial corpus already produced timeouts,
		                                // confirm them immediately. Otherwise, we may get stuck trying
		                                // to generate a non-timing-out initial corpus for a hangy
		                                // target.
		                                if catch_hangs && hang_candidate_path.exists() {
		                                    let exe = env::current_exe().unwrap_or_else(|err| {
		                                        eprintln!("golibafl: failed to get current exe path: {err}");
		                                        std::process::exit(2);
		                                    });
		                                    match confirm_timeout_candidate(
		                                        &exe,
		                                        &hang_candidate_path,
		                                        hang_timeout,
		                                        hang_confirm_runs,
		                                        &hangs_dir,
		                                        &crashes_dir,
		                                        &client_id,
		                                    ) {
		                                        TimeoutCandidateVerdict::NotHang => (),
		                                        TimeoutCandidateVerdict::Hang(p)
		                                        | TimeoutCandidateVerdict::Crash(p) => {
		                                            if verbose {
		                                                eprintln!(
		                                                    "golibafl: timeout candidate confirmed during init load; saved: {}",
		                                                    p.display()
		                                                );
		                                            }
		                                            if stop_all_fuzzers_on_panic {
		                                                let executions = *state.executions();
		                                                restarting_mgr.fire(
		                                                    &mut state,
		                                                    EventWithStats::with_current_time(
		                                                        Event::<BytesInput>::Stop,
		                                                        executions,
		                                                    ),
		                                                )?;
		                                                state.request_stop();
		                                                restarting_mgr.send_exiting()?;
		                                                return Err(Error::shutting_down());
		                                            }
		                                        }
		                                    }
		                                }

		                                if let Some(engine) = grammar_engine.as_ref() {
                                            let mut generator = GrammarinatorGenerator::new(engine.clone());
                                            state
                                                .generate_initial_inputs(
                                                    &mut fuzzer,
                                                    &mut executor,
                                                    &mut generator,
                                                    &mut restarting_mgr,
                                                    initial_generated_inputs,
                                                )
                                                .expect("Failed to generate the initial corpus");
                                        } else {
                                            // Generator of printable bytearrays of max size initial_input_max_len
                                            let mut generator = RandBytesGenerator::new(initial_input_max_len);
                                            state
                                                .generate_initial_inputs(
                                                    &mut fuzzer,
                                                    &mut executor,
                                                    &mut generator,
                                                    &mut restarting_mgr,
                                                    initial_generated_inputs,
                                                )
                                                .expect("Failed to generate the initial corpus");
                                        }
                                println!(
                                    "We imported {} inputs from the generator.",
                                    state.corpus().count()
                                );
                            }
                        }
                    }

	                    if stop_all_fuzzers_on_panic && state.solutions().count() > initial_solutions {
	                        let executions = *state.executions();
	                        restarting_mgr.fire(
	                            &mut state,
	                            EventWithStats::with_current_time(
	                                Event::<BytesInput>::Stop,
	                                executions,
	                            ),
	                        )?;
	                        state.request_stop();
	                        restarting_mgr.send_exiting()?;
	                        return Err(Error::shutting_down());
	                    }

	                    // Timeouts can occur while importing/generating the initial corpus. Confirm
	                    // them as hangs/crashes here too, otherwise the fuzzer can get wedged before
	                    // entering the main fuzzing loop.
	                    if catch_hangs && hang_candidate_path.exists() {
	                        let exe = env::current_exe().unwrap_or_else(|err| {
	                            eprintln!("golibafl: failed to get current exe path: {err}");
	                            std::process::exit(2);
	                        });
	                        match confirm_timeout_candidate(
	                            &exe,
	                            &hang_candidate_path,
	                            hang_timeout,
	                            hang_confirm_runs,
	                            &hangs_dir,
	                            &crashes_dir,
	                            &client_id,
	                        ) {
	                            TimeoutCandidateVerdict::NotHang => (),
	                            TimeoutCandidateVerdict::Hang(p) | TimeoutCandidateVerdict::Crash(p) => {
	                                if verbose {
	                                    eprintln!(
	                                        "golibafl: timeout candidate confirmed during init; saved: {}",
	                                        p.display()
	                                    );
	                                }
	                                if stop_all_fuzzers_on_panic {
	                                    let executions = *state.executions();
	                                    restarting_mgr.fire(
	                                        &mut state,
	                                        EventWithStats::with_current_time(
	                                            Event::<BytesInput>::Stop,
	                                            executions,
	                                        ),
	                                    )?;
	                                    state.request_stop();
	                                    restarting_mgr.send_exiting()?;
	                                    return Err(Error::shutting_down());
	                                }
	                            }
	                        }
	                    }

                        if let Some(engine) = grammar_engine.as_ref() {
                            let grammar_stage = StdMutationalStage::with_max_iterations(
                                GrammarinatorMutator::new(engine.clone()),
                                std::num::NonZeroUsize::new(1).unwrap(),
                            );
                            let mut stages = tuple_list!(calibration, tracing, grammar_stage);

                            loop {
                                if let Err(err) =
                                    restarting_mgr.maybe_report_progress(&mut state, monitor_timeout)
                                {
                                    if matches!(err, Error::ShuttingDown) {
                                        let _ = restarting_mgr.send_exiting();
                                        notify_restarting_mgr_exit();
                                    }
                                    return Err(err);
                                }

                                if let Err(err) = fuzzer.fuzz_one(
                                    &mut stages,
                                    &mut executor,
                                    &mut state,
                                    &mut restarting_mgr,
                                ) {
                                    if matches!(err, Error::ShuttingDown) {
                                        let _ = restarting_mgr.send_exiting();
                                        notify_restarting_mgr_exit();
                                    }
                                    return Err(err);
                                }

                                if catch_hangs && hang_candidate_path.exists() {
                                    let exe = env::current_exe().unwrap_or_else(|err| {
                                        eprintln!("golibafl: failed to get current exe path: {err}");
                                        std::process::exit(2);
                                    });
                                    match confirm_timeout_candidate(
                                        &exe,
                                        &hang_candidate_path,
                                        hang_timeout,
                                        hang_confirm_runs,
                                        &hangs_dir,
                                        &crashes_dir,
                                        &client_id,
                                    ) {
                                        TimeoutCandidateVerdict::NotHang => (),
                                        TimeoutCandidateVerdict::Hang(p)
                                        | TimeoutCandidateVerdict::Crash(p) => {
                                            if verbose {
                                                eprintln!(
                                                    "golibafl: timeout candidate confirmed; saved: {}",
                                                    p.display()
                                                );
                                            }
                                            if stop_all_fuzzers_on_panic {
                                                let executions = *state.executions();
                                                restarting_mgr.fire(
                                                    &mut state,
                                                    EventWithStats::with_current_time(
                                                        Event::<BytesInput>::Stop,
                                                        executions,
                                                    ),
                                                )?;
                                                state.request_stop();
                                                restarting_mgr.send_exiting()?;
                                                return Err(Error::shutting_down());
                                            }
                                        }
                                    }
                                }

                                if stop_all_fuzzers_on_panic
                                    && state.solutions().count() > initial_solutions
                                {
                                    let executions = *state.executions();
                                    restarting_mgr.fire(
                                        &mut state,
                                        EventWithStats::with_current_time(
                                            Event::<BytesInput>::Stop,
                                            executions,
                                        ),
                                    )?;
                                    state.request_stop();
                                    restarting_mgr.send_exiting()?;
                                    return Err(Error::shutting_down());
                                }
                            }
                        } else {
                            // Setup a randomic Input2State stage
                            let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
                                I2SRandReplace::new()
                            )));

                            // Setup a MOPT mutator
                            let mutator = StdMOptMutator::new(
                                &mut state,
                                havoc_mutations().merge(tokens_mutations()),
                                7,
                                5,
                            )?;
                            let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> =
                                StdPowerMutationalStage::new(mutator);

                            let mut stages = tuple_list!(calibration, tracing, i2s, power);

                            loop {
                                if let Err(err) =
                                    restarting_mgr.maybe_report_progress(&mut state, monitor_timeout)
                                {
                                    if matches!(err, Error::ShuttingDown) {
                                        let _ = restarting_mgr.send_exiting();
                                        notify_restarting_mgr_exit();
                                    }
                                    return Err(err);
                                }

                                if let Err(err) = fuzzer.fuzz_one(
                                    &mut stages,
                                    &mut executor,
                                    &mut state,
                                    &mut restarting_mgr,
                                ) {
                                    if matches!(err, Error::ShuttingDown) {
                                        let _ = restarting_mgr.send_exiting();
                                        notify_restarting_mgr_exit();
                                    }
                                    return Err(err);
                                }

                                if catch_hangs && hang_candidate_path.exists() {
                                    let exe = env::current_exe().unwrap_or_else(|err| {
                                        eprintln!("golibafl: failed to get current exe path: {err}");
                                        std::process::exit(2);
                                    });
                                    match confirm_timeout_candidate(
                                        &exe,
                                        &hang_candidate_path,
                                        hang_timeout,
                                        hang_confirm_runs,
                                        &hangs_dir,
                                        &crashes_dir,
                                        &client_id,
                                    ) {
                                        TimeoutCandidateVerdict::NotHang => (),
                                        TimeoutCandidateVerdict::Hang(p)
                                        | TimeoutCandidateVerdict::Crash(p) => {
                                            if verbose {
                                                eprintln!(
                                                    "golibafl: timeout candidate confirmed; saved: {}",
                                                    p.display()
                                                );
                                            }
                                            if stop_all_fuzzers_on_panic {
                                                let executions = *state.executions();
                                                restarting_mgr.fire(
                                                    &mut state,
                                                    EventWithStats::with_current_time(
                                                        Event::<BytesInput>::Stop,
                                                        executions,
                                                    ),
                                                )?;
                                                state.request_stop();
                                                restarting_mgr.send_exiting()?;
                                                return Err(Error::shutting_down());
                                            }
                                        }
                                    }
                                }

                                if stop_all_fuzzers_on_panic
                                    && state.solutions().count() > initial_solutions
                                {
                                    let executions = *state.executions();
                                    restarting_mgr.fire(
                                        &mut state,
                                        EventWithStats::with_current_time(
                                            Event::<BytesInput>::Stop,
                                            executions,
                                        ),
                                    )?;
                                    state.request_stop();
                                    restarting_mgr.send_exiting()?;
                                    return Err(Error::shutting_down());
                                }
                            }
                        }
                }};
            }

        match counters_map_len {
            1 => {
                let edges = unsafe { extra_counters() };
                let edges = edges.into_iter().next().unwrap();
                run_with_edges_observer!(
                    StdMapObserver::from_mut_slice("edges", edges),
                    MaxMapFeedback
                )
            }
            n if n > 1 => {
                let edges = unsafe { extra_counters() };
                run_with_edges_observer!(
                    MultiMapObserver::new("edges", edges),
                    NonSimdMaxMapFeedback
                )
            }
            _ => panic!("No coverage maps available; cannot fuzz!"),
        }
    };

    let launch_res = if tui_monitor {
        let monitor = TuiMonitor::builder().build();
        Launcher::builder()
            .shmem_provider(shmem_provider)
            .configuration(EventConfig::from_name("default"))
            .monitor(monitor)
            .run_client(&mut run_client)
            .cores(&effective_cores)
            .broker_port(broker_port)
            .serialize_state(ShouldSaveState::OOMSafeOnRestart)
            .fork(false)
            .build()
            .launch_with_hooks::<_, BytesInput, _>(tuple_list!(StopOnObjectiveHook {
                enabled: stop_all_fuzzers_on_panic,
            }))
    } else {
        let monitor = SimpleMonitor::new(|s| println!("{s}"));
        Launcher::builder()
            .shmem_provider(shmem_provider)
            .configuration(EventConfig::from_name("default"))
            .monitor(monitor)
            .run_client(&mut run_client)
            .cores(&effective_cores)
            .broker_port(broker_port)
            .serialize_state(ShouldSaveState::OOMSafeOnRestart)
            .fork(false)
            .build()
            .launch_with_hooks::<_, BytesInput, _>(tuple_list!(StopOnObjectiveHook {
                enabled: stop_all_fuzzers_on_panic,
            }))
    };

    match &launch_res {
        Ok(()) | Err(Error::ShuttingDown) => (),
        Err(err) => {
            if env::var_os("GOSENTRY_VERBOSE_AFL").is_some() {
                let diag = launch_diagnostics(err);
                eprint!("{diag}");
                let diag_path = output.join(format!(
                    "golibafl_launcher_failure_{}.txt",
                    std::process::id()
                ));
                if fs::write(&diag_path, diag.as_bytes()).is_ok() {
                    eprintln!(
                        "golibafl: wrote launcher diagnostics to {}",
                        diag_path.display()
                    );
                }
            }
            panic!("Failed to run launcher: {err:?}");
        }
    };

    let hang_inputs = list_hang_inputs(&hangs_dir);
    let crash_inputs = list_crash_inputs(&crashes_dir);
    let new_hangs = if catch_hangs {
        hang_inputs.len().saturating_sub(initial_hang_inputs)
    } else {
        0
    };
    let new_crashes = crash_inputs.len().saturating_sub(initial_crash_inputs);

    if new_hangs > 0 || new_crashes > 0 {
        if !is_launcher_client {
            if new_hangs > 0 {
                eprintln!("Found {new_hangs} hanging input(s).");
                eprintln!("libafl output dir: {}", output.display());
                eprintln!("hangs dir: {}", hangs_dir.display());

                let mut sorted = hang_inputs;
                sorted.sort_by_key(|p| {
                    fs::metadata(p)
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                });
                for p in sorted.iter().rev().take(new_hangs) {
                    eprintln!("hang input: {}", p.display());
                    if let Ok(exe) = env::current_exe() {
                        eprintln!(
                            "repro (kill after {}ms): {} run --input {}",
                            hang_timeout.as_millis(),
                            exe.display(),
                            p.display()
                        );
                    } else {
                        eprintln!(
                            "repro (kill after {}ms): golibafl run --input {}",
                            hang_timeout.as_millis(),
                            p.display()
                        );
                    }
                }
            }

            if new_crashes > 0 {
                eprintln!("Found {new_crashes} crashing input(s).");
                eprintln!("libafl output dir: {}", output.display());
                eprintln!("crashes dir: {}", crashes_dir.display());

                let mut sorted = crash_inputs;
                sorted.sort_by_key(|p| {
                    fs::metadata(p)
                        .and_then(|m| m.modified())
                        .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                });
                for p in sorted.iter().rev().take(new_crashes) {
                    eprintln!("crash input: {}", p.display());
                    if let Ok(exe) = env::current_exe() {
                        eprintln!("repro: {} run --input {}", exe.display(), p.display());
                    } else {
                        eprintln!("repro: golibafl run --input {}", p.display());
                    }
                }

                eprintln!(
                    "(Crash output is printed above; rerun the repro command to see it again.)"
                );
            }

            if stop_all_fuzzers_on_panic {
                notify_restarting_mgr_exit();
                std::process::exit(1);
            }
        }
        return;
    }

    if matches!(launch_res, Err(Error::ShuttingDown)) {
        notify_restarting_mgr_exit();
        println!("Fuzzing stopped by user. Good bye.");
    }
}

fn cov(output_dir: &Path, harness_dir: &Path, coverage_filter: Option<String>) {
    let mut test_code = String::from(include_str!("../harness_wrappers/harness_test.go"));

    let output_dir = if output_dir.is_relative() {
        &format!(
            "{}/{}",
            env!("CARGO_MANIFEST_DIR"),
            output_dir.as_os_str().to_str().unwrap()
        )
    } else {
        output_dir.as_os_str().to_str().unwrap()
    };

    let harness_dir = harness_dir
        .as_os_str()
        .to_str()
        .expect("Harness dir not valid unicode");

    test_code = test_code.replace("REPLACE_ME", output_dir);

    fs::write(format!("{}/harness_test.go", harness_dir), test_code)
        .expect("Failed to write coverage go file");

    let output = Command::new("go")
        .args(["list", "-deps", "-test"])
        .current_dir(harness_dir)
        .output()
        .expect("Failed to execute go");

    let filter_terms: Vec<&str> = if let Some(coverage_filter) = coverage_filter.as_ref() {
        coverage_filter
            .split(",")
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    let deps_raw = String::from_utf8_lossy(&output.stdout);
    let mut packages: Vec<&str> = deps_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();

    if !filter_terms.is_empty() {
        packages.retain(|p| filter_terms.iter().any(|t| p.contains(t)));
    }

    let status = Command::new("go")
        .args([
            "test",
            "-tags=gocov",
            "-run=FuzzMe",
            "-cover",
            &format!("-coverpkg={}", packages.join(",")),
            "-coverprofile",
            "cover.out",
        ])
        .current_dir(harness_dir)
        .stdout(Stdio::null())
        .status();

    fs::remove_file(format!("{}/harness_test.go", harness_dir))
        .expect("Failed to remove coverage file");

    // make sure we unpack status after we removed file
    status.expect("Failed to execute go");

    Command::new("go")
        .args(["tool", "cover", "-html", "cover.out", "-o", "cover.html"])
        .current_dir(harness_dir)
        .status()
        .expect("Failed to execute go");

    println!("Coverage files succesfully created in {}", harness_dir)
}

// Entry point wrapping clap and calling fuzz, run or cov
pub fn main() {
    let cli = Cli::parse();

    match cli.mode {
        Mode::Fuzz {
            config,
            cores,
            broker_port,
            input,
            output,
            use_grammar,
            grammar,
            start_rule,
            grammar_actions,
            grammar_serializer,
            grammarinator_dir,
            grammar_max_depth,
            grammar_max_tokens,
        } => {
            let broker_port = resolve_broker_port(broker_port);
            let grammar_cfg = if use_grammar {
                if grammar.is_empty() {
                    eprintln!("golibafl: --use-grammar requires --grammar");
                    std::process::exit(2);
                }
                let start_rule = start_rule.unwrap_or_else(|| {
                    eprintln!("golibafl: --use-grammar requires --start-rule");
                    std::process::exit(2);
                });
                Some(GrammarinatorConfig {
                    grammar,
                    start_rule,
                    actions: grammar_actions,
                    serializer: grammar_serializer,
                    grammarinator_dir,
                    max_depth: grammar_max_depth,
                    max_tokens: grammar_max_tokens,
                })
            } else {
                if !grammar.is_empty()
                    || start_rule.is_some()
                    || grammar_actions
                    || grammar_serializer.is_some()
                    || grammarinator_dir.is_some()
                {
                    eprintln!(
                        "golibafl: --grammar/--start-rule/--grammar-actions/--grammar-serializer/--grammarinator-dir require --use-grammar"
                    );
                    std::process::exit(2);
                }
                None
            };

            fuzz(
                &cores,
                broker_port,
                &input,
                &output,
                config.as_ref(),
                grammar_cfg.as_ref(),
            )
        }
        Mode::Run { input } => {
            run(input);
        }
        Mode::Cov {
            output,
            fuzzer_harness,
            coverage_filter,
        } => cov(&output, &fuzzer_harness, coverage_filter),
    }
}
