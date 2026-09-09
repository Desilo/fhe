#!/usr/bin/python3

import re
import subprocess
from argparse import ArgumentParser
from dataclasses import dataclass, field
from functools import cached_property
from math import ceil, log
from pathlib import Path
from threading import Lock, Thread
from time import sleep
from timeit import default_timer as timer


@dataclass
class FailOutput:
    lines: list[str]
    printed: bool = False

    def __str__(self):
        return "".join(self.lines)


@dataclass
class TestSuite:
    executable: Path
    gather_index: int
    name: str
    test_filter: str | None
    setup: str
    specific: bool = False

    finished: bool = False
    printed: bool = False
    count: int = 0
    run: int = 0
    ok: int = 0
    skipped: int = 0
    failed: int = 0
    fail_outputs: list[FailOutput] = field(default_factory=list)

    thread_id: int | None = None

    @cached_property
    def heavy(self):
        if self.specific:
            return False

        if self.setup == "daily":
            pattern = r"^(CKKSEngineBootstrap.*|.*SPE3\.)$"
            return re.match(pattern, self.name)

        if self.setup == "full":
            pattern = r"^CKKSEngine(Bootstrap|Leveled|ReadWrite)"
            return re.match(pattern, self.name)

        return self.name in set(
            (
                "CKKSEngineBootstrap/Silver.",
                "CKKSEngineBootstrap/Gold.",
                "SandCKKSEngineMultiplyMatrix.",
            )
        )

    @property
    def done(self):
        return self.ok + self.skipped + self.failed

    def run_tests(self):
        test_filter = f"--gtest_filter={self.name}"

        if not self.specific:
            test_filter += "*"

        if self.test_filter:
            test_filter += f":{self.test_filter}"

        self.start = timer()

        with subprocess.Popen(
            [self.executable, test_filter],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ) as process:
            output = []
            running = False
            for line in process.stdout:
                if line.startswith("[ RUN      ]"):
                    self.run += 1
                    running = True
                    output = [line]
                elif running:
                    if line.startswith("[       OK ]"):
                        self.ok += 1
                        running = False
                    if line.startswith("[  SKIPPED ]"):
                        self.skipped += 1
                        running = False
                    elif line.startswith("[  FAILED  ]"):
                        self.failed += 1
                        running = False
                        output.append(line)
                        self.fail_outputs.append(FailOutput(output))
                    else:
                        output.append(line)
            if running:
                # In case of abnormal termination
                self.fail_outputs.append(FailOutput(output))

        self.finished = True
        end = timer()
        self.elapsed = end - self.start


class RunnerThread(Thread):
    def __init__(self, runner, thread_id):
        super().__init__()

        self.runner = runner
        self.thread_id = thread_id
        self.suite = None
        self.finished = False

    def run(self):
        while True:
            suite = self.runner.get_next_test_suite(self.thread_id)
            self.suite = suite
            if suite is None:
                break
            suite.run_tests()
        self.finished = True


@dataclass
class TestRunner:
    def __init__(self, setup, thread_count, heavy_thread_count):
        self.setup = setup
        self.threads = [
            RunnerThread(self, thread_id) for thread_id in range(thread_count)
        ]
        self.heavy_thread_count = heavy_thread_count

        self.suites = []
        self.gather_index = 0
        self.suites_lock = Lock()

        self.printed = False
        self.start = timer()
        self.end = None

    def gather(self, executable_path, test_filter=None):
        command = [executable_path, "--gtest_list_tests"]

        if test_filter:
            command += [f"--gtest_filter={test_filter}"]

        completed_process = subprocess.run(
            command, capture_output=True, text=True
        )

        self.gather_index += 1
        gather_index = self.gather_index
        split_prefix = None
        for line in completed_process.stdout.splitlines()[1:]:
            if line[0].isalpha():
                if self.setup == "daily" and line in set(
                    (
                        "CKKSEngineBootstrap/"
                        "BootstrapSparseGoldLogSlotCount5And1StagesSmall.",
                        "CKKSEngineBootstrap/"
                        "BootstrapSparseGoldLogSlotCount10And2StagesSmall.",
                        "CKKSEngineBootstrap/Gold.",
                        "CKKSEngineLeveled.",
                    )
                ):
                    split_prefix = line
                else:
                    split_prefix = None
                    self.suites.append(
                        TestSuite(
                            executable_path,
                            gather_index,
                            line,
                            test_filter,
                            self.setup,
                        )
                    )
            else:
                if split_prefix:
                    self.suites.append(
                        TestSuite(
                            executable_path,
                            gather_index,
                            split_prefix + line.split("#")[0].strip(),
                            None,
                            self.setup,
                            specific=True,
                        )
                    )

                self.suites[-1].count += 1

    def get_next_test_suite(self, thread_id):
        with self.suites_lock:
            for suite in self.suites:
                # only top N threads will process heavy tasks
                # which are currently all bootstrap tests
                if suite.heavy and thread_id >= self.heavy_thread_count:
                    continue

                if suite.thread_id is None:
                    suite.thread_id = thread_id
                    return suite

        return None

    def sort_suites(self):
        # False < True, so to sort heavy suites first we have to negate the key.
        self.suites = sorted(
            self.suites,
            key=lambda suite: (
                not suite.heavy,
                suite.gather_index,
                suite.name,
            ),
        )

    def start_threads(self):
        for thread in self.threads:
            thread.start()

    def join_threads(self):
        for thread in self.threads:
            thread.join()
        self.end = timer()

    @cached_property
    def test_count(self):
        return sum(suite.count for suite in self.suites)

    @cached_property
    def log_test_count(self):
        return max(ceil(log(self.test_count, 10)), 1)

    @property
    def suite_count(self):
        return len(self.suites)

    @property
    def finished(self):
        return all(suite.finished for suite in self.suites)

    @property
    def elapsed_time(self):
        if self.end:
            return self.end - self.start
        return timer() - self.start


class Logger:
    def __init__(self, output_path, setup):
        self.output_path = output_path
        self.setup = setup

        if self.output_path:
            self.output_file = open(self.output_path, "w")
        else:
            self.output_file = None

        self.printed = False

    def __del__(self):
        if self.output_file:
            self.output_file.close()

    def colorize(self, text, color):
        if self.output_file:
            # Cannot colorize when writing to a file.
            return text

        # For details, searching for "ANSI escape sequence" is recommended.
        match color:
            case "red":
                return f"\033[31m{text}\033[0m"
            case "green":
                return f"\033[32m{text}\033[0m"
            case "gray":
                return f"\033[90m{text}\033[0m"

        return text

    def format_elapsed(self, elapsed):
        return self.colorize(f"{elapsed:10.3f}s ", "gray")

    def format_test_suite(self, suite):
        status = ""
        count = f"{suite.done}/{suite.count}"

        if suite.finished:
            status = self.format_elapsed(suite.elapsed)

            if not suite.failed and suite.done == suite.count:
                status += "✅ "
                count = self.colorize(count, "green")
            else:
                status += "❌ "
                count = self.colorize(count, "red")
        else:
            elapsed = timer() - suite.start if suite.start else 0
            status = self.format_elapsed(elapsed)

        if suite.failed:
            count += f" Failure {suite.failed}"

        return f"{status}{suite.name} {count}"

    def format_runner_thread(self, thread):
        if thread.finished:
            if self.setup != "local":
                return None

            name = self.colorize(f"   Thread {thread.thread_id}", "gray")
            return f"{name} ✅"

        return self.format_test_suite(thread.suite)

    def log(self, string=""):
        if self.output_file:
            self.output_file.write(f"{string}\n")
        elif string is not None:
            print(string)

    def log_runner(self, runner):
        test_count = runner.test_count
        suite_count = runner.suite_count
        done_test_count = sum(suite.done for suite in runner.suites)
        finished_suite_count = sum(suite.finished for suite in runner.suites)
        log_test_count = runner.log_test_count

        if self.printed:
            if self.output_file is None:
                # Move the cursor up by the printed length to reset the display,
                # then move it up one more line so everything can be rewritten from the top.
                # For details, searching for "ANSI escape sequence" is recommended.
                if self.setup == "local":
                    print(f"\033[{len(runner.threads) + 4}A\033[J\033[A")
            else:
                self.log()
        else:
            self.printed = True

        printed = False
        for suite in runner.suites:
            for fail_output in suite.fail_outputs:
                if not fail_output.printed:
                    self.log(self.colorize(str(fail_output), "red"))
                    fail_output.printed = True
                    printed = True

            if suite.finished and not suite.printed:
                self.log(self.format_test_suite(suite))
                suite.printed = True
                printed = True

        if printed or self.output_file is None:
            self.log()

        self.log(
            self.format_elapsed(runner.elapsed_time)
            + f"{str(finished_suite_count).rjust(log_test_count + 4)}/"
            + f"{str(suite_count).ljust(log_test_count)} Suites"
        )
        self.log(
            f"{str(done_test_count).rjust(log_test_count + 16)}/"
            f"{str(test_count).ljust(log_test_count)} Test cases"
        )
        self.log()

        for thread in runner.threads:
            self.log(self.format_runner_thread(thread))

        if self.output_file:
            self.output_file.flush()

    def log_finished(self, runner):
        self.log_runner(runner)

        self.log()

        printed = False
        failed = False
        for suite in runner.suites:
            for fail_output in suite.fail_outputs:
                self.log(self.colorize(str(fail_output), "red"))
                printed = True
                failed = True

        if printed:
            self.log()

        self.log(
            self.format_elapsed(runner.elapsed_time)
            + f" Finished running {runner.test_count} tests "
            + f"from {runner.suite_count} test suites."
        )

        return failed


def run():
    parser = ArgumentParser()
    parser.add_argument("-j", "--threads", type=int, default=8)

    def get_default_path():
        return Path(__file__).resolve().parent / "build"

    parser.add_argument(
        "-d", "--directory", type=Path, default=get_default_path()
    )

    parser.add_argument("-u", "--unit", action="store_true")
    parser.add_argument("-c", "--ckks-core", action="store_true")
    parser.add_argument("-e", "--ckks-engine", action="store_true")

    parser.add_argument("-i", "--interval", type=float)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument(
        "-t",
        "--tier",
        choices=[
            "sand",
            "pebble",
            "iron",
            "bronze",
            "silver",
            "gold",
            "platinum",
            "only-sand",
            "only-pebble",
            "only-iron",
            "only-bronze",
            "only-silver",
            "only-gold",
            "only-platinum",
        ],
        default="iron",
    )

    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--setup", choices=["local", "daily", "full"], default="local"
    )
    parser.add_argument("--heavy-threads", type=int, default=None)

    args = parser.parse_args()

    targets = set()
    if args.unit:
        targets.add("unit")
    if args.ckks_core:
        targets.add("ckks_core")
    if args.ckks_engine:
        targets.add("ckks_engine")
    if not targets:
        targets = set(("unit", "ckks_core", "ckks_engine"))

    # The current approach only supports exclude.
    unit_filter = None
    match args.tier:
        case "sand":
            ckks_filter = (
                "-*Pebble*:*Iron*:*Bronze*:*Silver*:*Gold*:*Platinum*"
            )
        case "pebble":
            ckks_filter = "-*Iron*:*Bronze*:*Silver*:*Gold*:*Platinum*"
        case "iron":
            ckks_filter = "-*Bronze*:*Silver*:*Gold*:*Platinum*"
        case "bronze":
            ckks_filter = "-*Silver*:*Gold*:*Platinum*"
        case "silver":
            ckks_filter = "-*Gold*:*Platinum*"
        case "gold":
            ckks_filter = "-*Platinum*"
        case "platinum":
            ckks_filter = None
        case "only-sand":
            ckks_filter = (
                "-*Pebble*:*Iron*:*Bronze*:*Silver*:*Gold*:*Platinum*"
            )
            targets.remove("unit")
        case "only-pebble":
            ckks_filter = "-*Sand*:*Iron*:*Bronze*:*Silver*:*Gold*:*Platinum*"
            targets.remove("unit")
        case "only-iron":
            ckks_filter = (
                "-*Sand*:*Pebble*:*Bronze*:*Silver*:*Gold*:*Platinum*"
            )
            targets.remove("unit")
        case "only-bronze":
            ckks_filter = "-*Sand*:*Pebble*:*Iron*:*Silver*:*Gold*:*Platinum*"
            targets.remove("unit")
        case "only-silver":
            ckks_filter = "-*Sand*:*Pebble*:*Iron*:*Bronze*:*Gold*:*Platinum*"
            targets.remove("unit")
        case "only-gold":
            ckks_filter = (
                "-*Sand*:*Pebble*:*Iron*:*Bronze*:*Silver*:*Platinum*"
            )
            targets.remove("unit")
        case "only-platinum":
            ckks_filter = "-*Sand*:*Pebble*:*Iron*:*Bronze*:*Silver*:*Gold*"
            targets.remove("unit")

    if not args.interval:
        interval = 60 if args.output else 0.1
    else:
        interval = args.interval

    heavy_thread_count = args.heavy_threads
    if heavy_thread_count is None:
        heavy_thread_count = args.threads

    runner = TestRunner(args.setup, args.threads, heavy_thread_count)
    if "unit" in targets:
        runner.gather(args.directory / "unit_test", unit_filter)
    if "ckks_core" in targets:
        for test in args.directory.glob("ckks_core_*_test"):
            runner.gather(test, ckks_filter)
    if "ckks_engine" in targets:
        for test in args.directory.glob("ckks_engine_*_test"):
            runner.gather(test, ckks_filter)

    runner.sort_suites()

    if args.dry_run:
        for suite in runner.suites:
            print(suite.name)
        return

    runner.start_threads()

    logger = Logger(args.output, args.setup)

    while not runner.finished:
        logger.log_runner(runner)
        sleep(interval)

    runner.join_threads()

    failed = logger.log_finished(runner)

    if failed:
        raise RuntimeError("Test failed")


if __name__ == "__main__":
    run()
