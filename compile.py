#!/usr/bin/env python3

import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser(
        description="Compile the project using CMake."
    )
    parser.add_argument(
        "--check_hardcoded",
        action="store_true",
        help="Enable Check Hardcoded",
    )
    parser.add_argument(
        "--configure", action="store_true", help="Configure project"
    )
    parser.add_argument(
        "--coverage", action="store_true", help="Enable Coverage"
    )
    parser.add_argument(
        "-d", "--debug", action="store_true", help="Enable Debug mode"
    )
    parser.add_argument(
        "-e", "--examples", action="store_true", help="Enable Examples"
    )
    parser.add_argument(
        "-g", "--google_test", action="store_true", help="Enable Google Test"
    )
    parser.add_argument(
        "-i",
        "--incremental_build",
        action="store_true",
        help="Enable Incremental Build",
    )
    parser.add_argument(
        "--unit_test", action="store_true", help="Enable Unit Test"
    )
    parser.add_argument(
        "--ckks_core_test", action="store_true", help="Enable CKKS Core Test"
    )
    parser.add_argument(
        "--ckks_engine_base_test",
        action="store_true",
        help="Enable CKKS Engine Base Test",
    )
    parser.add_argument(
        "--ckks_engine_sp_test",
        action="store_true",
        help="Enable CKKS Engine SP Test",
    )
    parser.add_argument(
        "--ckks_engine_spe_test",
        action="store_true",
        help="Enable CKKS Engine SPE Test",
    )
    parser.add_argument(
        "--ckks_engine_spx_test",
        action="store_true",
        help="Enable CKKS Engine SPX Test",
    )
    parser.add_argument(
        "--ckks_engine_reject_test",
        action="store_true",
        help="Enable CKKS Engine Reject Test",
    )
    parser.add_argument(
        "-l", "--large_test", action="store_true", help="Enable Large Test"
    )
    parser.add_argument(
        "-j",
        "--parallel",
        nargs="?",
        const=0,
        default=None,
        type=int,
        help="Enable Parallel Build",
    )

    args = parser.parse_args()
    args_dict = vars(args)

    # Enabling google_test:
    # a) enables all tests by default
    # b) exposes extra scheme presets for testing
    if args.google_test:
        args_dict["unit_test"] = True
        args_dict["ckks_core_test"] = True
        args_dict["ckks_engine_base_test"] = True
        args_dict["ckks_engine_sp_test"] = True
        args_dict["ckks_engine_spe_test"] = True
        args_dict["ckks_engine_spx_test"] = True
        args_dict["ckks_engine_reject_test"] = True
    elif (
        args.unit_test
        or args.ckks_core_test
        or args.ckks_engine_base_test
        or args.ckks_engine_sp_test
        or args.ckks_engine_spe_test
        or args.ckks_engine_spx_test
        or args.ckks_engine_reject_test
    ):
        args_dict["google_test"] = True

    build_directory = "build"

    compile_command = ["cmake", "-S", ".", "-B", build_directory]

    if args.incremental_build:
        compile_command.extend(["-G", "Ninja"])

    flags = {
        "check_hardcoded": "DESILO_FHE_CHECK_HARDCODED",
        "configure": "DESILO_FHE_CONFIGURE",
        "coverage": "DESILO_FHE_COVERAGE",
        "debug": "DESILO_FHE_DEBUG",
        "examples": "DESILO_FHE_EXAMPLES",
        "google_test": "DESILO_FHE_GOOGLE_TEST",
        "incremental_build": "DESILO_FHE_INCREMENTAL_BUILD",
        "unit_test": "DESILO_FHE_UNIT_TEST",
        "ckks_core_test": "DESILO_FHE_CKKS_CORE_TEST",
        "ckks_engine_base_test": "DESILO_FHE_CKKS_ENGINE_BASE_TEST",
        "ckks_engine_sp_test": "DESILO_FHE_CKKS_ENGINE_SP_TEST",
        "ckks_engine_spe_test": "DESILO_FHE_CKKS_ENGINE_SPE_TEST",
        "ckks_engine_spx_test": "DESILO_FHE_CKKS_ENGINE_SPX_TEST",
        "ckks_engine_reject_test": "DESILO_FHE_CKKS_ENGINE_REJECT_TEST",
        "large_test": "DESILO_FHE_LARGE_TEST",
    }

    compile_command.extend(
        [
            f'-D{flag}={"ON" if args_dict[arg] else "OFF"}'
            for arg, flag in flags.items()
        ]
    )

    subprocess.run(compile_command, check=True)

    if args.incremental_build:
        build_command = ["ninja", "-C", build_directory]

        # ninja runs in parallel by default
        if args.parallel is None:
            # we manually limit it to 1 job if --parallel is not specified
            build_command.append("-j1")
        elif args.parallel > 0:
            # -j0 means infinity for ninja build, but that might be consume
            # too many resources, so we just let ninja optimize itself
            # by giving no -j option
            build_command.append(f"-j{args.parallel}")

    else:
        build_command = ["cmake", "--build", build_directory]

        if args.parallel is not None:
            build_command.append("-j")
            # We ignore 0 here like we did for ninja build
            if args.parallel > 0:
                build_command.append(f"{args.parallel}")

    subprocess.run(build_command, check=True)


if __name__ == "__main__":
    main()
