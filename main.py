"""
Main CLI entry point for the Password & Credential Security Audit Suite.

Controlled laboratory security-testing toolkit for authorized
password-security assessment only.
"""

from config.settings import (
    DEFAULT_ATTEMPTS_PER_SECOND,
    REPORT_DIR,
    SUPPORTED_HASH_ALGORITHMS,
)
from core.cli_utils import (
    choose_from_list,
    pause,
    print_key_value,
    print_section,
    print_subsection,
    prompt_int,
    prompt_non_empty,
    prompt_yes_no,
)
from core.lab_workflow import LabWorkflow
from modules.brute_force_simulator import (
    BruteForceConfig,
    BruteForceSimulator,
)
from modules.crack_time_estimator import CrackTimeEstimator
from modules.mutation_engine import MutationEngine


APP_NAME = "PASSWORD & CREDENTIAL SECURITY AUDIT SUITE"
VERSION = "0.2.0"


def display_banner() -> None:
    """Display the application banner."""

    print("=" * 72)
    print(APP_NAME)
    print("=" * 72)
    print("Controlled laboratory security-testing toolkit")
    print("For authorized password-security assessment only")
    print(f"Version {VERSION}")
    print("=" * 72)


def display_menu() -> None:
    """Display the main application menu."""

    print()
    print_section("MAIN MENU")
    print("[1] Password Strength Analysis")
    print("[2] Dictionary Generator")
    print("[3] Dictionary Attack Simulation")
    print("[4] Brute-Force Simulation")
    print("[5] Hash Analyzer")
    print("[6] Offline Hash Audit")
    print("[7] Mutation / Hybrid Wordlist Generator")
    print("[8] Crack-Time Estimator")
    print("[9] Security Audit Report")
    print("[0] Exit")


def choose_hash_algorithm() -> str:
    """Choose a supported hashing algorithm."""

    options = [
        (algorithm, label)
        for algorithm, label in SUPPORTED_HASH_ALGORITHMS.items()
    ]

    return choose_from_list(
        "Select hash algorithm",
        options,
    )


def print_values(values: list[str]) -> None:
    """Print a simple bullet list without depending on cli_utils.print_list."""

    for value in values:
        print(f"  - {value}")


def run_password_strength_analysis(workflow: LabWorkflow) -> None:
    """Analyze a laboratory password."""

    print_section("PASSWORD STRENGTH ANALYSIS")

    password = prompt_non_empty(
        "Enter laboratory test password: "
    )

    result = workflow.analyze_password(password)

    print_subsection("PASSWORD ANALYSIS")

    print_key_value("Length", result.length)
    print_key_value("Character space", result.character_space)
    print_key_value(
        "Entropy bits",
        f"{result.entropy_bits:.2f}",
    )
    print_key_value("Lowercase", result.has_lowercase)
    print_key_value("Uppercase", result.has_uppercase)
    print_key_value("Digits", result.has_digits)
    print_key_value("Symbols", result.has_symbols)
    print_key_value(
        "Unique characters",
        result.unique_characters,
    )
    print_key_value(
        "Common password",
        result.is_common_password,
    )
    print_key_value(
        "Repeated pattern",
        result.has_repeated_pattern,
    )
    print_key_value(
        "Sequential pattern",
        result.has_sequential_pattern,
    )
    print_key_value(
        "Keyboard pattern",
        result.has_keyboard_pattern,
    )
    print_key_value(
        "Year pattern",
        result.has_year_pattern,
    )
    print_key_value(
        "Leetspeak",
        result.has_leetspeak,
    )
    print_key_value(
        "Predictability score",
        f"{result.predictability_score:.2f}",
    )
    print_key_value(
        "Security score",
        f"{result.security_score:.2f}",
    )
    print_key_value(
        "Strength",
        result.strength,
    )

    if result.findings:
        print_subsection("FINDINGS")
        print_values(result.findings)

    if result.recommendations:
        print_subsection("RECOMMENDATIONS")
        print_values(result.recommendations)


# Compatibility name retained for the existing test suite and CLI.
def password_strength_menu(
    workflow: LabWorkflow | None = None,
) -> None:
    """Compatibility wrapper for password-strength analysis."""

    if workflow is None:
        workflow = LabWorkflow()

    run_password_strength_analysis(workflow)


def run_dictionary_generator(workflow: LabWorkflow) -> None:
    """Generate mutation-based dictionary candidates."""

    print_section("DICTIONARY GENERATOR")

    raw_words = prompt_non_empty(
        "Enter base words separated by commas: "
    )

    base_words = [
        word.strip()
        for word in raw_words.split(",")
        if word.strip()
    ]

    max_candidates = prompt_int(
        "Maximum candidates",
        minimum=1,
    )

    candidates = workflow.generate_mutations(
        base_words,
        max_candidates=max_candidates,
    )

    print_subsection("GENERATION RESULTS")

    print_key_value(
        "Base words",
        len(base_words),
    )
    print_key_value(
        "Generated candidates",
        len(candidates),
    )

    if candidates:
        print_subsection("SAMPLE CANDIDATES")
        print_values(candidates[:50])

    if prompt_yes_no(
        "Save generated dictionary to a file?",
        default=False,
    ):
        output_path = prompt_non_empty(
            "Output file path: "
        )

        engine = MutationEngine()

        path = engine.generate_to_file(
            base_words,
            output_path,
            max_candidates=max_candidates,
        )

        print_key_value("Saved", path)
    else:
        print("Dictionary saving skipped.")


def run_dictionary_attack(workflow: LabWorkflow) -> None:
    """Run a controlled offline dictionary attack."""

    print_section("DICTIONARY ATTACK SIMULATION")

    algorithm = choose_hash_algorithm()

    target_hash = prompt_non_empty(
        f"Enter {algorithm} laboratory target hash: "
    )

    wordlist_path = prompt_non_empty(
        "Wordlist path: "
    )

    mutate = prompt_yes_no(
        "Enable mutation / hybrid candidates?",
        default=False,
    )

    attempt_limit = prompt_int(
        "Attempt limit",
        minimum=1,
    )

    result = workflow.dictionary_attack_wordlist(
        target_hash=target_hash,
        algorithm=algorithm,
        wordlist_path=wordlist_path,
        mutate=mutate,
        attempt_limit=attempt_limit,
    )

    print_subsection("ATTACK RESULT")

    print_key_value(
        "Attack type",
        result.attack_type,
    )
    print_key_value(
        "Algorithm",
        result.algorithm,
    )
    print_key_value(
        "Candidates tested",
        result.candidates_tested,
    )
    print_key_value(
        "Match found",
        result.match_found,
    )

    if result.matched_password is not None:
        print_key_value(
            "Matched password",
            result.matched_password,
        )

    print_key_value(
        "Elapsed seconds",
        f"{result.elapsed_seconds:.6f}",
    )
    print_key_value(
        "Candidates/sec",
        f"{result.candidates_per_second:.2f}",
    )
    print_key_value(
        "Estimated search space",
        result.estimated_search_space,
    )
    print_key_value(
        "Attempt limit",
        result.attempt_limit,
    )
    print_key_value(
        "Termination",
        result.termination_reason,
    )
    print_key_value(
        "Status",
        result.status,
    )

    if result.metadata:
        print_subsection("METADATA")

        for key, value in result.metadata.items():
            print_key_value(key, value)


def run_brute_force(workflow: LabWorkflow) -> None:
    """Run a controlled offline brute-force simulation."""

    print_section("BRUTE-FORCE SIMULATION")

    algorithm = choose_hash_algorithm()

    target_hash = prompt_non_empty(
        f"Enter {algorithm} laboratory target hash: "
    )

    min_length = prompt_int(
        "Minimum password length",
        minimum=1,
    )

    max_length = prompt_int(
        "Maximum password length",
        minimum=min_length,
    )

    lowercase = prompt_yes_no(
        "Include lowercase letters?",
        default=True,
    )

    uppercase = prompt_yes_no(
        "Include uppercase letters?",
        default=False,
    )

    digits = prompt_yes_no(
        "Include digits?",
        default=False,
    )

    symbols = prompt_yes_no(
        "Include symbols?",
        default=False,
    )

    attempt_limit = prompt_int(
        "Attempt limit",
        minimum=1,
    )

    config = BruteForceConfig(
        minimum_length=min_length,
        maximum_length=max_length,
        use_lowercase=lowercase,
        use_uppercase=uppercase,
        use_digits=digits,
        use_symbols=symbols,
    )

    simulator = BruteForceSimulator(
        target_hash=target_hash,
        algorithm=algorithm,
        attempt_limit=attempt_limit,
    )

    result = simulator.run(config)

    print_subsection("ATTACK RESULT")

    print_key_value(
        "Attack type",
        result.attack_type,
    )
    print_key_value(
        "Algorithm",
        result.algorithm,
    )
    print_key_value(
        "Candidates tested",
        result.candidates_tested,
    )
    print_key_value(
        "Match found",
        result.match_found,
    )

    if result.matched_password is not None:
        print_key_value(
            "Matched password",
            result.matched_password,
        )

    print_key_value(
        "Elapsed seconds",
        f"{result.elapsed_seconds:.6f}",
    )
    print_key_value(
        "Candidates/sec",
        f"{result.candidates_per_second:.2f}",
    )
    print_key_value(
        "Estimated search space",
        result.estimated_search_space,
    )
    print_key_value(
        "Estimated total seconds",
        result.estimated_total_seconds,
    )
    print_key_value(
        "Attempt limit",
        result.attempt_limit,
    )
    print_key_value(
        "Termination",
        result.termination_reason,
    )
    print_key_value(
        "Status",
        result.status,
    )

    if result.metadata:
        print_subsection("CONFIGURATION")

        for key, value in result.metadata.items():
            print_key_value(key, value)


def run_hash_analyzer(workflow: LabWorkflow) -> None:
    """Analyze a supplied offline hash."""

    print_section("HASH ANALYZER")

    target_hash = prompt_non_empty(
        "Enter laboratory hash: "
    )

    result = workflow.analyze_hash(target_hash)

    print_subsection("HASH ANALYSIS")

    print_key_value(
        "Possible algorithms",
        ", ".join(result.possible_algorithms),
    )
    print_key_value(
        "Format type",
        result.format_type,
    )
    print_key_value(
        "Confidence",
        result.confidence,
    )
    print_key_value(
        "Hash length",
        result.length,
    )
    print_key_value(
        "Hexadecimal",
        result.hexadecimal,
    )
    print_key_value(
        "Security rating",
        result.security_rating,
    )
    print_key_value(
        "Salted format",
        result.salted_format,
    )

    if result.findings:
        print_subsection("FINDINGS")
        print_values(result.findings)

    if result.recommendations:
        print_subsection("RECOMMENDATIONS")
        print_values(result.recommendations)


def run_offline_hash_audit(workflow: LabWorkflow) -> None:
    """Generate and analyze a controlled laboratory hash."""

    print_section("OFFLINE HASH AUDIT")

    password = prompt_non_empty(
        "Enter laboratory test password: "
    )

    algorithm = choose_hash_algorithm()

    target_hash = workflow.generate_hash(
        password,
        algorithm,
    )

    print_subsection("GENERATED LABORATORY TARGET")

    print_key_value(
        "Algorithm",
        algorithm,
    )
    print_key_value(
        "Hash",
        target_hash,
    )

    password_analysis = workflow.analyze_password(
        password
    )

    hash_analysis = workflow.analyze_hash(
        target_hash
    )

    print_subsection("PASSWORD ANALYSIS")

    print_key_value(
        "Security score",
        f"{password_analysis.security_score:.2f}",
    )
    print_key_value(
        "Strength",
        password_analysis.strength,
    )
    print_key_value(
        "Entropy bits",
        f"{password_analysis.entropy_bits:.2f}",
    )

    if password_analysis.findings:
        print_subsection("PASSWORD FINDINGS")
        print_values(password_analysis.findings)

    if password_analysis.recommendations:
        print_subsection("PASSWORD RECOMMENDATIONS")
        print_values(
            password_analysis.recommendations
        )

    print_subsection("HASH ANALYSIS")

    print_key_value(
        "Possible algorithms",
        ", ".join(
            hash_analysis.possible_algorithms
        ),
    )
    print_key_value(
        "Format type",
        hash_analysis.format_type,
    )
    print_key_value(
        "Confidence",
        hash_analysis.confidence,
    )
    print_key_value(
        "Hash length",
        hash_analysis.length,
    )
    print_key_value(
        "Hexadecimal",
        hash_analysis.hexadecimal,
    )
    print_key_value(
        "Security rating",
        hash_analysis.security_rating,
    )
    print_key_value(
        "Salted format",
        hash_analysis.salted_format,
    )

    if hash_analysis.findings:
        print_subsection("HASH FINDINGS")
        print_values(hash_analysis.findings)

    if hash_analysis.recommendations:
        print_subsection("HASH RECOMMENDATIONS")
        print_values(
            hash_analysis.recommendations
        )


def run_mutation_generator(workflow: LabWorkflow) -> None:
    """Generate mutation and hybrid candidates."""

    print_section(
        "MUTATION / HYBRID WORDLIST GENERATOR"
    )

    raw_words = prompt_non_empty(
        "Enter base words separated by commas: "
    )

    base_words = [
        word.strip()
        for word in raw_words.split(",")
        if word.strip()
    ]

    max_candidates = prompt_int(
        "Maximum candidates",
        minimum=1,
    )

    mutations = workflow.generate_mutations(
        base_words,
        max_candidates=max_candidates,
    )

    print_subsection("MUTATION RESULTS")

    print_key_value(
        "Base candidates",
        len(base_words),
    )
    print_key_value(
        "Generated mutations",
        len(mutations),
    )

    if mutations:
        print_subsection("SAMPLE")
        print_values(mutations[:100])

    if prompt_yes_no(
        "Save mutations to a file?",
        default=False,
    ):
        output_path = prompt_non_empty(
            "Output file path: "
        )

        engine = MutationEngine()

        path = engine.generate_to_file(
            base_words,
            output_path,
            max_candidates=max_candidates,
        )

        print_key_value(
            "Saved",
            path,
        )
    else:
        print("Mutation saving skipped.")


def run_crack_time_estimator() -> None:
    """Estimate controlled brute-force crack time."""

    print_section("CRACK-TIME ESTIMATOR")

    password_length = prompt_int(
        "Password length",
        minimum=1,
    )

    character_set_size = prompt_int(
        "Character-set size",
        minimum=1,
    )

    attempts_per_second = prompt_int(
        "Attempts per second",
        minimum=1,
        default=DEFAULT_ATTEMPTS_PER_SECOND,
    )

    estimator = CrackTimeEstimator()

    result = estimator.estimate(
        password_length=password_length,
        character_set_size=character_set_size,
        attempts_per_second=attempts_per_second,
    )

    print_subsection("ESTIMATE")

    print_key_value(
        "Search space",
        result.search_space,
    )
    print_key_value(
        "Attempts/sec",
        result.attempts_per_second,
    )
    print_key_value(
        "Average-case attempts",
        result.average_case_attempts,
    )
    print_key_value(
        "Worst-case seconds",
        result.worst_case_seconds,
    )
    print_key_value(
        "Average-case seconds",
        result.average_case_seconds,
    )
    print_key_value(
        "Worst-case duration",
        result.human_readable_worst_case,
    )
    print_key_value(
        "Average-case duration",
        result.human_readable_average_case,
    )


def run_security_audit_report(
    workflow: LabWorkflow,
) -> None:
    """Generate a controlled security audit report."""

    print_section("SECURITY AUDIT REPORT")

    password = prompt_non_empty(
        "Enter laboratory test password: "
    )

    algorithm = choose_hash_algorithm()

    target_hash = workflow.generate_hash(
        password,
        algorithm,
    )

    report = workflow.build_audit(
        target_hash=target_hash,
        algorithm=algorithm,
        password=password,
        attack_results=[],
    )

    json_path, text_path = workflow.write_audit_report(
        report,
        output_stem=str(REPORT_DIR),
    )

    print_subsection("REPORT GENERATED")

    print_key_value(
        "Risk level",
        report.risk_level,
    )
    print_key_value(
        "JSON report",
        json_path,
    )
    print_key_value(
        "Text report",
        text_path,
    )

    if report.findings:
        print_subsection("FINDINGS")

        print_values(
            [
                finding.title
                for finding in report.findings
            ]
        )

    if report.recommendations:
        print_subsection("RECOMMENDATIONS")
        print_values(report.recommendations)


def run_selected_option(
    option: str,
    workflow: LabWorkflow | None = None,
) -> bool:
    """
    Dispatch a menu option.

    The workflow argument remains optional for compatibility
    with the existing test suite.
    """

    if option == "0":
        return False

    if workflow is None:
        workflow = LabWorkflow()

    if option == "1":
        handler = password_strength_menu
    elif option == "2":
        handler = run_dictionary_generator
    elif option == "3":
        handler = run_dictionary_attack
    elif option == "4":
        handler = run_brute_force
    elif option == "5":
        handler = run_hash_analyzer
    elif option == "6":
        handler = run_offline_hash_audit
    elif option == "7":
        handler = run_mutation_generator
    elif option == "8":
        handler = (
            lambda _workflow:
            run_crack_time_estimator()
        )
    elif option == "9":
        handler = run_security_audit_report
    else:
        print("Invalid menu option.")
        return True

    try:
        handler(workflow)

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")

    except Exception as exc:
        print()
        print("Unexpected application error:")
        print(
            f"  {type(exc).__name__}: {exc}"
        )
        print(
            "The application returned safely "
            "to the main menu."
        )

    return True


def main() -> None:
    """Run the application."""

    display_banner()

    workflow = LabWorkflow()

    while True:
        display_menu()

        option = input(
            "\nSelect an option: "
        ).strip()

        if not run_selected_option(
            option,
            workflow,
        ):
            print(
                "\nExiting Password & Credential "
                "Security Audit Suite."
            )
            break

        pause()


if __name__ == "__main__":
    main()
