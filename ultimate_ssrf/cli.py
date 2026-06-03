import argparse


def setup_argparse():
    parser = argparse.ArgumentParser(
        description="Ultimate SSRF Framework v4.2-experimental",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--target", "-t", help="Single target domain")
    target_group.add_argument("--targets", help="Comma-separated targets")
    target_group.add_argument("--target-file", "-f", help="File with targets (one per line)")

    parser.add_argument("--callback", "-c", help="OOB callback host")
    parser.add_argument("--dangerous-payloads", action="store_true", help="Enable dangerous/destructive payloads")
    parser.add_argument("--collaborator", help="Alias for --callback / OAST host")
    parser.add_argument("--burp-collaborator", help="Burp Collaborator host")
    parser.add_argument("--delay", "-d", type=float, default=0.5)
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--visible", action="store_true")

    proxy_group = parser.add_argument_group("Proxy Support")
    proxy_group.add_argument("--proxy", "-p", help="Single proxy URL (used for the entire scan)")
    proxy_group.add_argument("--proxy-file", help="File with proxy list (one proxy per scan)")
    proxy_group.add_argument("--proxy-type", choices=["http", "socks5"], default="http")

    ai_group = parser.add_argument_group("AI Integration (Optional)")
    ai_group.add_argument(
        "--ai-provider",
        choices=["claude", "openai", "ollama", "gemini", "mistral", "deepseek", "none"],
    )
    ai_group.add_argument("--ai-key", help="API key for cloud AI")
    ai_group.add_argument("--ai-model", help="Specific model name")

    feature_group = parser.add_argument_group("Feature Control")
    feature_group.add_argument("--no-waf", action="store_true", help="Disable WAF detection")
    feature_group.add_argument("--no-websocket", action="store_true", help="Disable WebSocket SSRF tests")
    feature_group.add_argument("--no-grpc", action="store_true", help="Disable gRPC SSRF tests")
    feature_group.add_argument("--no-k8s", action="store_true", help="Disable Kubernetes SSRF tests")
    feature_group.add_argument("--no-serverless", action="store_true", help="Disable serverless SSRF tests")
    feature_group.add_argument("--no-ai", action="store_true", help="Disable AI features")

    export_group = parser.add_argument_group("Export Options")
    export_group.add_argument("--export-nuclei", action="store_true", help="Export Nuclei templates")
    export_group.add_argument("--export-siem", action="store_true", help="Export CEF for SIEM")
    export_group.add_argument("--export-json-api", action="store_true", help="Export JSON API report")
    export_group.add_argument("--attack-map", action="store_true", help="Generate attack path graph")
    export_group.add_argument("--output", "-o", default=".", help="Output directory")

    return parser
import asyncio
import sys
from .core import UltimateSSRFFramework
from .targets import TargetManager
from .utils import CYAN, BOLD, RESET, WARN, FAIL, YELLOW

BANNER = f"""
{BOLD}{CYAN}
╔════════════════════════════════════════════════════════════════╗
║              ULTIMATE SSRF FRAMEWORK v4.2-experimental         ║
║     github.com/KauanCosta2000/Ultimate-ssrf-Framework          ║
║              Created by belladonnask                           ║
╚════════════════════════════════════════════════════════════════╝
{RESET}"""

async def run_async_main():
    parser = setup_argparse()
    args = parser.parse_args()
    print(BANNER)

    targets = TargetManager.from_args(args)
    if not targets:
        targets = TargetManager.interactive()
        if not targets:
            print(f"{FAIL} No targets.")
            return
        if not args.callback and not args.collaborator and not args.burp_collaborator:
            print(f"\n{BOLD}{CYAN}OOB CALLBACK SELECTION{RESET}")
            print("  1 - Default local placeholder")
            print("  2 - Burp Collaborator")
            print("  3 - Interactsh / OASTify / Custom OAST host")
            cb_choice = input(f"{WARN} Choose [1/2/3] [1]: ").strip() or "1"
            if cb_choice == "2":
                args.burp_collaborator = input("Burp Collaborator host: ").strip()
            elif cb_choice == "3":
                args.collaborator = input("Callback/OAST host: ").strip()

        if args.ai_provider is None:
            enable_ai = input(f"{WARN} Enable AI? (none/claude/openai/ollama/gemini/mistral/deepseek) [none]: ").strip().lower()
            if enable_ai and enable_ai != "none":
                args.ai_provider = enable_ai
                if enable_ai != "ollama":
                    args.ai_key = input(f"{WARN} API key: ").strip()
                model_choice = input(f"{WARN} Model (press Enter for default): ").strip()
                if model_choice:
                    args.ai_model = model_choice

        # Default dangerous payloads if interactive
        if not hasattr(args, "dangerous_payloads") or not args.dangerous_payloads:
            danger = input(f"{WARN} Enable dangerous/destructive payloads? (y/N): ").strip().lower()
            if danger == "y":
                args.dangerous_payloads = True
            else:
                args.dangerous_payloads = False

    for i, t in enumerate(targets, 1):
        print(f"\n{BOLD}{YELLOW}[{i}/{len(targets)}]{RESET} Scanning: {t}")
        await UltimateSSRFFramework(t, args).run()
        if i < len(targets):
            await asyncio.sleep(5)

def main():
    try:
        asyncio.run(run_async_main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)

if __name__ == "__main__":
    main()
