import os
import argparse
import json
from colorama import init, Fore

init(autoreset=True)

# Stylized banner
def show_banner():
    print(Fore.MAGENTA + "==========================================")
    print(Fore.CYAN + "📱 Mobile Static Testing Tool")
    print(Fore.YELLOW + "👨‍💻 Created by: Mayur_Patil")
    print(Fore.MAGENTA + "==========================================\n")

# Vulnerability keywords (your patterns)
VULN_PATTERNS = {
    "reverse_engineering": [".smali", "native", "NDK", "lib/armeabi"],
    "webview_js": ["addJavascriptInterface", "setJavaScriptEnabled"],
    "logging_issues": ["Log.d", "Log.e", "Log.i", "printStackTrace"],
    "root_detection": ["isRooted", "su", "/system/bin/su"],
    "firebase_misconfig": ["firebaseio.com", "FirebaseDatabase.getInstance"],
    "ssl_pinning": ["checkServerTrusted", "HostnameVerifier", "TrustManager"],
    "insecure_data_storage": ["MODE_WORLD_READABLE", "MODE_WORLD_WRITEABLE"],
    "insecure_credentials": ["password", "apikey", "secret", "token"],
    "insufficient_crypto": ["AES/ECB/NoPadding", "DES", "Base64.decode"],
    "poor_code_quality": ["eval(", "exec(", "loadUrl("],
    "extraneous_functionality": ["debug", "test", "dev"],
    "deep_linking_abuse": ["intent-filter", "scheme", "host"]
}

# Scan function
def scan_directory(path, selected_flags):
    results = {}
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(('.smali', '.xml', '.java', '.kt', '.txt')):
                file_path = os.path.join(root, file)
                with open(file_path, "r", encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                    for i, line in enumerate(lines):
                        for flag in selected_flags:
                            for keyword in VULN_PATTERNS[flag]:
                                if keyword in line:
                                    if flag not in results:
                                        results[flag] = []
                                    results[flag].append({
                                        "file": file_path,
                                        "line": i + 1,
                                        "code": line.strip()
                                    })
    return results

# Output writer
def save_results(results, output_format):
    if output_format == "txt":
        with open("output/scan_results.txt", "w") as f:
            for issue, findings in results.items():
                f.write(f"\n[+] {issue.upper()} ({len(findings)} findings)\n")
                for entry in findings:
                    f.write(f"  - File: {entry['file']} (Line {entry['line']}): {entry['code']}\n")
    elif output_format == "json":
        with open("output/scan_results.json", "w") as f:
            json.dump(results, f, indent=4)
    else:
        print(Fore.RED + "[!] Invalid output format specified.")

# Auto-decompile APK
def decompile_apk(apk_path):
    output_dir = apk_path.replace(".apk", "_code")
    os.system(f"apktool d -f \"{apk_path}\" -o \"{output_dir}\"")
    return output_dir

# Main logic
def main():
    show_banner()

    parser = argparse.ArgumentParser(
        description="📱 Mobile Static Testing Tool by Mayur_Patil",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("--path", required=True, help="📁 Path to APK file or decompiled code folder")
    parser.add_argument("--output", choices=["txt", "json"], help="💾 Save output as .txt or .json")
    parser.add_argument("--all", action='store_true', help="🚀 Run all vulnerability scans")

    for flag in VULN_PATTERNS:
        parser.add_argument(f"--{flag}", action='store_true', help=f"🔍 Scan for {flag.replace('_', ' ').title()}")

    args = parser.parse_args()

    # If APK given, decompile first
    if args.path.endswith(".apk"):
        print(Fore.CYAN + "[*] APK detected. Running apktool...")
        decompiled_path = decompile_apk(args.path)
    else:
        decompiled_path = args.path

    # Determine selected scans
    selected_flags = list(VULN_PATTERNS.keys()) if args.all else [
        flag for flag in VULN_PATTERNS if getattr(args, flag)
    ]

    if not selected_flags:
        print(Fore.RED + "[!] No scan module selected. Use --all or specific flags like --reverse_engineering")
        return

    print(Fore.GREEN + f"\n[+] Starting scan on {decompiled_path}...\n")
    results = scan_directory(decompiled_path, selected_flags)

    # Output
    if args.output:
        save_results(results, args.output)
        print(Fore.GREEN + f"[✔] Results saved in scan_results.{args.output}")
    else:
        print(Fore.GREEN + "\n[!] Results:")
        for issue, findings in results.items():
            print(Fore.YELLOW + f"\n[+] {issue.upper()} ({len(findings)} findings)")
            for entry in findings:
                print(f"  - File: {entry['file']} (Line {entry['line']}): {entry['code']}")

if __name__ == "__main__":
    main()
