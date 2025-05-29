import subprocess
import sys
import os
import shutil

def check_python_version():
    print("✅ Checking Python version...")
    if sys.version_info < (3, 11):
        print("❌ Python 3.11 or higher is required.")
        sys.exit(1)
    print(f"✔ Python version OK: {sys.version.split()[0]}")

def check_git_installed():
    print("✅ Checking Git installation...")
    try:
        output = subprocess.check_output(["git", "--version"], text=True)
        print(f"✔ Git is installed: {output.strip()}")
    except FileNotFoundError:
        print("❌ Git is not installed. Please install Git >= 2.0.")
        sys.exit(1)

def install_uv():
    print("✅ Checking uv...")
    try:
        subprocess.run(["uv", "--version"], check=True)
        print("✔ uv is already installed.")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("⚙ Installing uv...")
        subprocess.run([
            sys.executable, "-m", "pip", "install", "uv"
        ], check=True)

def install_packages():
    print("📦 Installing Python packages using pip...")
    packages = ["numpy", "pandas", "streamlit"]
    for pkg in packages:
        print(f"→ Installing {pkg}...")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg], check=True)
    print("✔ All packages installed.")

def recommend_vscode_extensions():
    print("\n💡 Recommended VS Code Extensions (install manually from Marketplace):")
    extensions = [
        "ms-python.python",
        "ms-toolsai.jupyter",
        "ms-python.debugpy",
        "charliermarsh.ruff",
        "mgesbert.cline"
    ]
    for ext in extensions:
        print(f"   - {ext}")
    print("\n⚠️ NOTE: Automatic installation of VS Code extensions is limited via script on Windows.\n")

if __name__ == "__main__":
    print("🚀 Starting SOAI 2025 Dev Environment Setup\n")
    check_python_version()
    check_git_installed()
    install_uv()
    install_packages()
    recommend_vscode_extensions()
    print("🎉 Dev setup complete!")
