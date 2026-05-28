# 🚀 TrustInstall.sh

> 🛡️ Secure local RPM & AppImage installer for Fedora/RHEL systems
> ⚡ Built with transparency, safety, and love for Open Source software.

---

![License](https://img.shields.io/badge/license-GPLv3-blue.svg)
![Platform](https://img.shields.io/badge/platform-Fedora%20%7C%20RHEL-red)
![Bash](https://img.shields.io/badge/bash-script-green)
![Security](https://img.shields.io/badge/security-focused-brightgreen)
![Open Source](https://img.shields.io/badge/Open%20Source-❤️-orange)

---

# ❤️ About TrustInstall.sh

**TrustInstall.sh** is a professional security-focused Bash utility designed to safely install local `.rpm` and `.AppImage` packages on Linux systems.

Unlike traditional installation methods that blindly execute package transactions, TrustInstall.sh gives users full visibility, security analysis, integrity verification, and installation transparency before making any system changes.

The project was created for Linux users who value:

* 🔒 Security
* 👁️ Transparency
* 🧠 Awareness
* 🐧 Open Source philosophy
* ⚙️ Safe package management

---

# ✨ Features

## 🔍 Intelligent Package Discovery

Automatically scans the current directory for:

* `.rpm`
* `.AppImage`

files and organizes them in a clean interactive interface.

---

## 🛡️ Advanced Risk Analysis

Before installation, TrustInstall.sh performs a complete transaction simulation using DNF.

It detects:

* ⚠️ Package conflicts
* ⚠️ Dangerous removals
* ⚠️ Unsigned packages
* ⚠️ Missing dependencies
* ⚠️ External repository requirements

The user sees everything before proceeding.

---

## 🔐 GPG Signature Verification

TrustInstall.sh supports professional-grade signature validation.

### Supported verification methods:

* `.asc` signatures
* `.sig` signatures
* Imported GPG public keys
* Manual key verification

This helps ensure packages were not tampered with.

---

## 🧾 SHA256 Integrity Validation

For AppImages and unsigned binaries:

* Generates SHA256 checksums
* Helps compare files against official publisher hashes

---

## 🧠 Human-Centered Transparency

TrustInstall.sh never hides operations.

Every command is:

* displayed
* explained
* confirmed

before execution.

No silent installations.
No hidden modifications.

---

## 🐧 AppImage Integration

TrustInstall.sh can fully integrate AppImages into Linux desktops.

### Includes:

* ✅ Executable permission setup
* ✅ Desktop launcher generation
* ✅ Icon extraction
* ✅ Application menu integration
* ✅ FUSE detection

---

## ⚡ Safe Error Handling

Built with defensive Bash scripting techniques:

* `set -euEo pipefail`
* signal traps
* automatic cleanup
* secure temporary directories

Designed to reduce accidental system damage.

---

# 🖥️ Supported Linux Systems

| Distribution | Supported |
| ------------ | --------- |
| Fedora       | ✅         |
| RHEL         | ✅         |
| Rocky Linux  | ✅         |
| AlmaLinux    | ✅         |
| CentOS       | ✅         |
| Oracle Linux | ✅         |

---

# 📦 Requirements

## Required

* Bash
* DNF
* RPM
* Coreutils
* file
* sha256sum
* mktemp

## Optional

* GPG
* FUSE / FUSE3
* update-desktop-database

---

# ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/TrustInstall.git
cd TrustInstall
```

Make the script executable:

```bash
chmod +x TrustInstall.sh
```

Run the installer:

```bash
./TrustInstall.sh
```

---

# 📖 Usage

Place your `.rpm` or `.AppImage` files in the same directory as the script.

Then run:

```bash
./TrustInstall.sh
```

TrustInstall.sh will guide you through:

1. 🔍 Package discovery
2. 🛡️ Risk analysis
3. 🔐 Signature verification
4. 📋 Installation preview
5. ⚡ Safe installation

---

# 🧪 Example Workflow

```text
╔════════════════════════════════╗
║        TrustInstall.sh         ║
╚════════════════════════════════╝

[1] Scan local packages
[2] Analyze dependencies
[3] Verify GPG signatures
[4] Preview transaction
[5] Install securely
```

---

# ❤️ Open Source Philosophy

TrustInstall.sh was built with deep respect for the Open Source community.

We believe software should be:

* transparent
* inspectable
* educational
* privacy-respecting
* user-controlled

This project exists because of the amazing Linux ecosystem and the developers who dedicate their time to Free and Open Source Software.

Special appreciation to:

* 🐧 Linux
* 📦 Fedora Project
* 🔐 GnuPG
* ⚡ AppImage
* 🧰 GNU Coreutils
* ❤️ The Open Source community

---

# 🔒 Security Philosophy

> “Users should understand system changes before they happen.”

TrustInstall.sh is designed around explicit consent and operational transparency.

Every dangerous action requires manual confirmation.

The user remains in control at all times.

---

# 📸 Screenshots

Coming soon.

---

# 🛣️ Future Plans

Planned features include:

* 🌐 Flatpak support
* 📦 DEB package analysis
* 🔄 Rollback snapshots
* 🧠 Dependency visualization
* 🎨 TUI interface
* 📊 Security scoring
* 🐳 Containerized testing

---

# 🤝 Contributing

Contributions are welcome ❤️

If you'd like to improve TrustInstall.sh:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

Ideas, feedback, and security improvements are always appreciated.

---

# 📜 License

GPL-3.0 License

This project respects software freedom and the principles of Open Source development.

---

# ⚠️ Disclaimer

TrustInstall.sh improves installation safety, but users are still responsible for:

* verifying software sources
* downloading packages from trusted publishers
* reviewing installation actions carefully

Use responsibly.

---

# ⭐ Support The Project

If you like the project:

* ⭐ Star the repository
* 🍴 Fork it
* 🐧 Share it with Linux users
* ❤️ Support Open Source software

---

# ❤️ Built for the Linux Community

TrustInstall.sh is made with passion for Linux, transparency, and Open Source software.

Together we make Linux safer.

---

# 🛡️ TrustInstall.sh

### Install local packages with confidence.

