# TRIDENT

**The AI-powered immune layer for Windows.**

Watch. Judge. Act.

[![PyPI - Version](https://img.shields.io/pypi/v/trident-windows?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/trident-windows/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/trident-windows?style=flat-square&logo=python&logoColor=white)](https://pypi.org/project/trident-windows/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6?style=flat-square&logo=windows&logoColor=white)](https://github.com/aalok101singh/trident)
[![GitHub stars](https://img.shields.io/github/stars/aalok101singh/trident?style=social)](https://github.com/aalok101singh/trident/stargazers)

TRIDENT is a background security tool that watches every process starting on your Windows machine, scores it with a small AI model running locally on your CPU, and routes the decision through a three-tier confidence cascade before anything gets terminated.

**No cloud. No kernel driver. No signature database.** Just a fine-tuned transformer and a strict policy layer that refuses to let the model act alone.

---

## 🤔 What Is This, Really?

Every time you open an app, run a script, or something silently launches in the background, Windows creates a **new process**. TRIDENT sees that happen, asks a local AI model two questions — *should we allow this or kill it?* and *how much should we trust it?* — and then decides what to do.

Three possible outcomes:

1. **Kill it silently** — the model is very confident it's malicious, and the file isn't in a Windows system folder.
2. **Watch it** — the model is uncertain, so TRIDENT keeps an eye on it.
3. **Ask you** — the model is suspicious but not sure, so you get a native Windows notification asking what to do.

The AI is **never allowed to act alone**. Every kill decision passes through a safety cascade first. If the process is Windows' own `lsass.exe` or `powershell.exe`, the cascade refuses — even if the model says kill. **That is the entire point of TRIDENT.**

---

## 🚀 Install & Run

You need **Python 3.11 or newer** and **Windows 10 (1809+) or Windows 11**. That's it. No admin, no installer, no reboot.

Open PowerShell and run these three commands:

```powershell
pip install trident-windows
trident models fetch
trident start
```

| Command | What happens |
| :--- | :--- |
| `pip install trident-windows` | Installs TRIDENT and its dependencies. Takes ~2 minutes. |
| `trident models fetch` | Downloads the 280 MB AI model from Hugging Face to `%LOCALAPPDATA%\TRIDENT\models\`. Takes 2–10 minutes depending on your connection. One-time. |
| `trident start` | Runs a first-time welcome message, registers TRIDENT to launch at logon, and starts the background daemon. |

**After `trident start` returns, you can close every terminal.** TRIDENT keeps running in the background. It survives closing the window, logging off, and rebooting.

---

## 🛡️ It Starts In Safe Mode

When you run `trident start` for the very first time, you'll see this:

```
Welcome to TRIDENT.

TRIDENT watches every process on your machine and scores it
with a local AI model. In enforce mode, it can terminate
processes it thinks are malicious.

Kill mode is DISABLED by default. TRIDENT will run in dry-run
mode and record what it would have done. Review with:

    trident logs --tail 50

Enable enforcement later with:

    trident config --mode enforce

[Enter] to continue in dry-run mode
[q]     to cancel
```

**Press Enter.** TRIDENT starts in **dry-run mode**. It scores every process, writes every decision to a log file, but **kills nothing**. You can watch what it *would* have done for as long as you want.

When you're ready to let it actually enforce:

```powershell
trident config --mode enforce
```

The change takes effect immediately — no restart needed.

---

## 🧠 How It Actually Works

```text
New process starts on Windows
        │
        ▼
┌───────────────────────────────┐
│  Layer 1 — Telemetry          │
│  Polls every 500 ms.          │
│  Two-pass: cheap scan of all  │
│  PIDs, detailed scan only     │
│  for genuinely new ones.      │
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│  Layer 2 — Decision Kernel    │
│  Fine-tuned AI model.         │
│  Runs on CPU. ~150 ms.        │
│  Answers two questions per    │
│  process: action + trust.     │
└──────────────┬────────────────┘
               │
               ▼
┌───────────────────────────────┐
│  Layer 3 — Cascade            │
│  Refuses to let the model     │
│  act alone. Three gates.      │
│  Then: kill, monitor, or ask. │
└───────────────────────────────┘
```

**The three safety gates:**

1. **Confidence gate** — the model must be at least 92% confident to auto-kill.
2. **Critical path gate** — anything inside `C:\Windows\System32`, `SysWOW64`, `WinSxS`, `Program Files\Windows Defender`, or `WindowsApps` is **never** auto-killed. It always goes to human review.
3. **Trust gate** — paths you have explicitly trusted are still scored, still logged, but never acted on.

If any gate says no, the decision becomes a Windows toast notification instead of a kill.

---

## 📋 Every Command

```
trident start              Start the background watcher
trident stop               Stop it gracefully
trident stop --uninstall   Also remove the logon registration
trident status             Is it running? What mode?
trident logs --tail 50     Show the last 50 decisions
trident config             View or change operating mode
trident models fetch       Download the AI model from Hugging Face
trident models status      Is the model downloaded?
trident trust <path>       Add a path to the allowlist
trident report <pid>       Open a decision report for a specific process
trident version            Print version
```

---

## 🔄 Three Modes

| Mode | Kills? | Sends Toasts? | Logs? | When to Use |
| :--- | :---: | :---: | :---: | :--- |
| `dry-run` | No | No | Yes | **Default for the first 24 hours** |
| `monitor` | No | Yes | Yes | After you've reviewed the log |
| `enforce` | Yes | Yes | Yes | When you trust the pipeline |

Switch modes at any time:

```powershell
trident config --mode monitor
```

The daemon picks up the change on its next polling tick. No restart.

---

## 📊 Performance

Measured on a modern i7 dev machine:

| | Idle | Per New Process |
| :--- | :--- | :--- |
| **Memory** | ~495 MB | ~495 MB |
| **CPU** | 0.2% | ~8% (one core, ~150 ms) |

Expected on the reference target — a 2-core i3-8100 with 4 GB RAM — is the same memory footprint with 250–400 ms per decision.

The 495 MB is 55% the AI model weights, memory-mapped from disk. Post-1.0 work includes int8 quantization, which should cut that down to roughly 70 MB.

---

## 🧭 Where Everything Lives

All user data is scoped to one directory:

```
%LOCALAPPDATA%\TRIDENT\
├── config\             Your editable trident.toml + trusted_paths.json
├── logs\               Daily decision logs (JSONL, one line per decision)
├── models\             ONNX graph, weights, tokenizer
├── cleanup-scripts\    Generated review-only PowerShell scripts
└── runtime\            daemon.pid, daemon.log, stop signal
```

The audit log is append-only JSONL. Easy to grep, easy to `jq`, easy to feed into a future training pass.

---

## ❌ What It Does NOT Do

Honesty is important for a security tool. TRIDENT is **not**:

- **An antivirus.** It doesn't scan files on disk.
- **A firewall.** No network inspection, no outbound filtering.
- **A behavioral monitor.** It sees process *starts*, not what a running process does afterward. DLL injection, fileless attacks, and memory-resident malware are outside its scope.
- **A kernel-level defense.** User-mode only. A privileged attacker can bypass it. That's true of every user-mode security tool.

What it **does**: closes the gap between "no AI process layer" and "a small local model watching every process start." That's a real gap on a consumer Windows machine.

---

## 🧹 Uninstall Cleanly

```powershell
trident stop --uninstall
pip uninstall trident-windows
Remove-Item "$env:LOCALAPPDATA\TRIDENT" -Recurse -Force
```

The first command stops the daemon and removes the logon registration. The second uninstalls the Python package. The third deletes the user data (model, logs, config). No registry keys left behind except the `trident:` URI protocol — remove it manually with `reg delete "HKCU\Software\Classes\trident" /f` if you want a truly clean slate.

---

## 🛠️ For Developers

```powershell
git clone https://github.com/aalok101singh/trident
cd trident
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
trident models fetch
trident start
```

Run the test suite:

```powershell
pytest tests/
```

Build a wheel:

```powershell
pip install build
python -m build --wheel
```

The wheel ends up in `dist\`. Install it in a fresh venv to verify.

---

## 🧪 Status

`v0.9.0` — beta. Tested on Windows 10 and Windows 11 with Python 3.11 through 3.14.

Known limitations at this version:

- The model over-flags `powershell.exe` launches. Every one fires an escalation toast unless you trust the path.
- Unsigned executables in user-writable directories (Downloads, `%TEMP%`) are often flagged.
- Some developer tools (`python.exe`, `node.exe`, `cargo` binaries in user paths) get flagged at Tier 1 in enforce mode. A developer-path allowlist is planned for 0.10.
- Model confidence is not temperature-calibrated, so raw confidences are over-confident. The threat score uses the softmax margin to compensate.

Tracked at [github.com/aalok101singh/trident/issues](https://github.com/aalok101singh/trident/issues).

---

## 📄 License

- **Code:** MIT — see [LICENSE](LICENSE).
- **Model:** Apache 2.0 — see [LICENSE-MODEL](LICENSE-MODEL).

---

## 🔗 Links

- **GitHub:** [github.com/aalok101singh/trident](https://github.com/aalok101singh/trident)
- **PyPI:** [pypi.org/project/trident-windows](https://pypi.org/project/trident-windows/)
- **Model:** [huggingface.co/aalok101singh/trident-v1](https://huggingface.co/aalok101singh/trident-v1)

---

*Watch. Judge. Act. Three prongs, one shaft. The shaft is the cascade.*
