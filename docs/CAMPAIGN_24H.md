# Running the 24-hour campaign

*English translation of [`CAMPAGNE_24H.md`](CAMPAGNE_24H.md), which remains the reference version.*

This program keeps every core of the machine busy for 24 hours to test an experimental cryptography suite. It only touches its own folder, sends nothing over the network during the computation and needs no administrator rights (except to install system packages). This is research code: do not use it to protect real data.

## 1. Install

```bash
git clone https://github.com/Spider4Tech/sillage-brume.git
cd sillage-brume
./scripts/preparer_campagne.sh --installer
```

This script checks the machine and installs the Python packages in the `.venv` folder. If something is missing, it prints the command to run for your distribution. Linux is required; WSL works, but without temperature monitoring and with less reliable timing measurements.

### On Windows

Install WSL 2 once: `wsl --install -d Ubuntu` in an administrator PowerShell, reboot, then open Ubuntu to create the user. Then clone the repository and run, instead of `./scripts/runlong`:

```bat
scripts/rundenuit.cmd 10
```

(10 hours; 8 by default.) The script installs what is missing in WSL (your Linux password is requested), computes in a `~/sillage-brume` clone that belongs to WSL and blocks Windows sleep. It uses the code published on GitHub, not local changes in the Windows clone.

- **Keep the window open:** closing it stops the computation. `Ctrl-C` stops it cleanly. Run `scripts/rundenuit.cmd` again to resume, `scripts/rundenuit.cmd 10 -Neuf` to start from scratch.
- **From another window:** `scripts/rundenuit.cmd -Statut`, `scripts/rundenuit.cmd -Arreter`.
- **Result:** the archive is copied into the `resultats` folder of the Windows clone.
- **Limitations:** there is no temperature safety stop, so watch the cooling. On a laptop, leave the lid open. Pause Windows Update for the duration of the campaign. The load monitor does not see Windows activity, so the dudect measurements are less reliable even without a warning. By default WSL only gets half of Windows' memory: if the start-up check reports it, increase `memory` in `%UserProfile%\.wslconfig`.

## 2. Check the machine

- **Cooling:** 24 hours at full load. Clear the air intakes. A recent Ryzen may run at 90 to 95 °C by design; this is normal.
- **Power:** on mains power, with no automatic sleep (sleep is blocked when systemd is present, not under WSL).
- **Stability:** an unstable overclock or memory setting can crash the machine or corrupt results. Prefer the default settings.

## 3. Run

```bash
./scripts/runlong
```

The computation runs in the background: you can close the terminal. The machine just has to stay on.

```bash
./scripts/runlong --statut     # progress, temperature, failures
./scripts/runlong --arreter    # clean stop
tail -f resultats/nuit/journal.log    # details
```

**Do not use the machine during the “2/6 temps constant” (constant time) phase**, about 3 to 4 hours: it measures differences of a few cycles, and any other activity skews the result (the report flags a busy machine). This phase starts after about 3 hours. The rest of the time, the machine is heavily loaded but remains usable for small tasks. Run only one campaign at a time.

## 4. After an interruption

After a stop, a power cut or a crash, simply run again:

```bash
./scripts/runlong
```

The computation resumes the interrupted campaign, with the remaining time. To start from scratch: `./scripts/runlong --neuf`.

If the temperature stays above 100 °C for 5 minutes, the program stops by itself: let it cool down, improve airflow, then resume. The threshold is set with `SILLAGE_TEMP_MAX=95 ./scripts/runlong`. A stuck campaign is stopped automatically and the rest continues; the report says so.

## 5. Sending back the results

At the end, or at each stop, the program writes `resultats/campagne_<date>.tar.gz` and prints its name. Send back the most recent one.

It contains the results, the logs and a machine sheet (processor, memory, software versions). The machine name, your user name and your home-folder paths are removed from the files, and the owner is cleared from the archive. The program refuses to create the archive if one of these paths remains. You can inspect it before sending it: `tar tvzf resultats/campagne_*.tar.gz`.

## 6. Targeted dudect: `./scripts/runspecial`

`aead` and `kem_decaps` exceeded |t| = 4.5 at the first measurement of the 2026-10-31 campaign, then passed at the second one, which had dropped its fixed values. `./scripts/runspecial` looks for the origin: address sweep, key and plaintext separated, identical preparation of both classes, A/A without ASLR. Allow ≈ 5 h 45, on an idle machine, with the campaign's compiler (`--bloc aead`: ≈ 2 h 10). Options: `./scripts/runspecial --help`. Result: `resultats/special/<date>/BILAN.md`.
