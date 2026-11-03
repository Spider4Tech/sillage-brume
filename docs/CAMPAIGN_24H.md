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

## 7. GPU campaign on another card: `./scripts/rungpu2080`

GPU campaign no. 1 (`tests/gpu/campagne_dl.cu`, see `GPU_CRYPTANALYSIS_PLAN.md`) also runs on a slower card, for example an
RTX 2080 (Turing). The binary is compiled for sm_75 and sm_89, and PTX covers newer cards; each kernel launch lasts
less than 0.5 s, below the Windows watchdog (TDR, 2 s) when the card also drives the display or runs under WSL.

- **Prerequisites:** an NVIDIA driver and `nvcc` (CUDA 12 or later) in `/usr/local/cuda/bin`, otherwise `NVCC=/path/nvcc`. Under WSL 2, install NVIDIA's
  “WSL-Ubuntu” CUDA package, never a Linux driver inside WSL: the Windows driver is the one used.
- **Run:** `./scripts/rungpu2080`. The script checks the GPU's conformance to the C code, measures its throughput, announces the estimated duration, then starts
  the **extended plan** (the 9 experiments of the base plan and 4 more targets) for at most 72 h: `./scripts/rungpu2080 100` for 100 h.
  The extended plan takes ≈ 26 h on an RTX 4070 Ti; a 2080 is about two to three times slower.
- **Follow, stop, resume:** `./scripts/rungpu2080 --statut`, `--arreter`, then run it again: the campaign resumes from the last
  checkpoint (every 10 min). A base-plan campaign, even finished, is completed with the targets of the extended plan.
- **Power:** the card draws full power for hours. If the power supply is tight, cap the power on the host
  (`sudo nvidia-smi -pl 180`, for example), and check the PCIe cables.
- **Not at the same time as dudect** (`runspecial`, `rundenuit.sh`): the GPU load would distort the timing measurements; `rungpu` refuses to
  start in that case.
- **Results:** `resultats/gpu_dl.{json,md}`; log, GPU readings and checkpoint: `resultats/gpu/<date>/`. Send back that folder and
  the two files.

## 8. GPU campaign on a rented machine, with a time limit: `./scripts/rungpu_cloud`

For an instance rented by the hour, with one or more cards (Turing, Ada or Hopper: binary for sm_75, sm_89 and sm_90). Each card
computes a slice of the pairs of **every** experiment; at the end, the slices are added up, and the result is identical to that
of a single GPU (checked: the same statistics, bit for bit, for one GPU and for two merged slices).

1. **Instance:** Ubuntu with the NVIDIA driver. `nvidia-smi` displays “CUDA Version: X.Y”; install the compiler of that version
   (12.0 at least) from NVIDIA's repository:
   ```bash
   wget https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64/cuda-keyring_1.1-1_all.deb
   sudo dpkg -i cuda-keyring_1.1-1_all.deb && sudo apt update
   sudo apt install -y build-essential git cuda-nvcc-X-Y cuda-cudart-dev-X-Y     # X-Y: the version displayed, e.g. 12-8
   git clone https://github.com/Spider4Tech/sillage-brume.git && cd sillage-brume
   ```
2. **Run:** `./scripts/rungpu_cloud` (at most 10 h). The script counts the cards, checks conformance to the C code, measures the throughput,
   announces the duration of both plans and takes the extended plan if it fits in the budget, otherwise the base plan (to force it: `--long` or
   `--base`; another budget: `./scripts/rungpu_cloud 8`). It runs in the background: the SSH session can be closed.
3. **Follow:** `./scripts/rungpu_cloud --statut`. Stop: `--arreter`; running it again resumes, with the same number of cards.
4. **Collect:** at the end, `resultats/gpu_cloud_<date>.tar.gz` (slices, logs, card readings, merged `gpu_dl.json` and `.md`);
   `scp` it to your machine, then **delete the instance**: a stopped instance is still billed.

The work amounts to ≈ 6.5 h of RTX 4070 Ti for the base plan and ≈ 26 h for the extended plan; the duration is divided by the number of cards and
by their relative speed, which the script measures before starting. The campaign only uses integer operations and counters in
shared memory: neither the tensor cores, nor the HBM memory, nor the memory of 80 GB cards are of any use to it.
