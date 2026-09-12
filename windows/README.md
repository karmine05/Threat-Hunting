# Windows Fleet scripts

Public payload host for Fleet-deployed Windows scripts.

## Sysmon

- Config (source of truth): [`sysmon/sysmonconfig.xml`](./sysmon/sysmonconfig.xml)
- Raw URL used by the Fleet script:
  `https://raw.githubusercontent.com/karmine05/Threat-Hunting/main/windows/sysmon/sysmonconfig.xml`
- Deployer: [`scripts/deploy-sysmon.ps1`](./scripts/deploy-sysmon.ps1)

Upload `deploy-sysmon.ps1` in Fleet (**Controls → Scripts**). The script:

1. Downloads Sysmon from Microsoft Sysinternals.
2. Downloads this config from GitHub.
3. Installs Sysmon if it is missing.
4. If the Sysmon service is **already running**, it **backs off** (no reinstall) and only then re-initializes the config (`Sysmon -c`) when the hash differs.

## Windows patching

- Script: [`scripts/windows-patch.ps1`](./scripts/windows-patch.ps1)

Upload in Fleet. It notifies the logged-on user, then (when run as SYSTEM by Fleet) hands off to a one-shot scheduled task so the work survives Fleet's default 5-minute `script_execution_timeout`. Raise that timeout to 3600+ in agent options if you want the script to stay attached. The task installs the latest Microsoft updates from official Windows Update / Microsoft Update, upgrades third-party packages with Chocolatey and winget, then force-restarts with a host notification if a reboot is required.
