use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use tracing::{info, warn};
use uvm_ublk::{load_ublk_module, ublk_module_loaded};

const UDEV_RULES_DIR: &str = "/etc/udev/rules.d";

fn supports_persistent_udev_rules() -> bool {
    Path::new(UDEV_RULES_DIR).exists()
}

fn write_udev_rule(current_group: &str) -> Result<()> {
    if !supports_persistent_udev_rules() {
        warn!(
            rules_dir = UDEV_RULES_DIR,
            "udev rules directory not present; skipping persistent ublk rule install"
        );
        return Ok(());
    }

    let rule_content = format!(
        "# Managed by agentenv server setup\n\
         KERNEL==\"ublk-control\", MODE=\"0660\", GROUP=\"{current_group}\"\n\
         KERNEL==\"ublkc*\", MODE=\"0660\", GROUP=\"{current_group}\"\n\
         KERNEL==\"ublkb*\", MODE=\"0660\", GROUP=\"{current_group}\"\n"
    );

    std::fs::write("/etc/udev/rules.d/99-agentenv-ublk.rules", rule_content)
        .context("install /etc/udev/rules.d/99-agentenv-ublk.rules")?;
    Ok(())
}

fn reload_udev() -> Result<()> {
    if which::which("udevadm").is_err() {
        warn!("udevadm not found; ublk permissions will apply after udev reloads rules");
        return Ok(());
    }
    let status = Command::new("udevadm")
        .args(["control", "--reload-rules"])
        .status()
        .context("reload udev rules")?;
    if !status.success() {
        bail!("udevadm control --reload-rules failed with {status}");
    }
    Command::new("udevadm")
        .args([
            "trigger",
            "--subsystem-match=misc",
            "--sysname-match=ublk-control",
        ])
        .status()
        .ok();
    for pattern in ["ublkc*", "ublkb*"] {
        Command::new("udevadm")
            .args(["trigger", &format!("--sysname-match={pattern}")])
            .status()
            .ok();
    }
    Command::new("udevadm").arg("settle").status().ok();
    Ok(())
}

fn ensure_permissions(current_group: &str) -> Result<()> {
    info!(group = current_group, "installing ublk device access rules");
    write_udev_rule(current_group)?;
    reload_udev()?;
    Ok(())
}

pub fn provision(group: &str) -> Result<()> {
    if !ublk_module_loaded() {
        install_extra_kernel_modules();
    }
    load_ublk_module()?;
    std::fs::create_dir_all("/etc/modules-load.d").context("create /etc/modules-load.d")?;
    std::fs::write("/etc/modules-load.d/aenv-ublk.conf", "ublk_drv\n")
        .context("install /etc/modules-load.d/aenv-ublk.conf")?;
    ensure_permissions(group)?;
    Ok(())
}

pub fn check() -> Result<()> {
    if !ublk_module_loaded() {
        bail!("ublk_drv is not loaded; run `server --setup-host` as root");
    }
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/ublk-control")
        .context("open /dev/ublk-control for read/write access")?;
    Ok(())
}

fn install_extra_kernel_modules() {
    let uname = Command::new("uname")
        .args(["-r"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if uname.is_empty() {
        return;
    }

    let (manager, package) = if which::which("apt-get").is_ok() {
        ("apt-get", format!("linux-modules-extra-{uname}"))
    } else if which::which("dnf").is_ok() || which::which("yum").is_ok() {
        (
            if which::which("dnf").is_ok() {
                "dnf"
            } else {
                "yum"
            },
            format!("kernel-modules-extra-{uname}"),
        )
    } else {
        return;
    };

    if !Command::new(manager)
        .args(["install", "-y", package.as_str()])
        .status()
        .is_ok_and(|status| status.success())
    {
        warn!(
            manager,
            package, "extra kernel modules not found for this kernel"
        );
    }
}
