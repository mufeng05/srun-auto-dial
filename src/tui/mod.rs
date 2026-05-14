use crate::error::Result;
use crate::net::Link;
use crate::service::{SrunService, parse_mac};
use inquire::{Password, PasswordDisplayMode, Select, Text};
use std::fmt::{Display, Formatter};
use std::sync::Arc;

const CUSTOM_PATH_LABEL: &str = "Enter a custom path...";

pub async fn run(service: Arc<SrunService>) -> Result<()> {
    println!("SRUN Auto Dialer");

    let mode = Select::new(
        "Select your dial mode:",
        vec![DialMacMode::Local, DialMacMode::Custom, DialMacMode::Random],
    )
    .prompt()?;

    match mode {
        DialMacMode::Local => local_mode(&service).await,
        DialMacMode::Custom => custom_mode(&service).await,
        DialMacMode::Random => random_mode(&service).await,
    }
}

async fn local_mode(service: &SrunService) -> Result<()> {
    let link = select_link(service, "Select a link:").await?;
    let operation = select_operation()?;

    match operation {
        Operation::Login => {
            let (creds, userinfo_path) = get_credentials()?;
            let result = service
                .login_local(
                    &link.name,
                    creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
                    userinfo_path.as_deref(),
                )
                .await?;
            println!("Login successful, IP: {}", result.ip);
        }
        Operation::Logout => {
            service.logout_local(&link.name).await?;
            println!("Logout successful");
        }
        Operation::Status => {
            let status = service.get_status(&link.name).await?;
            print_status(&status);
        }
    }
    Ok(())
}

async fn custom_mode(service: &SrunService) -> Result<()> {
    let link = select_link(service, "Select the parent link:").await?;
    let mac_input =
        Text::new("Enter the custom MAC address (e.g., AA:BB:CC:DD:EE:FF):").prompt()?;
    let mac = parse_mac(&mac_input)?;

    let operation = select_operation()?;
    match operation {
        Operation::Login => {
            let (creds, userinfo_path) = get_credentials()?;
            let result = service
                .login_macvlan(
                    &link.name,
                    &mac,
                    creds.as_ref().map(|(u, p)| (u.as_str(), p.as_str())),
                    userinfo_path.as_deref(),
                )
                .await?;
            println!(
                "Login successful, User: {}, IP: {}",
                result.username, result.ip
            );
        }
        Operation::Logout => {
            service.logout_macvlan(&link.name, &mac).await?;
            println!("Logout successful");
        }
        Operation::Status => {
            let status = service.get_status_macvlan(&link.name, &mac).await?;
            print_status(&status);
        }
    }
    Ok(())
}

async fn random_mode(service: &SrunService) -> Result<()> {
    let link = select_link(service, "Select the parent link:").await?;
    let count: u32 = Text::new("Enter the number of random MAC addresses to try:")
        .with_default("1")
        .prompt()?
        .parse()
        .map_err(|_| crate::error::SrunError::Config("invalid number".to_string()))?;

    let userinfo_path = select_userinfo_path("Select the user-info JSON to read:")?;

    let results = service
        .login_random(&link.name, count, Some(&userinfo_path))
        .await?;

    println!("\n--- Results ---");
    for r in &results {
        match &r.result {
            Ok(login) => println!(
                "MAC: {} -> Login OK, User: {}, IP: {}",
                r.mac, login.username, login.ip
            ),
            Err(e) => println!("MAC: {} -> Failed: {}", r.mac, e),
        }
    }

    let success_count = results.iter().filter(|r| r.result.is_ok()).count();
    println!(
        "\nTotal: {}, Success: {}, Failed: {}",
        results.len(),
        success_count,
        results.len() - success_count
    );
    Ok(())
}

// ---- UI helpers ----

/// Returns (manual credentials, userinfo file path).
/// At most one of the two is Some.
fn get_credentials() -> Result<(Option<(String, String)>, Option<String>)> {
    let mode = Select::new(
        "Select how to input user information:",
        vec![UserMode::Input, UserMode::Read],
    )
    .prompt()?;

    match mode {
        UserMode::Input => {
            let username = Text::new("Enter username:").prompt()?;
            let password = Password::new("Enter password:")
                .with_display_mode(PasswordDisplayMode::Masked)
                .without_confirmation()
                .prompt()?;
            Ok((Some((username, password)), None))
        }
        UserMode::Read => {
            let path = select_userinfo_path("Select the user-info JSON to read:")?;
            Ok((None, Some(path)))
        }
    }
}

/// Let the user pick a `*.json` file from the current directory, or enter a custom path.
fn select_userinfo_path(prompt: &str) -> Result<String> {
    let mut options: Vec<String> = std::fs::read_dir(".")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_type()
                .map(|t| t.is_file())
                .unwrap_or(false)
        })
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| name.to_ascii_lowercase().ends_with(".json"))
        .collect();
    options.sort();
    options.push(CUSTOM_PATH_LABEL.to_string());

    let selected = Select::new(prompt, options).prompt()?;
    if selected == CUSTOM_PATH_LABEL {
        let path = Text::new("Enter the JSON file path:")
            .with_default("userinfo.json")
            .prompt()?;
        Ok(path)
    } else {
        Ok(selected)
    }
}

async fn select_link(service: &SrunService, msg: &str) -> Result<Link> {
    let links = service.list_interfaces().await?;
    let link = Select::new(msg, links).prompt()?;
    Ok(link)
}

fn select_operation() -> Result<Operation> {
    let op = Select::new(
        "Select operation:",
        vec![Operation::Login, Operation::Logout, Operation::Status],
    )
    .prompt()?;
    Ok(op)
}

fn print_status(status: &crate::service::StatusResult) {
    println!("IP: {}", status.ip);
    match (&status.online_user, &status.online_mac) {
        (Some(user), Some(mac)) => println!("Online: {} (MAC: {})", user, mac),
        _ => println!("No user currently online"),
    }
}

// ---- Display enums ----

#[derive(Debug, Clone, Copy)]
enum DialMacMode {
    Local,
    Custom,
    Random,
}

impl Display for DialMacMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "Using the local network adapter's MAC address"),
            Self::Custom => write!(f, "Using a custom MAC address"),
            Self::Random => write!(
                f,
                "Using random MAC addresses (reads users from a JSON file)"
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Operation {
    Login,
    Logout,
    Status,
}

impl Display for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Login => write!(f, "Login"),
            Self::Logout => write!(f, "Logout"),
            Self::Status => write!(f, "Check status"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum UserMode {
    Input,
    Read,
}

impl Display for UserMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Input => write!(f, "Enter username and password manually"),
            Self::Read => write!(f, "Read from a JSON file"),
        }
    }
}
