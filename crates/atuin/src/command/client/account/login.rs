use std::{io, path::PathBuf, time::Duration};

use clap::Parser;
use eyre::{Context, Report, Result, bail, eyre};
use log::debug;
use tokio::{fs::File, io::AsyncWriteExt};

use atuin_client::{
    api_client,
    auth::{
        self, AuthConfigError, AuthFlowError, DeviceFlowPrompt, FlowController, PkceFlowPrompt,
        ProviderSelection,
    },
    encryption::{Key, decode_key, encode_key, load_key},
    record::sqlite_store::SqliteStore,
    record::store::Store,
    settings::{AuthFlowPreference, Settings},
};
use atuin_common::api::{AuthProvidersResponse, LoginRequest};
use rpassword::prompt_password;

#[derive(Parser, Debug)]
pub struct Cmd {
    #[clap(long, short)]
    pub username: Option<String>,

    #[clap(long, short)]
    pub password: Option<String>,

    /// The encryption key for your account
    #[clap(long, short)]
    pub key: Option<String>,

    /// Selects an external auth provider when the server advertises multiple
    #[clap(long = "provider")]
    pub provider: Option<String>,
}

enum LoginPlan {
    Password { username: String, password: String },
    External { selection: ProviderSelection },
}

struct ExternalLoginResult {
    provider: String,
    token: String,
    nonce: Option<String>,
    kind: ExternalLoginKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExternalLoginKind {
    Oidc,
    Oauth,
}

fn get_input() -> Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim_end_matches(&['\r', '\n'][..]).to_string())
}

impl Cmd {
    pub async fn run(&self, settings: &Settings, store: &SqliteStore) -> Result<()> {
        if settings.logged_in() {
            bail!(
                "You are already logged in! Please run 'atuin logout' if you wish to login again"
            );
        }

        let login_plan = self.plan_login(settings).await?;

        self.print_key_warning();

        let key_input = or_user_input(
            self.key.clone(),
            "encryption key [blank to use existing key file]",
        );
        let normalized_key = if key_input.is_empty() {
            key_input
        } else {
            normalize_key_input(&key_input)?
        };
        self.reconcile_key(&normalized_key, settings, store).await?;

        let request = self.execute_login_plan(login_plan).await?;

        let session = api_client::login(settings.sync_address.as_str(), request).await?;

        let session_path = settings.session_path.as_str();
        let mut file = File::create(session_path).await?;
        file.write_all(session.session.as_bytes()).await?;

        println!("Logged in!");

        Ok(())
    }

    async fn plan_login(&self, settings: &Settings) -> Result<LoginPlan> {
        if let Some(selection) = self.try_select_external_provider(settings).await? {
            return Ok(LoginPlan::External { selection });
        }

        Ok(self.plan_password_login())
    }

    fn plan_password_login(&self) -> LoginPlan {
        let username = or_user_input(self.username.clone(), "username");
        let password = self.password.clone().unwrap_or_else(read_user_password);

        LoginPlan::Password { username, password }
    }

    async fn execute_login_plan(&self, plan: LoginPlan) -> Result<LoginRequest> {
        match plan {
            LoginPlan::Password { username, password } => {
                Ok(LoginRequest::Password { username, password })
            }
            LoginPlan::External { selection } => {
                let controller = FlowController::new();
                let ctrlc = controller.install_ctrlc_handler();
                let login = self.perform_external_login(selection, &controller).await;
                ctrlc.abort();
                let login = login?;
                let request = match login.kind {
                    ExternalLoginKind::Oidc => LoginRequest::Oidc {
                        provider: login.provider,
                        token: login.token,
                        nonce: login.nonce,
                    },
                    ExternalLoginKind::Oauth => LoginRequest::Oauth {
                        provider: login.provider,
                        token: login.token,
                    },
                };
                Ok(request)
            }
        }
    }

    async fn try_select_external_provider(
        &self,
        settings: &Settings,
    ) -> Result<Option<ProviderSelection>> {
        let response = match api_client::auth_providers(settings.sync_address.as_str()).await? {
            Some(resp) => resp,
            None => {
                println!(
                    "Server does not advertise external auth providers; assuming password login (older server)."
                );
                return Ok(None);
            }
        };

        if response.providers.is_empty() {
            if response.allow_password {
                return Ok(None);
            }

            bail!(
                "Server disabled password login but did not configure any external authentication providers. Ask the server administrator to finish the setup."
            );
        }

        if response.allow_password {
            if let Some(name) = self.provider.as_deref() {
                bail!(
                    "Server still allows username/password login, so '--provider {name}' cannot be used yet. Ask the server administrator to disable passwords before selecting an external provider."
                );
            }

            if let Some(name) = settings.auth.provider() {
                bail!(
                    "Server still allows username/password login, so the configured default provider '{name}' cannot be used yet. Remove the client-side override or ask the server administrator to disable passwords before selecting an external provider."
                );
            }

            debug!("external auth providers ignored because server still allows password login");
            return Ok(None);
        }

        let selection = self.select_provider_from_response(&response, settings)?;
        Ok(Some(selection))
    }

    fn select_provider_from_response(
        &self,
        response: &AuthProvidersResponse,
        settings: &Settings,
    ) -> Result<ProviderSelection> {
        match auth::select_provider(response, &settings.auth, self.provider.as_deref()) {
            Ok(selection) => Ok(selection),
            Err(AuthConfigError::MultipleProviders { providers }) => {
                let choice = self.prompt_provider_choice(response, &providers)?;
                auth::select_provider(response, &settings.auth, Some(choice.as_str()))
                    .map_err(|error| self.provider_selection_error(error))
            }
            Err(error) => Err(self.provider_selection_error(error)),
        }
    }

    fn provider_selection_error(&self, error: AuthConfigError) -> Report {
        debug!("auth provider selection failed: {error:?}");
        match error {
            AuthConfigError::PasswordAuthOnly => eyre!(
                "Server still allows username/password login; rerun this command without selecting an external provider."
            ),
            AuthConfigError::NoExternalProviders => eyre!(
                "Server disabled password login but has no external providers configured. Please contact your server administrator."
            ),
            AuthConfigError::UnknownProvider(name) => eyre!(
                "Server does not advertise an auth provider named '{name}'. Pick one of the names shown by the admin or via '--provider'."
            ),
            AuthConfigError::MissingField { provider, field } => eyre!(
                "Authentication provider '{provider}' is missing required field '{field}'. Ask the server administrator to fix their configuration."
            ),
            AuthConfigError::UnsupportedFlow { provider, flow } => eyre!(
                "Authentication provider '{provider}' does not support the {} flow. Update your config or contact the server administrator.",
                describe_flow_preference(flow)
            ),
            AuthConfigError::NoUsableFlows { provider } => eyre!(
                "Authentication provider '{provider}' does not have any usable login flows configured. Contact your server administrator."
            ),
            AuthConfigError::MultipleProviders { .. } => eyre!(
                "Multiple auth providers available; rerun with '--provider <name>' to choose one."
            ),
        }
    }

    fn print_key_warning(&self) {
        println!("IMPORTANT");
        println!(
            "If you are already logged in on another machine, you must ensure that the key you use here is the same as the key you used there."
        );
        println!("You can find your key by running 'atuin key' on the other machine");
        println!("Do not share this key with anyone");
        println!("\nRead more here: https://docs.atuin.sh/guide/sync/#login \n");
    }

    async fn reconcile_key(
        &self,
        key: &str,
        settings: &Settings,
        store: &SqliteStore,
    ) -> Result<()> {
        let key_path = PathBuf::from(settings.key_path.as_str());

        if key.is_empty() {
            if key_path.exists() {
                let bytes = fs_err::read_to_string(&key_path)
                    .context("existing key file couldn't be read")?;
                if decode_key(bytes).is_err() {
                    bail!("the key in existing key file was invalid");
                }
                return Ok(());
            }

            bail!(
                "No key provided. Please use 'atuin key' on your other machine, or recover your key from a backup."
            );
        }

        if !key_path.exists() {
            if decode_key(key.to_string()).is_err() {
                bail!("the specified key was invalid");
            }

            let mut file = File::create(key_path).await?;
            file.write_all(key.as_bytes()).await?;
            return Ok(());
        }

        let current_key: [u8; 32] = load_key(settings)?.into();
        let encoded = key.to_string();
        let new_key: [u8; 32] = decode_key(encoded.clone())
            .context("could not decode provided key - is not valid base64")?
            .into();

        if new_key != current_key {
            println!("\nRe-encrypting local store with new key");
            store.re_encrypt(&current_key, &new_key).await?;

            println!("Writing new key");
            let mut file = File::create(key_path).await?;
            file.write_all(encoded.as_bytes()).await?;
        }

        Ok(())
    }

    async fn perform_external_login(
        &self,
        selection: ProviderSelection,
        controller: &FlowController,
    ) -> Result<ExternalLoginResult> {
        let provider_name = selection.provider_name().to_owned();
        let label = selection.display_label().to_owned();
        let kind = if selection.is_oidc() {
            ExternalLoginKind::Oidc
        } else {
            ExternalLoginKind::Oauth
        };

        let token = match selection.flow() {
            AuthFlowPreference::DeviceCode => {
                let renderer = |prompt: &DeviceFlowPrompt| render_device_prompt(&label, prompt);
                auth::login_device_flow(&selection, &renderer, controller)
                    .await
                    .map_err(|err| self.external_flow_error(&label, err))?
            }
            AuthFlowPreference::AuthCodePkce => {
                let renderer = |prompt: &PkceFlowPrompt| render_pkce_prompt(&label, prompt);
                auth::login_pkce(&selection, &renderer, controller)
                    .await
                    .map_err(|err| self.external_flow_error(&label, err))?
            }
        };

        Ok(ExternalLoginResult {
            provider: provider_name,
            token: token.secret,
            nonce: token.nonce,
            kind,
        })
    }

    fn external_flow_error(&self, label: &str, err: AuthFlowError) -> Report {
        debug!("external login with {label} failed: {err:?}");
        match err {
            AuthFlowError::Cancelled => eyre!(
                "Login via {label} was cancelled before completion. Run 'atuin login' again when you're ready."
            ),
            AuthFlowError::TimedOut { stage, after } => eyre!(
                "Login via {label} timed out while waiting for {stage} (after {}). Please try again and complete the step promptly.",
                describe_duration(after)
            ),
            AuthFlowError::Provider(message) => {
                eyre!("Login via {label} failed: {message}")
            }
            AuthFlowError::Network(message) => eyre!(
                "Network error while logging in with {label}: {message}. Check your connection and try again."
            ),
            AuthFlowError::Loopback(message) => eyre!(
                "Browser callback for {label} failed: {message}. Please retry the login flow."
            ),
            AuthFlowError::InvalidConfig(message) => eyre!(
                "{label} is misconfigured: {message}. Contact your server administrator to fix their auth configuration."
            ),
        }
    }

    fn prompt_provider_choice(
        &self,
        response: &AuthProvidersResponse,
        available: &[String],
    ) -> Result<String> {
        println!("\nMultiple authentication providers are available:");
        for (idx, name) in available.iter().enumerate() {
            println!(
                "  {}. {}",
                idx + 1,
                describe_provider(response, name.as_str())
            );
        }

        loop {
            eprint!(
                "Choose a provider by number (1-{}) or enter a provider name: ",
                available.len()
            );
            let input = get_input()?;

            if let Ok(index) = input.parse::<usize>() {
                if (1..=available.len()).contains(&index) {
                    return Ok(available[index - 1].clone());
                }
            }

            if let Some(name) = available
                .iter()
                .find(|candidate| candidate.eq_ignore_ascii_case(input.as_str()))
            {
                return Ok(name.clone());
            }

            println!("Invalid selection '{input}'. Please try again.");
        }
    }
}

fn render_device_prompt(label: &str, prompt: &DeviceFlowPrompt) {
    println!("\nAuthenticate with {label} using the device flow:");
    if let Some(complete) = &prompt.verification_uri_complete {
        println!("  Open {complete}");
        println!("  (If prompted, enter code {})", prompt.user_code);
    } else {
        println!(
            "  Visit {} and enter code {}",
            prompt.verification_uri, prompt.user_code
        );
    }
    println!(
        "  Code expires in {} minute(s)",
        (prompt.expires_in.as_secs() / 60).max(1)
    );
    println!("Waiting for approval...");
}

fn render_pkce_prompt(label: &str, prompt: &PkceFlowPrompt) {
    println!("\nAuthenticate with {label} using your browser:");
    println!("  Open this URL: {}", prompt.authorization_url);
    println!(
        "  After approving access you'll be redirected to {}. Keep this terminal open until the CLI confirms login.",
        prompt.redirect_uri
    );
}

fn normalize_key_input(key: &str) -> Result<String> {
    match bip39::Mnemonic::from_phrase(key, bip39::Language::English) {
        Ok(mnemonic) => Ok(encode_key(Key::from_slice(mnemonic.entropy()))?),
        Err(err) => match err.downcast_ref::<bip39::ErrorKind>() {
            Some(bip39::ErrorKind::InvalidWord) => Ok(key.to_string()),
            Some(bip39::ErrorKind::InvalidChecksum) => bail!("key mnemonic was not valid"),
            Some(
                bip39::ErrorKind::InvalidKeysize(_)
                | bip39::ErrorKind::InvalidWordLength(_)
                | bip39::ErrorKind::InvalidEntropyLength(_, _),
            ) => bail!("key was not the correct length"),
            _ => Ok(key.to_string()),
        },
    }
}

pub(super) fn or_user_input(value: Option<String>, name: &'static str) -> String {
    value.unwrap_or_else(|| read_user_input(name))
}

pub(super) fn read_user_password() -> String {
    let password = prompt_password("Please enter password: ");
    password.expect("Failed to read from input")
}

fn read_user_input(name: &'static str) -> String {
    eprint!("Please enter {name}: ");
    get_input().expect("Failed to read from input")
}

fn describe_provider(response: &AuthProvidersResponse, provider: &str) -> String {
    response
        .providers
        .iter()
        .find(|p| p.name == provider)
        .and_then(|p| p.display_name.as_deref())
        .map(|display| format!("{display} ({provider})"))
        .unwrap_or_else(|| provider.to_string())
}

fn describe_flow_preference(flow: AuthFlowPreference) -> &'static str {
    match flow {
        AuthFlowPreference::DeviceCode => "device-code",
        AuthFlowPreference::AuthCodePkce => "auth-code (PKCE)",
    }
}

fn describe_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{}s", seconds)
    } else {
        let minutes = seconds / 60;
        if minutes < 60 {
            format!("{}m", minutes)
        } else {
            let hours = minutes / 60;
            format!("{}h", hours)
        }
    }
}

#[cfg(test)]
mod tests {
    use atuin_client::encryption::Key;

    #[test]
    fn mnemonic_round_trip() {
        let key = Key::from([
            3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4, 6, 2, 6, 4, 3, 3, 8, 3, 2,
            7, 9, 5,
        ]);
        let phrase = bip39::Mnemonic::from_entropy(&key, bip39::Language::English)
            .unwrap()
            .into_phrase();
        let mnemonic = bip39::Mnemonic::from_phrase(&phrase, bip39::Language::English).unwrap();
        assert_eq!(mnemonic.entropy(), key.as_slice());
        assert_eq!(
            phrase,
            "adapt amused able anxiety mother adapt beef gaze amount else seat alcohol cage lottery avoid scare alcohol cactus school avoid coral adjust catch pink"
        );
    }
}
