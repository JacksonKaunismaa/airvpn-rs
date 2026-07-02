use super::views;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

/// All profile-backed settings fields, extracted from App for clarity.
pub(crate) struct SettingsState {
    pub(crate) credentials_configured: bool,
    pub(crate) connect: bool,
    pub(crate) startlast: bool,
    pub(crate) locklast: bool,
    pub(crate) ipv6_mode: String,
    pub(crate) ipv4_mode: String,
    pub(crate) entry_iface: String,
    pub(crate) dns: String,
    pub(crate) loaded: bool,
    pub(crate) dirty: bool,

    // Settings sub-tab navigation
    pub(crate) sub_tab: views::settings::SettingsSubTab,

    // WireGuard settings (text for text_input widget)
    pub(crate) wg_key: String,
    pub(crate) wg_mtu: String,
    pub(crate) wg_keepalive: String,
    pub(crate) wg_handshake_first: String,
    pub(crate) wg_handshake_connected: String,

    // Network Lock settings
    pub(crate) netlock_incoming: String,
    pub(crate) netlock_allow_ping: bool,
    pub(crate) netlock_allowlist_ips: String,
    pub(crate) netlock_local_forward_ifaces: String,

    // Routes
    pub(crate) routes_custom: String,

    // Area filter settings
    pub(crate) areas_allowlist: String,
    pub(crate) areas_denylist: String,

    // DNS settings
    pub(crate) dns_mode: String,
    pub(crate) dns_services: String,

    // UI display settings
    pub(crate) ui_unit: String,
    pub(crate) ui_iec: bool,

    // Logging settings
    pub(crate) log_file_enabled: bool,
    pub(crate) log_file_path: String,
    pub(crate) log_level_debug: bool,

    // Mode settings
    pub(crate) mode_port: String,

    // Advanced settings (text for text_input widget)
    pub(crate) pinger_timeout: String,
    pub(crate) manifest_refresh: String,
    pub(crate) penality: String,
    pub(crate) http_timeout: String,
    pub(crate) checking_ntry: String,
    pub(crate) capacity_factor: String,
    pub(crate) check_route: bool,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            credentials_configured: false,
            connect: false,
            startlast: false,
            locklast: false,
            ipv6_mode: String::new(),
            ipv4_mode: String::new(),
            entry_iface: String::new(),
            dns: String::new(),
            loaded: false,
            dirty: false,
            sub_tab: views::settings::SettingsSubTab::General,
            wg_key: String::new(),
            wg_mtu: String::new(),
            wg_keepalive: String::new(),
            wg_handshake_first: String::new(),
            wg_handshake_connected: String::new(),
            netlock_incoming: String::new(),
            netlock_allow_ping: true,
            netlock_allowlist_ips: String::new(),
            netlock_local_forward_ifaces: String::new(),
            routes_custom: String::new(),
            areas_allowlist: String::new(),
            areas_denylist: String::new(),
            dns_mode: String::new(),
            dns_services: String::new(),
            ui_unit: String::new(),
            ui_iec: false,
            log_file_enabled: false,
            log_file_path: String::new(),
            log_level_debug: false,
            mode_port: String::new(),
            pinger_timeout: String::new(),
            manifest_refresh: String::new(),
            penality: String::new(),
            http_timeout: String::new(),
            checking_ntry: String::new(),
            capacity_factor: String::new(),
            check_route: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(views::Tab),
    Connect,
    ConnectToServer(String),
    Disconnect,
    Recover,
    /// Device/key picked from the Overview dropdown (persisted immediately).
    OverviewKeyChanged(String),
    Tick,
    HelperConnected,
    FetchServers,
    ServerClicked(usize),
    ServerSort(views::servers::SortColumn),
    ServerSearchChanged(String),
    LogFilterToggle(String),
    LogClear,
    FetchProfile,
    SaveSettings,
    SettingsConnectToggle(bool),
    SettingsStartlastToggle(bool),
    SettingsLocklastToggle(bool),
    SettingsIpv6ModeChanged(String),
    SettingsIpv4ModeChanged(String),
    SettingsEntryIfaceChanged(String),
    SettingsDnsChanged(String),
    ShowErrorsToggle(bool),
    ConnectNoLockToggle(bool),
    ConnectAllowLanToggle(bool),
    ConnectNoReconnectToggle(bool),
    ConnectNoVerifyToggle(bool),
    SettingsSubTabChanged(views::settings::SettingsSubTab),
    FetchKeys,
    // WireGuard settings
    SettingsWgMtuChanged(String),
    SettingsWgKeepaliveChanged(String),
    SettingsWgHandshakeFirstChanged(String),
    SettingsWgHandshakeConnectedChanged(String),
    // Area filter settings
    SettingsAreasAllowlistChanged(String),
    SettingsAreasDenylistChanged(String),
    // Network Lock settings
    SettingsNetlockIncomingChanged(String),
    SettingsNetlockAllowPingToggle(bool),
    SettingsNetlockAllowlistIpsChanged(String),
    SettingsNetlockLocalForwardIfacesChanged(String),
    // Routes
    SettingsRoutesCustomChanged(String),
    // DNS settings
    SettingsDnsModeChanged(String),
    SettingsDnsServicesChanged(String),
    // UI display settings
    SettingsUiUnitChanged(String),
    SettingsUiIecToggle(bool),
    // Logging settings
    SettingsLogFileEnabledToggle(bool),
    SettingsLogFilePathChanged(String),
    SettingsLogLevelDebugToggle(bool),
    // Mode settings
    SettingsModePortChanged(String),
    // Advanced settings
    SettingsPingerTimeoutChanged(String),
    SettingsManifestRefreshChanged(String),
    SettingsPenalityChanged(String),
    SettingsHttpTimeoutChanged(String),
    SettingsCheckingNtryChanged(String),
    SettingsCapacityFactorChanged(String),
    SettingsCheckRouteToggle(bool),
    LockInstall,
    LockUninstall,
    LockEnable,
    LockDisable,
    EddieImportAccept,
    EddieImportCancel,
}
