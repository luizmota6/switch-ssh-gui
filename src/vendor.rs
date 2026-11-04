use serde::{Deserialize, Serialize};

/// Perfis de fabricante: comandos de inicialização (desligar paginação)
/// e atalhos de comandos somente-leitura.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Vendor {
    ArubaCx,
    #[default]
    ArubaAosS,
    CiscoIos,
    HpeComware,
    Dell,
    Mikrotik,
    PaloAlto,
    Generico,
}

impl Vendor {
    pub const ALL: [Vendor; 8] = [
        Vendor::ArubaCx,
        Vendor::ArubaAosS,
        Vendor::CiscoIos,
        Vendor::HpeComware,
        Vendor::Dell,
        Vendor::Mikrotik,
        Vendor::PaloAlto,
        Vendor::Generico,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Vendor::ArubaCx => "Aruba AOS-CX (6000/6100/6200/6300…)",
            Vendor::ArubaAosS => "Aruba AOS-S / ProCurve (2530/2930…)",
            Vendor::CiscoIos => "Cisco IOS / IOS-XE",
            Vendor::HpeComware => "HPE Comware (1950/5130…)",
            Vendor::Dell => "Dell (N-Series OS6 / OS9 / OS10)",
            Vendor::Mikrotik => "MikroTik RouterOS",
            Vendor::PaloAlto => "Palo Alto PAN-OS",
            Vendor::Generico => "Genérico",
        }
    }

    /// Comandos enviados logo após o login.
    pub fn init_commands(self) -> &'static [&'static str] {
        match self {
            Vendor::ArubaCx => &["no page"],
            Vendor::ArubaAosS => &["no page", "terminal width 200"],
            Vendor::CiscoIos => &["terminal length 0", "terminal width 0"],
            Vendor::HpeComware => &["screen-length disable"],
            Vendor::Dell => &["terminal length 0"],
            // RouterOS não tem comando global para desligar o pager; o auto --More-- cuida disso
            Vendor::Mikrotik => &[],
            Vendor::PaloAlto => &["set cli pager off"],
            Vendor::Generico => &[],
        }
    }

    /// Comando que imprime a configuração em uso (para backup).
    pub fn backup_command(self) -> &'static str {
        match self {
            Vendor::HpeComware => "display current-configuration",
            Vendor::Mikrotik => "/export",
            Vendor::PaloAlto => "show config running",
            _ => "show running-config",
        }
    }

    /// Extensão do arquivo de backup (formato que o equipamento reimporta).
    pub fn backup_extension(self) -> &'static str {
        match self {
            Vendor::Mikrotik => "rsc",
            Vendor::PaloAlto => "xml",
            _ => "cfg",
        }
    }

    /// (rótulo, comando)
    pub fn quick_commands(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Vendor::ArubaCx => &[
                ("Sistema", "show system"),
                ("Versão", "show version"),
                ("Interfaces", "show interface brief"),
                ("VLANs", "show vlan"),
                ("Tabela MAC", "show mac-address-table"),
                ("Vizinhos LLDP", "show lldp neighbor-info"),
                ("PoE", "show power-over-ethernet brief"),
                ("Running-config", "show running-config"),
                ("Logs", "show logging -r"),
            ],
            Vendor::ArubaAosS => &[
                ("Sistema", "show system"),
                ("Versão", "show version"),
                ("Interfaces", "show interfaces brief"),
                ("VLANs", "show vlans"),
                ("Tabela MAC", "show mac-address"),
                ("Vizinhos LLDP", "show lldp info remote-device"),
                ("PoE", "show power-over-ethernet brief"),
                ("Running-config", "show running-config"),
                ("Logs", "show logging -r"),
            ],
            Vendor::CiscoIos => &[
                ("Versão", "show version"),
                ("Interfaces IP", "show ip interface brief"),
                ("Status portas", "show interfaces status"),
                ("VLANs", "show vlan brief"),
                ("Tabela MAC", "show mac address-table"),
                ("Vizinhos CDP", "show cdp neighbors"),
                ("Vizinhos LLDP", "show lldp neighbors"),
                ("Running-config", "show running-config"),
                ("Logs", "show logging"),
            ],
            Vendor::HpeComware => &[
                ("Versão", "display version"),
                ("Interfaces", "display interface brief"),
                ("VLANs", "display vlan brief"),
                ("Tabela MAC", "display mac-address"),
                ("Vizinhos LLDP", "display lldp neighbor-information list"),
                ("Configuração", "display current-configuration"),
                ("Logs", "display logbuffer"),
            ],
            Vendor::Dell => &[
                ("Versão", "show version"),
                ("Interfaces IP", "show ip interface brief"),
                ("Status portas", "show interfaces status"),
                ("VLANs", "show vlan"),
                ("Tabela MAC", "show mac address-table"),
                ("Vizinhos LLDP", "show lldp neighbors"),
                ("Running-config", "show running-config"),
                ("Logs", "show logging"),
            ],
            Vendor::Mikrotik => &[
                ("Recursos", "/system resource print"),
                ("RouterBoard", "/system routerboard print"),
                ("Interfaces", "/interface print"),
                ("Endereços IP", "/ip address print"),
                ("Rotas", "/ip route print"),
                ("Tabela MAC", "/interface bridge host print"),
                ("Vizinhos", "/ip neighbor print"),
                ("Configuração", "/export"),
                ("Logs", "/log print"),
            ],
            Vendor::PaloAlto => &[
                ("Sistema", "show system info"),
                ("Recursos", "show system resources"),
                ("Interfaces", "show interface all"),
                ("Rotas", "show routing route"),
                ("Tabela ARP", "show arp all"),
                ("Sessões", "show session info"),
                ("HA", "show high-availability state"),
                ("Jobs", "show jobs all"),
                ("Configuração", "show config running"),
            ],
            Vendor::Generico => &[],
        }
    }
}

/// Comandos que alteram estado/derrubam o equipamento pedem confirmação.
pub fn is_dangerous(cmd: &str) -> bool {
    let c = cmd.trim().to_lowercase();
    const PREFIXES: [&str; 8] = [
        "reload", "reboot", "boot", "erase", "write erase", "delete", "format", "shutdown",
    ];
    PREFIXES.iter().any(|p| c.starts_with(p))
        || c.contains("factory")
        || c.starts_with("no vlan")
        || c.starts_with("undo vlan")
        || c.starts_with("reset saved")
        // MikroTik
        || c.contains("system reboot")
        || c.contains("system shutdown")
        || c.contains("reset-configuration")
        // Palo Alto
        || c.starts_with("request restart")
        || c.starts_with("request shutdown")
        || c.contains("private-data-reset")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comandos_perigosos_novos_fabricantes() {
        assert!(is_dangerous("/system reboot"));
        assert!(is_dangerous("/system reset-configuration no-defaults=yes"));
        assert!(is_dangerous("request restart system"));
        assert!(is_dangerous("request system private-data-reset"));
        assert!(!is_dangerous("/system resource print"));
        assert!(!is_dangerous("show config running"));
    }
}
