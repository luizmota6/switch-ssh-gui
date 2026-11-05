use serde::{Deserialize, Serialize};

/// Perfis de fabricante: comandos de inicialização (desligar paginação)
/// e atalhos de comandos somente-leitura.
/// Sem padrão: o fabricante precisa ser escolhido explicitamente em cada perfil.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Vendor {
    ArubaCx,
    ArubaAosS,
    CiscoIos,
    HpeComware,
    Dell,
    Mikrotik,
    PaloAlto,
    Fortigate,
    Generico,
}

impl Vendor {
    pub const ALL: [Vendor; 9] = [
        Vendor::ArubaCx,
        Vendor::ArubaAosS,
        Vendor::CiscoIos,
        Vendor::HpeComware,
        Vendor::Dell,
        Vendor::Mikrotik,
        Vendor::PaloAlto,
        Vendor::Fortigate,
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
            Vendor::Fortigate => "Fortinet FortiGate (FortiOS)",
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
            // FortiOS só desliga o pager alterando a config (config system console);
            // o auto --More-- cuida disso sem mexer no equipamento
            Vendor::Fortigate => &[],
            Vendor::Generico => &[],
        }
    }

    /// Comando que imprime a configuração em uso (para backup).
    pub fn backup_command(self) -> &'static str {
        match self {
            Vendor::HpeComware => "display current-configuration",
            Vendor::Mikrotik => "/export",
            Vendor::PaloAlto => "show config running",
            // só o que difere do padrão: mesmo formato do backup .conf do FortiOS
            Vendor::Fortigate => "show",
            _ => "show running-config",
        }
    }

    /// Extensão do arquivo de backup (formato que o equipamento reimporta).
    pub fn backup_extension(self) -> &'static str {
        match self {
            Vendor::Mikrotik => "rsc",
            Vendor::PaloAlto => "xml",
            Vendor::Fortigate => "conf",
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
            Vendor::Fortigate => &[
                ("Status", "get system status"),
                ("Desempenho", "get system performance status"),
                ("Interfaces", "get system interface physical"),
                ("Rotas", "get router info routing-table all"),
                ("Tabela ARP", "get system arp"),
                ("Sessões", "diagnose sys session stat"),
                ("HA", "get system ha status"),
                ("VPN IPsec", "get vpn ipsec tunnel summary"),
                ("Configuração", "show"),
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
        // FortiGate (reboot/shutdown/factoryreset já cobertos acima via "contains")
        || c.starts_with("execute reboot")
        || c.starts_with("execute shutdown")
        || c.starts_with("execute restore")
        || c.starts_with("execute formatlogdisk")
        || c.starts_with("execute erase-disk")
        // `purge` apaga TODAS as entradas da tabela em edição
        || c.starts_with("purge")
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

    #[test]
    fn fortigate() {
        assert!(is_dangerous("execute reboot"));
        assert!(is_dangerous("execute shutdown"));
        assert!(is_dangerous("execute factoryreset"));
        assert!(is_dangerous("execute restore config tftp backup.conf 10.0.0.5"));
        assert!(is_dangerous("purge"));
        assert!(!is_dangerous("get system status"));
        assert!(!is_dangerous("show"));
        assert_eq!(Vendor::Fortigate.backup_command(), "show");
        assert_eq!(Vendor::Fortigate.backup_extension(), "conf");
        assert!(Vendor::Fortigate.init_commands().is_empty());
        assert!(Vendor::ALL.contains(&Vendor::Fortigate));
    }
}
