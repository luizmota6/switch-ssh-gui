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
    Generico,
}

impl Vendor {
    pub const ALL: [Vendor; 5] = [
        Vendor::ArubaCx,
        Vendor::ArubaAosS,
        Vendor::CiscoIos,
        Vendor::HpeComware,
        Vendor::Generico,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Vendor::ArubaCx => "Aruba AOS-CX (6000/6100/6200/6300…)",
            Vendor::ArubaAosS => "Aruba AOS-S / ProCurve (2530/2930…)",
            Vendor::CiscoIos => "Cisco IOS / IOS-XE",
            Vendor::HpeComware => "HPE Comware (1950/5130…)",
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
            Vendor::Generico => &[],
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
}
