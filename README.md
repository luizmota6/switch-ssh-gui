# Switch SSH Console (Rust + egui)

Interface desktop para acesso SSH/CLI a switches gerenciáveis. Binário único, nativo (Windows/Linux), sem runtime.

## Recursos

- **Perfis de switch** (nome, protocolo, host, porta, usuário, fabricante, comandos personalizados) — salvos em JSON. **Senha nunca é gravada em disco.** O usuário é opcional.
- **SSH ou Telnet** por perfil. No Telnet (porta 23, **sem criptografia**) o app negocia eco/tamanho da janela/tipo de terminal e, se usuário e senha estiverem preenchidos, responde sozinho aos prompts `Username:`/`login:` e `Password:`; com eles em branco, digite no terminal. Os comandos de inicialização do fabricante só são enviados depois que aparece o prompt da CLI (`#`, `>` ou `]`).
- **Senha mestra + 2FA (opcional)** — em **🔒 Segurança**: a abertura do programa passa a pedir senha mestra e o código TOTP de 6 dígitos (Google/Microsoft Authenticator, Authy…; cadastro por QR code). Perfis, chaves de host e — se marcado "Lembrar senha no cofre" — as senhas dos switches ficam em `cofre.json`, cifrado com AES-256-GCM e chave derivada por Argon2id. 10 códigos de recuperação de uso único para o caso de perder o celular; botão **Bloquear** fecha o cofre na hora. **A senha mestra não pode ser recuperada.**
- **Autenticação** por senha (com fallback *keyboard-interactive*, comum em switches) ou chave privada (+ passphrase).
- **Verificação de chave do host (TOFU)**: na 1ª conexão mostra o fingerprint `SHA256:` para conferir; nas próximas, bloqueia a conexão se a chave mudar (alerta de MITM).
- **Emulador de terminal xterm-256color completo** (crate `vt100`): cores, tela alternativa, cursor — roda **nano, vim, htop, mc** e menus de switch. O PTY acompanha o tamanho da janela.
- **Teclado direto**: clique no terminal e digite. Setas, Home/End, PgUp/PgDn, F1–F12, Ctrl+letra (Ctrl+O, Ctrl+X, Ctrl+W…), Alt+letra (M-x do nano), Shift+Tab. **Ctrl+V cola** a área de transferência. Roda do mouse = histórico (5.000 linhas).
- **Barra de comando** opcional embaixo (histórico ↑/↓) + Ctrl+C / Ctrl+Z / `?`.
- **Paginação automática**: responde sozinho a `--More--`, `-- MORE --` e `Press any key to continue` (liga/desliga durante a sessão).
- **Comandos de inicialização por fabricante** (desliga paginação após o login):

| Fabricante | Init | Atalhos |
|---|---|---|
| Aruba AOS-CX | `no page` | system, version, interface brief, vlan, mac-address-table, lldp, PoE, running-config, logs |
| Aruba AOS-S / ProCurve | `no page`, `terminal width 200` | idem (sintaxe AOS-S) |
| Cisco IOS/IOS-XE | `terminal length 0`, `terminal width 0` | version, ip int brief, int status, vlan, mac, CDP/LLDP, running-config, logging |
| HPE Comware | `screen-length disable` | display version/interface/vlan/mac/lldp/current-configuration/logbuffer |
| Dell (N-Series OS6 / OS9 / OS10) | `terminal length 0` | version, ip int brief, int status, vlan, mac, LLDP, running-config, logging |
| MikroTik RouterOS | — (o pager `[Q quit\|D dump\|down]` é respondido com D) | resource, routerboard, interfaces, IP, rotas, bridge host, neighbors, `/export`, log |
| Palo Alto PAN-OS | `set cli pager off` | system info/resources, interfaces, rotas, ARP, sessões, HA, jobs, `show config running` |

Backup da configuração por fabricante: `show running-config` (`.cfg`) na maioria; Comware `display current-configuration` (`.cfg`); MikroTik `/export` (`.rsc`, reimporta com `/import`); Palo Alto `show config running` (`.xml`, formato que o PAN-OS importa).
| Genérico | — | só os personalizados |

- **Backup da configuração** (SSH ou Telnet): botão no painel direito executa `show running-config` (Comware: `display current-configuration`), pagina sozinho, espera o prompt voltar e grava só a configuração (sem eco nem prompt) em `backups\<perfil>_<data>.cfg`. Respostas de erro da CLI (ex.: falta de `enable` no Cisco) não viram arquivo.
- **Confirmação de comandos perigosos** (`reload`, `boot`, `erase`, `delete`, `format`, `shutdown`, `no vlan`, `factory`…).
- **Log automático da sessão** em arquivo + "Salvar saída" e "Copiar tudo".
- Keepalive SSH a cada 30 s; buffer de 50.000 linhas com renderização virtualizada.

## Onde ficam os arquivos

| | Windows | Linux |
|---|---|---|
| Config/perfis/known hosts | `%APPDATA%\switch-ssh-gui\config\config.json` | `~/.config/switch-ssh-gui/config.json` |
| Idem, com senha mestra + 2FA (cifrado) | `%APPDATA%\switch-ssh-gui\config\cofre.json` | `~/.config/switch-ssh-gui/cofre.json` |
| Logs | `%APPDATA%\switch-ssh-gui\data\logs\` | `~/.local/share/switch-ssh-gui/logs/` |
| Backups de configuração | `%APPDATA%\switch-ssh-gui\data\backups\` | `~/.local/share/switch-ssh-gui/backups/` |

## Compilar

Pré-requisito: Rust estável (`rustup`), https://rustup.rs

### Windows (MSVC)
Pré-requisito extra: **Strawberry Perl** (compila o OpenSSL embutido, que dá suporte a curve25519/ed25519/AES-GCM/chacha20 exigidos por OpenSSH moderno). NASM é opcional.
```powershell
winget install StrawberryPerl.StrawberryPerl
# abra um NOVO PowerShell
cargo build --release
# binário: target\release\switch-ssh-gui.exe (OpenSSL estático, sem DLL extra)
```

### Linux (Debian/Ubuntu)
```bash
sudo apt install build-essential pkg-config libssl-dev libxkbcommon-dev libgl1-mesa-dev
cargo build --release
./target/release/switch-ssh-gui
```

### Via GitHub Actions
O workflow em `.github/workflows/build.yml` compila Windows e Linux a cada push/tag e publica os binários como *artifacts*.

## Testes

```bash
cargo test                       # unitários (emulação de terminal)
cargo test -- --ignored          # integração: exige um switch simulado em 127.0.0.1:2222
                                 # (usuário sw / Teste@123) — veja abaixo
```

O teste de integração conecta num switch simulado que imita uma CLI AOS-CX (banner "Press any key", prompt `SWT-LAB#`, `show version`, `show interface brief` com `-- MORE --` a cada 20 linhas, ANSI). Há duas opções:

**`tools/fakeswitch-server` (Windows/Linux, recomendado)** — servidor SSH próprio em Rust; não precisa de sshd, WSL, Python nem administrador. Aceita senha e keyboard-interactive; gera chave de host nova a cada execução.
```powershell
# terminal 1 — sobe o switch simulado em 127.0.0.1:2222 (Ctrl+C para parar)
cd tools\fakeswitch-server
cargo run --release

# terminal 2 — na raiz do projeto
cargo test --release -- --ignored
```
Para escutar em outro endereço: `FAKESWITCH_ADDR=0.0.0.0:2222`. Com ele rodando, dá para testar a interface também: crie um perfil para `127.0.0.1`, porta `2222`, usuário `sw`.

**`tools/fakeswitch.py` (só Linux)** — o mesmo simulador como shell de login de um usuário `sw` (senha `Teste@123`) num `sshd` real escutando na porta 2222.

## Observações

- Switches **Aruba Instant On 1930** são gerenciados via web/app e não oferecem CLI SSH completa; este app é para equipamentos com CLI (AOS-CX, AOS-S, Cisco, Comware etc.).
- Em AOS-S/ProCurve, habilite SSH no switch: `crypto key generate ssh rsa bits 2048` → `ip ssh` → `no telnet-server`.

## Máquinas sem GPU / RDP / VM

O projeto inclui o **Mesa3D llvmpipe** (`mesa/x64`, OpenGL 4.x por software, licença MIT).
No Windows, o `build.rs` copia `opengl32.dll` e `libgallium_wgl.dll` para `target\debug` e
`target\release` automaticamente — a janela abre mesmo sem placa de vídeo.

Para distribuir: leve o `.exe` **junto com as duas DLLs** na mesma pasta.
Em máquinas com GPU, pode apagar as DLLs para usar aceleração de hardware (opcional).

Erros de inicialização ficam em `%APPDATA%\switch-ssh-gui\config\erro.log`.
