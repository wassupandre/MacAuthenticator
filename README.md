# MacAuthenticator

Autenticador 2FA minimalista e nativo para a barra de menus do macOS, escrito em **Swift puro em um único arquivo** e sem nenhuma dependência externa.

![Interface do MacAuthenticator na barra de menus do macOS](docs/screenshot.png)

## Sobre o Projeto

O **MacAuthenticator** nasceu como um projeto prático entre colegas de trabalho para incentivar a programação e explorar o que é possível construir no macOS usando apenas os frameworks nativos da Apple (`AppKit`, `CryptoKit`, `CoreImage` e `Security`), sem bibliotecas de terceiros, gerenciadores de pacotes ou servidores em segundo plano.

Todo o código-fonte vive em um único arquivo (`MacAuthenticator.swift`) fácil de ler, auditar e compilar direto pelo terminal.

---

## Funcionalidades

* **Multi-protocolo 2FA:**
  * **TOTP** e **HOTP** padrão (RFC 4226 / RFC 6238) com suporte a `SHA-1`, `SHA-256` e `SHA-512`.
  * Chaves em **Base32** e **Hexadecimal**.
  * **Steam Guard** (códigos alfanuméricos de 5 caracteres com alfabeto customizado).
  * **Battle.net** (códigos numéricos de 8 dígitos).
* **Importação Flexível de QR Codes:**
  * Lê imagens diretamente do disco usando `CoreImage` (`CIDetector`).
  * Suporta URIs individuais (`otpauth://...`) e **exportação em lote do Google Authenticator** (`otpauth-migration://...`) por meio de um parser Protobuf implementado do zero.
* **Experiência Nativa na Barra de Menus:**
  * **Clique esquerdo:** abre o popover com os códigos ativos e destaque em vermelho nos últimos 5 segundos antes da renovação.
  * **Clique no código:** copia o token para a área de transferência com feedback visual (`Copiado!`).
  * **Clique direito (ou `Ctrl + Clique`):** abre o menu contextual com atalho para importar QR Codes ou encerrar o aplicativo (`Sair do MacAuthenticator`).

---

## Arquitetura de Segurança

* **100% Offline:** O aplicativo não possui permissões, sockets ou código de rede. Nenhum dado sai da máquina.
* **Armazenamento no macOS Keychain:** Todas as chaves secretas são criptografadas e gerenciadas pelo sistema operacional via `Security.framework` (`SecItemAdd` / `SecItemUpdate`), configuradas com `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (acessíveis apenas com o Mac desbloqueado e não sincronizáveis/exportáveis).
* **Proteção da Área de Transferência:** Ao copiar um token, o app anexa os marcadores `org.nspasteboard.TransientType` e `org.nspasteboard.ConcealedType` para impedir que gerenciadores de histórico (como Raycast, Alfred ou Maccy) registrem o código, além de limpar o clipboard automaticamente após **30 segundos**.
* **Bloqueio de Captura de Tela:** A janela do popover utiliza `sharingType = .none`, tornando os códigos invisíveis durante compartilhamentos de tela ou gravações.

---

## Pré-requisitos e Compilação

Você precisa apenas de um Mac com as **Command Line Tools** do Xcode instaladas:

```bash
xcode-select --install
```

### Compilar e rodar pelo terminal

```bash
git clone [https://github.com/seu-usuario/MacAuthenticator.git](https://github.com/seu-usuario/MacAuthenticator.git)
cd MacAuthenticator
swiftc MacAuthenticator.swift -o MacAuthenticator
./MacAuthenticator
```

### (Opcional) Empacotar como um `.app` nativo do macOS

Para executá-lo com duplo clique sem manter uma janela de terminal aberta e sem aparecer no Dock:

```bash
mkdir -p MacAuthenticator.app/Contents/MacOS
swiftc MacAuthenticator.swift -o MacAuthenticator.app/Contents/MacOS/MacAuthenticator

cat << 'EOF' > MacAuthenticator.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "[http://www.apple.com/DTDs/PropertyList-1.0.dtd](http://www.apple.com/DTDs/PropertyList-1.0.dtd)">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>MacAuthenticator</string>
    <key>CFBundleIdentifier</key>
    <string>com.macauthenticator.2fa</string>
    <key>CFBundleName</key>
    <string>MacAuthenticator</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSUIElement</key>
    <true/>
</dict>
</plist>
EOF

open MacAuthenticator.app
```

---

## Como Usar

1. Execute o `MacAuthenticator` e clique no ícone de **cadeado** na barra de menus superior do macOS.
2. Clique em **Importar QR code…** e selecione uma imagem (PNG, JPG, captura de tela, etc.) contendo o QR Code 2FA do serviço desejado.
3. Clique sobre qualquer código exibido para copiá-lo automaticamente.
4. Para fechar o aplicativo, clique com o **botão direito** no ícone da barra de menus e selecione **Sair do MacAuthenticator**.

---

## Guia de Leitura do Código

O arquivo `MacAuthenticator.swift` está dividido em 5 blocos principais para facilitar o estudo em grupo:

| Seção | O que faz | Conceitos envolvidos |
| :--- | :--- | :--- |
| `MARK: - Modelo` | Define `OTPEntry`, `OTPType` e `OTPAlgorithm`. | `Codable`, `Enums` com valores associados e raw values. |
| `MARK: - Lógica OTP` | Implementa Base32, Hex, HMAC e Dynamic Truncation. | Manipulação de bits (*bitwise*), Big-Endian e `CryptoKit`. |
| `MARK: - Importação de QR code` | Lê imagens e interpreta URIs e payloads do Google Auth. | `CoreImage` (`CIDetector`), `URLComponents` e decodificação binária de Protobuf (`Varint`). |
| `MARK: - Armazenamento Seguro` | Salva, atualiza e carrega contas no Keychain. | `Security.framework` (`CFDictionary`, `SecItem*`). |
| `MARK: - Interface` | Constrói o ícone da barra de menus, popover e menu contextual. | `AppKit` (`NSStatusItem`, `NSPopover`, `NSStackView`, `NSPasteboard`). |
