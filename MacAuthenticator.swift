import Cocoa
import CryptoKit
import CoreImage
import Security
import UniformTypeIdentifiers

// MARK: - Modelo

enum OTPType: String, Codable {
    case totp    // tempo, secret base32
    case hotp    // contador, secret base32
    case hex     // tempo, secret hexadecimal
    case hhex    // contador, secret hexadecimal
    case steam   // Steam Guard (tempo, base32, 5 caracteres)
    case battle  // Battle.net (tempo, hexadecimal, 8 dígitos)
}

enum OTPAlgorithm: String, Codable {
    case sha1, sha256, sha512
}

struct OTPEntry: Codable {
    var id = UUID()
    var issuer: String
    var account: String
    var secret: String
    var type: OTPType = .totp
    var algorithm: OTPAlgorithm = .sha1
    var digits: Int = 6
    var period: Int = 30
    var counter: UInt64 = 0
}

// MARK: - Lógica OTP

enum OTP {
    static let steamAlphabet = Array("23456789BCDFGHJKMNPQRTVWXY")

    // Decodifica Base32 (RFC 4648), ignorando espaços, hífens, minúsculas e padding
    static func base32Decode(_ input: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var bits = 0
        var value = 0
        var output = [UInt8]()
        let clean = input.uppercased().filter { $0 != " " && $0 != "-" && $0 != "=" }
        for ch in clean {
            guard let idx = alphabet.firstIndex(of: ch) else { return nil }
            value = (value << 5) | idx
            bits += 5
            if bits >= 8 {
                output.append(UInt8((value >> (bits - 8)) & 0xFF))
                bits -= 8
            }
        }
        return Data(output)
    }

    static func base32Encode(_ data: Data) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var output = ""
        var buffer = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                output.append(alphabet[(buffer >> (bits - 5)) & 31])
                bits -= 5
            }
            buffer &= (1 << bits) - 1
        }
        if bits > 0 {
            output.append(alphabet[(buffer << (5 - bits)) & 31])
        }
        return output
    }

    static func hexDecode(_ input: String) -> Data? {
        let clean = input.filter { $0 != " " && $0 != "-" }
        guard clean.count % 2 == 0 else { return nil }
        var data = Data()
        var index = clean.startIndex
        while index < clean.endIndex {
            let next = clean.index(index, offsetBy: 2)
            guard let byte = UInt8(clean[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        return data
    }

    static func hmac(_ algorithm: OTPAlgorithm, key: Data, message: Data) -> [UInt8] {
        let symmetricKey = SymmetricKey(data: key)
        switch algorithm {
        case .sha1:
            return Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: symmetricKey))
        case .sha256:
            return Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey))
        case .sha512:
            return Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey))
        }
    }

    // Truncamento dinâmico (RFC 4226) -> inteiro de 31 bits
    static func truncate(_ hash: [UInt8]) -> UInt32 {
        let offset = Int(hash[hash.count - 1] & 0x0F)
        return (UInt32(hash[offset] & 0x7F) << 24)
            | (UInt32(hash[offset + 1]) << 16)
            | (UInt32(hash[offset + 2]) << 8)
            | UInt32(hash[offset + 3])
    }

    static func counterData(_ counter: UInt64) -> Data {
        var be = counter.bigEndian
        return Data(bytes: &be, count: 8)
    }

    // Gera o código atual. Retorna nil se o secret ou parâmetros forem inválidos.
    static func generate(_ entry: OTPEntry, at date: Date = Date()) -> String? {
        guard (1...10).contains(entry.digits), entry.period > 0 else { return nil }

        let key: Data?
        switch entry.type {
        case .totp, .hotp, .steam:
            key = base32Decode(entry.secret)
        case .hex, .hhex, .battle:
            key = hexDecode(entry.secret)
        }
        guard let keyData = key, !keyData.isEmpty else { return nil }

        let counter: UInt64
        switch entry.type {
        case .hotp, .hhex:
            counter = entry.counter
        default:
            counter = UInt64(date.timeIntervalSince1970) / UInt64(entry.period)
        }

        let hash = hmac(entry.algorithm, key: keyData, message: counterData(counter))
        var number = truncate(hash)

        switch entry.type {
        case .steam:
            var code = ""
            for _ in 0..<5 {
                code.append(steamAlphabet[Int(number % UInt32(steamAlphabet.count))])
                number /= UInt32(steamAlphabet.count)
            }
            return code
        case .battle:
            return pad(number % 100_000_000, to: 8)
        default:
            // Usa UInt64 para evitar integer overflow quando digits == 10 (10^10 > UInt32.max)
            var mod: UInt64 = 1
            for _ in 0..<entry.digits { mod *= 10 }
            let codeValue = UInt32(UInt64(number) % mod)
            return pad(codeValue, to: entry.digits)
        }
    }

    static func pad(_ value: UInt32, to length: Int) -> String {
        let s = String(value)
        return String(repeating: "0", count: max(0, length - s.count)) + s
    }

    static func secondsRemaining(_ entry: OTPEntry, at date: Date = Date()) -> Int? {
        guard entry.period > 0 else { return nil }
        switch entry.type {
        case .hotp, .hhex:
            return nil
        default:
            return entry.period - (Int(date.timeIntervalSince1970) % entry.period)
        }
    }
}

// MARK: - Importação de QR code

enum QRImport {
    // Lê todos os QR codes de um arquivo de imagem e devolve o texto de cada um
    static func readQRCodes(from url: URL) -> [String] {
        guard let image = CIImage(contentsOf: url) else { return [] }
        let detector = CIDetector(
            ofType: CIDetectorTypeQRCode,
            context: nil,
            options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]
        )
        let features = detector?.features(in: image) ?? []
        return features.compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }

    // Aceita otpauth:// (uma conta) e otpauth-migration:// (exportação do Google Authenticator)
    static func parseAll(uri: String) -> [OTPEntry] {
        let text = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        if text.lowercased().hasPrefix("otpauth-migration://") {
            return parseMigration(uri: text)
        }
        if let entry = parse(uri: text) { return [entry] }
        return []
    }

    // Leitor mínimo de protobuf
    private struct ProtoReader {
        let bytes: [UInt8]
        var pos = 0

        init(_ bytes: [UInt8]) { self.bytes = bytes }

        var atEnd: Bool { pos >= bytes.count }

        mutating func readVarint() -> UInt64? {
            var result: UInt64 = 0
            var shift: UInt64 = 0
            while pos < bytes.count {
                let byte = bytes[pos]
                pos += 1
                result |= UInt64(byte & 0x7F) << shift
                if byte & 0x80 == 0 { return result }
                shift += 7
                if shift > 63 { return nil }
            }
            return nil
        }

        mutating func readBytes() -> [UInt8]? {
            guard let length = readVarint(), length <= UInt64(bytes.count - pos) else { return nil }
            let slice = Array(bytes[pos..<(pos + Int(length))])
            pos += Int(length)
            return slice
        }

        mutating func skip(wireType: UInt64) -> Bool {
            switch wireType {
            case 0:
                return readVarint() != nil
            case 1:
                guard pos + 8 <= bytes.count else { return false }
                pos += 8
                return true
            case 2:
                return readBytes() != nil
            case 5:
                guard pos + 4 <= bytes.count else { return false }
                pos += 4
                return true
            default:
                return false
            }
        }
    }

    // otpauth-migration://offline?data=BASE64(MigrationPayload)
    private static func parseMigration(uri: String) -> [OTPEntry] {
        guard let components = URLComponents(string: uri),
              var base64 = components.queryItems?.first(where: { $0.name == "data" })?.value else { return [] }

        base64 = base64
            .replacingOccurrences(of: " ", with: "+")
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }

        guard let data = Data(base64Encoded: base64) else { return [] }

        var reader = ProtoReader([UInt8](data))
        var result = [OTPEntry]()

        while !reader.atEnd {
            guard let tag = reader.readVarint() else { break }
            let field = tag >> 3
            let wire = tag & 7
            if field == 1 && wire == 2 {
                guard let payload = reader.readBytes() else { break }
                if let entry = parseOtpParameters(payload) { result.append(entry) }
            } else if !reader.skip(wireType: wire) {
                break
            }
        }
        return result
    }

    private static func parseOtpParameters(_ bytes: [UInt8]) -> OTPEntry? {
        var reader = ProtoReader(bytes)
        var secret = Data()
        var name = ""
        var issuer = ""
        var algorithmCode: UInt64 = 1
        var digitsCode: UInt64 = 1
        var typeCode: UInt64 = 2
        var counter: UInt64 = 0

        while !reader.atEnd {
            guard let tag = reader.readVarint() else { return nil }
            let field = tag >> 3
            let wire = tag & 7

            switch (field, wire) {
            case (1, 2):
                guard let value = reader.readBytes() else { return nil }
                secret = Data(value)
            case (2, 2):
                guard let value = reader.readBytes() else { return nil }
                name = String(decoding: value, as: UTF8.self)
            case (3, 2):
                guard let value = reader.readBytes() else { return nil }
                issuer = String(decoding: value, as: UTF8.self)
            case (4, 0):
                guard let value = reader.readVarint() else { return nil }
                algorithmCode = value
            case (5, 0):
                guard let value = reader.readVarint() else { return nil }
                digitsCode = value
            case (6, 0):
                guard let value = reader.readVarint() else { return nil }
                typeCode = value
            case (7, 0):
                guard let value = reader.readVarint() else { return nil }
                counter = value
            default:
                if !reader.skip(wireType: wire) { return nil }
            }
        }

        guard !secret.isEmpty else { return nil }

        let algorithm: OTPAlgorithm
        switch algorithmCode {
        case 0, 1: algorithm = .sha1
        case 2: algorithm = .sha256
        case 3: algorithm = .sha512
        default: return nil // MD5 não é suportado
        }

        let type: OTPType = (typeCode == 1) ? .hotp : .totp
        let digits = (digitsCode == 2) ? 8 : 6

        var account = name
        if let colon = name.firstIndex(of: ":") {
            let prefix = String(name[..<colon]).trimmingCharacters(in: .whitespaces)
            account = String(name[name.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if issuer.isEmpty { issuer = prefix }
        }
        if issuer.isEmpty { issuer = account.isEmpty ? "Sem nome" : account }

        return OTPEntry(
            issuer: issuer,
            account: account,
            secret: OTP.base32Encode(secret),
            type: type,
            algorithm: algorithm,
            digits: digits,
            period: 30,
            counter: counter
        )
    }

    // Converte uma URI otpauth://totp/Issuer:conta?secret=...&issuer=... em OTPEntry
    static func parse(uri: String) -> OTPEntry? {
        guard let components = URLComponents(string: uri.trimmingCharacters(in: .whitespacesAndNewlines)),
              components.scheme?.lowercased() == "otpauth",
              let host = components.host?.lowercased() else { return nil }

        let type: OTPType
        switch host {
        case "totp": type = .totp
        case "hotp": type = .hotp
        case "steam": type = .steam
        default: return nil
        }

        var params = [String: String]()
        for item in components.queryItems ?? [] {
            if let value = item.value { params[item.name.lowercased()] = value }
        }

        guard let secret = params["secret"], OTP.base32Decode(secret) != nil else { return nil }

        let label = String(components.path.drop(while: { $0 == "/" }))
        var issuer = ""
        var account = label
        if let colon = label.firstIndex(of: ":") {
            issuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            account = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        if let issuerParam = params["issuer"], !issuerParam.isEmpty { issuer = issuerParam }
        if issuer.isEmpty { issuer = account.isEmpty ? "Sem nome" : account }

        var algorithm = OTPAlgorithm.sha1
        switch params["algorithm"]?.uppercased() {
        case "SHA256": algorithm = .sha256
        case "SHA512": algorithm = .sha512
        default: break
        }

        let digits = Int(params["digits"] ?? "") ?? 6
        let period = Int(params["period"] ?? "") ?? 30
        let counter = UInt64(params["counter"] ?? "") ?? 0

        guard (6...10).contains(digits), period > 0 else { return nil }

        return OTPEntry(
            issuer: issuer,
            account: account,
            secret: secret,
            type: type,
            algorithm: algorithm,
            digits: digits,
            period: period,
            counter: counter
        )
    }
}

// MARK: - Armazenamento Seguro (macOS Keychain)

enum Store {
    private static let service = "com.macauthenticator.2fa"
    private static let account = "entries"

    static func load() -> [OTPEntry] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let entries = try? JSONDecoder().decode([OTPEntry].self, from: data) else {
            return []
        }
        return entries
    }

    @discardableResult
    static func save(_ entries: [OTPEntry]) -> Bool {
        guard let data = try? JSONEncoder().encode(entries) else { return false }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]

        let attributes: [String: Any] = [
            kSecValueData as String: data
        ]

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            // Protege o segredo para só ser acessível com o Mac desbloqueado e neste dispositivo
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            return SecItemAdd(addQuery as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }
}

// MARK: - Interface

final class CodeRow: NSStackView {
    static let rowWidth: CGFloat = 320

    let entry: OTPEntry
    let codeButton = NSButton()

    init(entry: OTPEntry) {
        self.entry = entry
        super.init(frame: .zero)

        orientation = .horizontal
        alignment = .centerY
        distribution = .fill
        spacing = 12
        widthAnchor.constraint(equalToConstant: CodeRow.rowWidth).isActive = true

        // Retângulo 1: nome da conta, truncado com "..." se for grande
        let issuer = NSTextField(labelWithString: entry.issuer)
        issuer.font = .systemFont(ofSize: 13, weight: .semibold)
        issuer.lineBreakMode = .byTruncatingTail
        issuer.maximumNumberOfLines = 1
        issuer.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let account = NSTextField(labelWithString: entry.account)
        account.font = .systemFont(ofSize: 11)
        account.textColor = .secondaryLabelColor
        account.lineBreakMode = .byTruncatingTail
        account.maximumNumberOfLines = 1
        account.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

        let info = NSStackView(views: [issuer, account])
        info.orientation = .vertical
        info.alignment = .leading
        info.spacing = 2
        info.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        info.setContentHuggingPriority(.defaultLow, for: .horizontal)
        issuer.widthAnchor.constraint(lessThanOrEqualTo: info.widthAnchor).isActive = true
        account.widthAnchor.constraint(lessThanOrEqualTo: info.widthAnchor).isActive = true

        // Retângulo 2: código fixo à direita
        codeButton.isBordered = false
        codeButton.alignment = .right
        codeButton.toolTip = "Clique para copiar"
        codeButton.target = self
        codeButton.action = #selector(copyCode)
        codeButton.setContentHuggingPriority(.required, for: .horizontal)
        codeButton.setContentCompressionResistancePriority(.required, for: .horizontal)
        codeButton.widthAnchor.constraint(equalToConstant: 120).isActive = true

        addArrangedSubview(info)
        addArrangedSubview(codeButton)
        refresh()
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) não implementado") }

    // 6 dígitos -> "123 456", 8 dígitos -> "1234 5678"
    static func format(_ code: String) -> String {
        guard code.allSatisfy({ $0.isNumber }) else { return code }
        switch code.count {
        case 6: return "\(code.prefix(3)) \(code.suffix(3))"
        case 8: return "\(code.prefix(4)) \(code.suffix(4))"
        default: return code
        }
    }

    var copiedUntil = Date.distantPast

    func refresh() {
        let style = NSMutableParagraphStyle()
        style.alignment = .right

        if Date() < copiedUntil {
            codeButton.attributedTitle = NSAttributedString(
                string: "Copiado!",
                attributes: [
                    .font: NSFont.systemFont(ofSize: 18, weight: .medium),
                    .foregroundColor: NSColor.systemGreen,
                    .paragraphStyle: style
                ]
            )
            return
        }

        let raw = OTP.generate(entry) ?? "INVÁLIDO"
        let expiring = (OTP.secondsRemaining(entry) ?? Int.max) <= 5

        codeButton.attributedTitle = NSAttributedString(
            string: CodeRow.format(raw),
            attributes: [
                .font: NSFont.monospacedDigitSystemFont(ofSize: 22, weight: .medium),
                .foregroundColor: expiring ? NSColor.systemRed : NSColor.labelColor,
                .paragraphStyle: style
            ]
        )
    }

    @objc func copyCode() {
        guard let code = OTP.generate(entry) else { return }

        // Usa NSPasteboardItem com marcadores padrão para impedir que gerenciadores
        // de histórico (Raycast, Alfred, Maccy, etc.) registrem o código 2FA
        let item = NSPasteboardItem()
        item.setString(code, forType: .string)
        item.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
        item.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))

        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.writeObjects([item])

        // Limpa automaticamente a área de transferência após 30 segundos
        // se o usuário não tiver copiado outra coisa nesse intervalo
        let changeCount = pasteboard.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            if NSPasteboard.general.changeCount == changeCount {
                NSPasteboard.general.clearContents()
            }
        }

        copiedUntil = Date().addingTimeInterval(1.2)
        refresh()
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.25) { [weak self] in
            self?.refresh()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    let popover = NSPopover()
    var entries = Store.load()
    var rows = [CodeRow]()
    var timer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)

        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "lock.fill", accessibilityDescription: "MacAuthenticator")
            button.target = self
            button.action = #selector(handleStatusBarClick)
            // Habilita o disparo da action tanto no clique esquerdo quanto no direito
            button.sendAction(on: [.leftMouseUp, .rightMouseUp])
        }

        popover.behavior = .transient
        rebuildContent()

        timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in
            guard let self = self, self.popover.isShown else { return }
            self.rows.forEach { $0.refresh() }
        }
        RunLoop.main.add(timer!, forMode: .common)
    }

    func rebuildContent() {
        rows = entries.map { CodeRow(entry: $0) }

        var views: [NSView] = rows
        if rows.isEmpty {
            let empty = NSTextField(labelWithString: "Nenhuma conta cadastrada")
            empty.textColor = .secondaryLabelColor
            views.append(empty)
        }

        let importButton = NSButton(title: "Importar QR code…", target: self, action: #selector(importQR))
        importButton.bezelStyle = .rounded
        views.append(importButton)

        let stack = NSStackView(views: views)
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        stack.layoutSubtreeIfNeeded()

        let controller = NSViewController()
        controller.view = stack
        popover.contentViewController = controller
        popover.contentSize = stack.fittingSize
    }

    func showPopover() {
        guard let button = statusItem.button else { return }
        rows.forEach { $0.refresh() }
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        // Impede que ferramentas de gravação ou compartilhamento de tela capturem os códigos
        popover.contentViewController?.view.window?.sharingType = .none
        NSApp.activate(ignoringOtherApps: true)
    }

    func togglePopover() {
        if popover.isShown {
            popover.performClose(nil)
        } else {
            showPopover()
        }
    }

    @objc func handleStatusBarClick() {
        guard let event = NSApp.currentEvent else {
            togglePopover()
            return
        }

        // Clique direito ou Ctrl + clique abre o menu contextual
        if event.type == .rightMouseUp || event.modifierFlags.contains(.control) {
            popover.performClose(nil)
            showContextMenu()
        } else {
            togglePopover()
        }
    }

    private func showContextMenu() {
        let menu = NSMenu()

        let importItem = NSMenuItem(title: "Importar QR code…", action: #selector(importQR), keyEquivalent: "")
        importItem.target = self
        menu.addItem(importItem)

        menu.addItem(.separator())

        let quitItem = NSMenuItem(title: "Sair do MacAuthenticator", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        // Atribui o menu temporariamente para ele abrir alinhado ao ícone da barra
        // e remove em seguida para que o clique esquerdo volte a abrir o popover
        statusItem.menu = menu
        statusItem.button?.performClick(nil)
        statusItem.menu = nil
    }

    @objc func quitApp() {
        NSApp.terminate(nil)
    }

    @objc func importQR() {
        popover.performClose(nil)
        NSApp.activate(ignoringOtherApps: true)

        let panel = NSOpenPanel()
        panel.title = "Selecione a imagem do QR code"
        panel.allowedContentTypes = [.image]
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false

        guard panel.runModal() == .OK, let url = panel.url else { return }

        let codes = QRImport.readQRCodes(from: url)
        let parsed = codes.flatMap { QRImport.parseAll(uri: $0) }
        let newEntries = parsed.filter { candidate in
            !entries.contains { $0.secret == candidate.secret }
        }

        guard !newEntries.isEmpty else {
            let alert = NSAlert()
            if codes.isEmpty {
                alert.messageText = "Nenhum QR code foi detectado na imagem."
            } else if parsed.isEmpty {
                alert.messageText = "O QR code não contém contas 2FA suportadas."
            } else {
                alert.messageText = "Essas contas já estão cadastradas."
            }
            alert.runModal()
            return
        }

        let updatedEntries = entries + newEntries
        guard Store.save(updatedEntries) else {
            let alert = NSAlert()
            alert.messageText = "Não foi possível salvar as contas no Keychain do macOS."
            alert.runModal()
            return
        }

        entries = updatedEntries
        rebuildContent()
        showPopover()
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()