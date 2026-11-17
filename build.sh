#!/bin/bash
set -e
cd "$(dirname "$0")"

APP="MacAuthenticator.app"

rm -rf "$APP" MacAuthenticator.zip build
mkdir -p build "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "Compilando para Apple Silicon (arm64)..."
swiftc MacAuthenticator.swift -O -target arm64-apple-macos11.0 -o build/MacAuthenticator-arm64

echo "Compilando para Intel (x86_64)..."
swiftc MacAuthenticator.swift -O -target x86_64-apple-macos11.0 -o build/MacAuthenticator-x86_64

echo "Gerando binário universal..."
lipo -create build/MacAuthenticator-arm64 build/MacAuthenticator-x86_64 -output "$APP/Contents/MacOS/MacAuthenticator"

cat > "$APP/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>MacAuthenticator</string>
    <key>CFBundleDisplayName</key>
    <string>MacAuthenticator</string>
    <key>CFBundleIdentifier</key>
    <string>com.MacAuthenticator.app</string>
    <key>CFBundleExecutable</key>
    <string>MacAuthenticator</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

echo "Assinando (ad-hoc)..."
codesign --force --deep --sign - "$APP"

echo "Gerando MacAuthenticator.zip..."
ditto -c -k --keepParent "$APP" MacAuthenticator.zip

rm -rf build
echo "Pronto: $APP e MacAuthenticator.zip"
