#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$project_dir"

version="$(sed -n 's/^const appVersion = "\([^"]*\)"/\1/p' report.go | head -n 1)"
if [[ -z "$version" ]]; then
  echo "Unable to read appVersion from report.go" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64) arch="amd64" ;;
  arm64) arch="arm64" ;;
  *) echo "Unsupported macOS architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [[ -n "${EXPECTED_ARCH:-}" && "$arch" != "$EXPECTED_ARCH" ]]; then
  echo "Runner architecture mismatch: expected $EXPECTED_ARCH, got $arch" >&2
  exit 1
fi

stage_dir="$project_dir/dist/ALL1n-$version-macos-$arch"
app_dir="$stage_dir/ALL1n.app"
zip_path="$stage_dir.zip"
rm -rf "$stage_dir" "$zip_path" "$zip_path.sha256"
mkdir -p "$app_dir/Contents/MacOS" "$app_dir/Contents/Resources"

go test -tags ci ./...
go build -buildvcs=false -trimpath -ldflags="-s -w" -o "$app_dir/Contents/MacOS/ALL1n" .
chmod +x "$app_dir/Contents/MacOS/ALL1n"

cat > "$app_dir/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDevelopmentRegion</key><string>zh_CN</string>
  <key>CFBundleDisplayName</key><string>ALL1n</string>
  <key>CFBundleExecutable</key><string>ALL1n</string>
  <key>CFBundleIdentifier</key><string>com.hongzh0.all1n</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>ALL1n</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$version</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSHumanReadableCopyright</key><string>By 基调听云-hongzh0</string>
</dict>
</plist>
PLIST

# Ad-hoc signing keeps the bundle internally consistent. The public build is
# intentionally not notarized because no Apple Developer certificate is stored.
codesign --force --deep --sign - "$app_dir"

cp README.md LICENSE CHANGELOG.md SECURITY.md "$stage_dir/"
ditto -c -k --sequesterRsrc --keepParent "$stage_dir" "$zip_path"
(
  cd "$(dirname "$zip_path")"
  shasum -a 256 "$(basename "$zip_path")" > "$(basename "$zip_path").sha256"
)

echo "macOS release package: $zip_path"
cat "$zip_path.sha256"
