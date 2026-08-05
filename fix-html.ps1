
# Read the file
$file = "index.html"
$content = Get-Content $file -Raw

# Strip base64 blobs appended after closing > tags (PNG base64 starts with AAD or iVBOR)
$content = $content -replace '>(?:AAD|iVBOR)[A-Za-z0-9+/=\r\n]+', '>'

# Fix apple-touch-icon that still uses a data: URI
$content = $content -replace '(<link\s+rel="apple-touch-icon"[^>]*href=")data:[^"]*"', '$1/icons/icon-192.png"'

# Save
Set-Content $file $content -NoNewline
Write-Host "index.html fixed"

# Rename icon files
$iconsDir = "icons"
$renames = @(
    @("icon-72 (1).png",  "icon-72.png"),
    @("icon-96 (1).png",  "icon-96.png"),
    @("icon-128 (1).png", "icon-128.png"),
    @("icon-144 (1).png", "icon-144.png"),
    @("icon-152 (1).png", "icon-152.png"),
    @("icon-192 (1).png", "icon-192.png"),
    @("icon-192 (2).png", "icon-192.png"),
    @("icon-384 (1).png", "icon-384.png"),
    @("icon-512 (1).png", "icon-512.png")
)

foreach ($pair in $renames) {
    $src = Join-Path $iconsDir $pair[0]
    $dst = Join-Path $iconsDir $pair[1]
    if (Test-Path $src) {
        if (Test-Path $dst) {
            Remove-Item $src
            Write-Host "Removed duplicate: $($pair[0])"
        } else {
            Rename-Item $src $pair[1]
            Write-Host "Renamed: $($pair[0]) -> $($pair[1])"
        }
    } else {
        Write-Host "Not found (skipped): $($pair[0])"
    }
}

Write-Host "`nIcons directory:"
Get-ChildItem $iconsDir | Select-Object Name
