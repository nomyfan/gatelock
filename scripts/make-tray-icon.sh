#!/bin/zsh
# Renders design/tray.svg into cmd/gatelock/icons/tray.png, the menu bar icon, which the app embeds.
# Needs ImageMagick with librsvg.
#
# macOS shows menu bar icons 18 points tall, so the PNG is 36 pixels tall, for Retina; the artwork
# leaves its own margin around the hedgehog.
set -euo pipefail
cd "${0:A:h}/.."

magick -background none -density 300 design/tray.svg -resize x36 PNG32:cmd/gatelock/icons/tray.png
echo cmd/gatelock/icons/tray.png
