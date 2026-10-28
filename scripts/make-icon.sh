#!/bin/zsh
# Renders the artwork in design/ into resources/icon.png, the 1024px Dock icon. Needs ImageMagick
# with librsvg.
#
# The artwork is a hedgehog on a sage-green tile that fills the SVG. The tile follows the macOS icon
# grid: an 824px rounded square (radius 185) centered on the 1024 canvas, with a drop shadow.
#
# Usage: scripts/make-icon.sh [artwork.svg] [out.png]
set -euo pipefail
cd "${0:A:h}/.."

src=${1:-design/icon.svg}
out=${2:-resources/icon.png}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Rendered at twice the size and scaled down, so the edges are smooth. The SVG is not quite square
# (1046 by 1040), so it is stretched to the tile's square.
magick -background none -density 192 "$src" -resize '824x824!' $work/art.png

magick -size 1024x1024 xc:none -fill white -draw "roundrectangle 100,100 923,923 185,185" $work/mask.png
magick $work/art.png -background none -gravity center -extent 1024x1024 \
  $work/mask.png -compose DstIn -composite $work/tile.png

magick $work/tile.png \( +clone -background black -shadow 14x36+0+26 \) +swap \
  -background none -layers merge +repage -gravity center -crop 1024x1024+0+0 +repage -depth 8 $out
echo $out
