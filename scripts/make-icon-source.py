"""
Build the 1024x1024 transparent Tauri icon source from lockLogo.png.

The source logo is a non-square RGBA PNG, so it is centred on a transparent
square canvas at a fixed inset. The original lockLogo.png is never modified:
it is only opened read-only here.

Usage:
    python scripts/make-icon-source.py
"""

from __future__ import annotations

import os
from pathlib import Path

from PIL import Image

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = REPO_ROOT / "lockLogo.png"
OUTPUT = REPO_ROOT / "src-tauri" / "icons" / "icon-source.png"

CANVAS = 1024
INSET = 0.86  # leaves a transparent margin around the mark


def main() -> None:
    if not SOURCE.is_file():
        raise SystemExit(f"Source logo not found: {SOURCE}")

    with Image.open(SOURCE) as raw:
        logo = raw.convert("RGBA")

        # Trim fully transparent padding so the mark fills the canvas evenly.
        bbox = logo.getbbox()
        if bbox is not None:
            logo = logo.crop(bbox)

        max_side = int(CANVAS * INSET)
        scale = min(max_side / logo.width, max_side / logo.height)
        new_size = (
            max(1, round(logo.width * scale)),
            max(1, round(logo.height * scale)),
        )
        logo = logo.resize(new_size, Image.LANCZOS)

        canvas = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
        offset = ((CANVAS - new_size[0]) // 2, (CANVAS - new_size[1]) // 2)
        canvas.alpha_composite(logo, offset)

        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        canvas.save(OUTPUT, "PNG", optimize=True)

    size = os.path.getsize(OUTPUT)
    print(f"Wrote {OUTPUT} ({CANVAS}x{CANVAS}, {size} bytes)")
    print(f"Logo scaled to {new_size[0]}x{new_size[1]} at offset {offset}")


if __name__ == "__main__":
    main()
