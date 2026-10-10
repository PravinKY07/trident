"""
Generate TRIDENT trident icons in four severity colors.

Draws the trident as geometric polygons on a transparent canvas,
then writes a multi-resolution .ico and a 256px PNG preview for each color.

Run once from repo root:
    .venv\\Scripts\\python.exe scripts\\make_icons.py

Writes to assets/trident-{safe,monitor,danger,trust}.{ico,png}
Pillow is a dev-only dependency; runtime never imports this.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "assets"

# Windows-native palette.
#   safe    = Windows accent blue    (engine online / startup)
#   monitor = neutral grey           (Tier 3 escalation, held for review)
#   danger  = Windows error red      (Tier 1 kill, primary threat)
#   trust   = Windows success green  (user trusted a path)
COLORS: dict[str, tuple[int, int, int, int]] = {
    "safe":    (10, 132, 255, 255),
    "monitor": (138, 138, 138, 255),
    "danger":  (209, 52, 56, 255),
    "trust":   (52, 199, 89, 255),
}

# Geometry on a 1024x1024 logical grid.
# Three prongs (tall center, shorter mirrored outers), one crossbar, one shaft.
GEOMETRY = {
    "center":   [(472, 220), (512, 100), (552, 220), (552, 460), (472, 460)],
    "left":     [(200, 300), (240, 200), (280, 300), (280, 460), (200, 460)],
    "right":    [(744, 300), (784, 200), (824, 300), (824, 460), (744, 460)],
    "crossbar": (200, 460, 824, 560),
    "shaft":    (472, 560, 552, 940),
}

CANVAS = 2048
GRID = 1024
ICO_SIZES = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]


def _s(v: int) -> int:
    """Scale a 1024-grid coordinate to the render canvas."""
    return int(v * (CANVAS / GRID))


def draw_trident(fill: tuple[int, int, int, int]) -> Image.Image:
    """Draw the geometric trident on a transparent canvas."""
    img = Image.new("RGBA", (CANVAS, CANVAS), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    for key in ("center", "left", "right"):
        pts = [(_s(x), _s(y)) for x, y in GEOMETRY[key]]
        d.polygon(pts, fill=fill)

    x0, y0, x1, y1 = GEOMETRY["crossbar"]
    d.rectangle((_s(x0), _s(y0), _s(x1), _s(y1)), fill=fill)

    x0, y0, x1, y1 = GEOMETRY["shaft"]
    d.rectangle((_s(x0), _s(y0), _s(x1), _s(y1)), fill=fill)

    return img


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    for name, rgba in COLORS.items():
        img = draw_trident(rgba)

        ico_path = OUT_DIR / f"trident-{name}.ico"
        img.save(ico_path, format="ICO", sizes=ICO_SIZES)
        print(f"wrote {ico_path}")

        png_path = OUT_DIR / f"trident-{name}-preview.png"
        img.resize((256, 256), Image.LANCZOS).save(png_path, format="PNG")
        print(f"wrote {png_path}")


if __name__ == "__main__":
    main()
