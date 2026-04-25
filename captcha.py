import random
import string
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter
from PyQt6.QtGui import QImage, QPixmap


def _load_captcha_font(size=45):
    font_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    ]

    for font_path in font_candidates:
        if Path(font_path).exists():
            return ImageFont.truetype(font_path, size=size)

    try:
        return ImageFont.load_default(size=size)
    except (AttributeError, TypeError):
        return ImageFont.load_default()


def generate_captcha(width=200, height=80, length=5):
    """
    Generates a captcha image with random text and noise.

    Returns:
        tuple: A QPixmap of the captcha image and the string of the captcha text.
    """
    # Generate random text
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

    # Create a blank image
    image = Image.new('RGB', (width, height), color = (255, 255, 255))
    draw = ImageDraw.Draw(image)

    font = _load_captcha_font(size=45)

    # Draw the text on the image
    text_width, text_height = draw.textbbox((0, 0), captcha_text, font=font)[2:]
    x = (width - text_width) / 2
    y = (height - text_height) / 2
    draw.text((x, y), captcha_text, font=font, fill=(0, 0, 0))

    # Add noise (lines and points)
    for _ in range(random.randint(3, 5)):
        start = (random.randint(0, width), random.randint(0, height))
        end = (random.randint(0, width), random.randint(0, height))
        draw.line([start, end], fill=(0, 0, 0), width=2)

    for _ in range(random.randint(100, 200)):
        draw.point((random.randint(0, width), random.randint(0, height)), fill=(0, 0, 0))

    # Apply a blur filter
    image = image.filter(ImageFilter.SMOOTH)

    # Convert PIL Image to QPixmap
    qimage = QImage(image.tobytes("raw", "RGB"), image.width, image.height, QImage.Format.Format_RGB888)
    pixmap = QPixmap.fromImage(qimage)

    return pixmap, captcha_text
