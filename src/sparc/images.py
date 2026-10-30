"""Lazy, bounded image decoding; transferred source files are never re-encoded."""

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import warnings

from .models import SparcError
from .protocol.files import MAX_FILE_BYTES

MAX_IMAGE_PIXELS = 20_000_000
_FORMATS = ('PNG', 'JPEG', 'GIF', 'WEBP')
_MIME = dict(zip(_FORMATS, ('image/png', 'image/jpeg', 'image/gif', 'image/webp')))


@dataclass(frozen=True)
class ImageInfo:
    format: str
    width: int
    height: int
    media_type: str


def _pillow():
    try:
        from PIL import Image
    except ImportError as exc:
        raise SparcError('image_dependency_missing', 'Install Pillow with pip install -r requirements.txt to use images') from exc
    return Image


@contextmanager
def _decoded(source):
    Image = _pillow()
    owned = isinstance(source, (str, Path))
    stream = None
    position = None
    try:
        stream = open(source, 'rb') if owned else source
        position = stream.tell()
        stream.seek(0, 2)
        size = stream.tell()
        if not 0 < size <= MAX_FILE_BYTES:
            raise SparcError('invalid_image', 'Image file must contain 1 byte through 100 MiB')
        stream.seek(0)
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(stream, formats=_FORMATS) as image:
                if image.format not in _FORMATS:
                    raise SparcError('invalid_image', 'Choose a PNG, JPEG, GIF, or WebP image')
                if image.width * image.height > MAX_IMAGE_PIXELS:
                    raise SparcError('invalid_image', 'Image exceeds the 20 million pixel preview limit')
                # Frame zero only. Loading catches truncated pixel data before transfer/publication.
                image.seek(0)
                image.load()
                yield image
    except SparcError:
        raise
    except Exception as exc:
        raise SparcError('invalid_image', 'Cannot decode image; choose a valid PNG, JPEG, GIF, or WebP file') from exc
    finally:
        if stream is not None:
            if owned:
                stream.close()
            elif position is not None and not stream.closed:
                stream.seek(position)


def inspect_image(source) -> ImageInfo:
    """Validate a supported first frame and restore a caller-owned file cursor."""
    with _decoded(source) as image:
        return ImageInfo(image.format, image.width, image.height, _MIME[image.format])


def make_thumbnail(path):
    """Return an independent RGB thumbnail, without creating any Tk objects."""
    with _decoded(path) as image:
        thumbnail = image.convert('RGB')
        thumbnail.thumbnail((384, 256))
        return thumbnail
