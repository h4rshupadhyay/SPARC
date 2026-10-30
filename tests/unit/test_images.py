"""Bounded first-frame decoding preserves the original transferable bytes."""

import io
import sys

import pytest

from sparc.models import SparcError


@pytest.mark.parametrize('fmt,mime', [('PNG','image/png'), ('JPEG','image/jpeg'), ('GIF','image/gif'), ('WEBP','image/webp')])
def test_supported_images_detect_and_thumbnail_without_reencoding_source(tmp_path,fmt,mime):
    from sparc.images import inspect_image, make_thumbnail
    from PIL import Image
    path = tmp_path/'image.bin'
    Image.new('RGB',(600,400),'navy').save(path,format=fmt)
    original=path.read_bytes()
    info=inspect_image(path)
    assert (info.format,info.width,info.height,info.media_type)==(fmt,600,400,mime)
    thumb=make_thumbnail(path)
    assert thumb.size==(384,256)
    assert path.read_bytes()==original
    with path.open('rb') as stream:
        stream.seek(7)
        assert inspect_image(stream)==info
        assert not stream.closed and stream.tell()==7


@pytest.mark.parametrize('data', [b'',b'not an image',b'\x89PNG\r\n\x1a\n'])
def test_bad_images_are_safe_domain_errors(tmp_path,data):
    from sparc.images import inspect_image
    path=tmp_path/'fake.png'; path.write_bytes(data)
    with pytest.raises(SparcError): inspect_image(path)


def test_dimensions_checked_before_pixel_loading(tmp_path,monkeypatch):
    from sparc.images import inspect_image
    from PIL import Image
    path=tmp_path/'large.png'
    Image.new('RGB',(101,101)).save(path)
    monkeypatch.setattr('sparc.images.MAX_IMAGE_PIXELS',10000)
    with pytest.raises(SparcError,match='pixel'): inspect_image(path)


def test_nonwhitelisted_decoder_is_never_selected(tmp_path):
    from sparc.images import inspect_image
    from PIL import Image
    path=tmp_path/'fake.png'; Image.new('RGB',(2,2)).save(path,format='BMP')
    with pytest.raises(SparcError): inspect_image(path)


def test_missing_pillow_is_actionable(monkeypatch):
    from sparc.images import inspect_image
    monkeypatch.setitem(sys.modules,'PIL',None)
    with pytest.raises(SparcError,match='Pillow'): inspect_image(io.BytesIO(b''))


def test_saved_copy_preserves_all_original_bytes(tmp_path):
    from sparc.images import save_image_copy
    source, saved = tmp_path / 'original.gif', tmp_path / 'copy.gif'
    source.write_bytes(b'original image bytes\x00' * 8000)
    save_image_copy(source, saved)
    assert saved.read_bytes() == source.read_bytes()
    assert not list(tmp_path.glob('.sparc-save-*'))


def test_cancelled_save_preserves_existing_destination_and_removes_staging(tmp_path):
    import threading
    from sparc.images import save_image_copy
    source, saved = tmp_path / 'original.png', tmp_path / 'copy.png'
    source.write_bytes(b'original image')
    saved.write_bytes(b'existing destination')
    cancel = threading.Event(); cancel.set()
    with pytest.raises(SparcError, match='canceled'):
        save_image_copy(source, saved, cancel=cancel)
    assert saved.read_bytes() == b'existing destination'
    assert not list(tmp_path.glob('.sparc-save-*'))
