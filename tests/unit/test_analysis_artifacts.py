"""Saved public lab results stay associated and loaded signatures are rechecked."""
import json
from importlib import import_module

import pytest
from sparc.analysis.message import run_message_trial
from sparc.analysis.specimen import make_timed_specimen

def module():
    try: return import_module('sparc.analysis.artifacts')
    except ModuleNotFoundError: pytest.fail('public analysis artifacts are missing')

def signature():
    from sparc.analysis import specimen
    cls = getattr(specimen, 'SignatureResult', None)
    assert cls is not None, 'typed specimen result is missing'
    public, signed, value, sign_ns = make_timed_specimen()
    timed = getattr(specimen, 'verify_timed_specimen', None)
    assert callable(timed), 'verification timing is missing'
    valid, verify_ns = timed(public, signed, value)
    return cls(public, signed, value, valid, sign_ns, verify_ns)

def test_signature_public_artifact_roundtrip_retains_fields_and_reverifies(tmp_path):
    api = module(); specimen = signature(); path = tmp_path/'signature.json'
    api.save_artifact(specimen, path)
    saved = json.loads(path.read_text())
    assert saved['kind'] == 'signature' and saved['version'] == 1
    assert saved['data']['signature'] == specimen.signature.hex()
    loaded = api.load_signature_artifact(path)
    assert loaded.public_key == specimen.public_key and loaded.signature == specimen.signature
    assert loaded.signed_bytes == specimen.signed_bytes and loaded.valid
    assert loaded.sign_ns == specimen.sign_ns and loaded.verify_ns >= 0

def test_specimen_verification_times_the_primitive_after_public_key_loading(monkeypatch):
    from sparc.analysis import specimen
    active=False
    class Public:
        @staticmethod
        def from_public_bytes(value):
            assert not active,'public key loading must be outside the primitive timer'
            return Public()
        def verify(self,signature,data):
            assert active
    def clock():
        nonlocal active
        active=not active
        return 100 if active else 150
    monkeypatch.setattr(specimen,'Ed25519PublicKey',Public)
    monkeypatch.setattr(specimen.time,'perf_counter_ns',clock)
    assert specimen.verify_timed_specimen(bytes(32),b'message',bytes(64))==(True,50)

def test_tampering_with_signed_bytes_is_not_hidden_by_saved_validity(tmp_path):
    api = module(); path = tmp_path/'specimen.json'
    api.save_artifact(signature(), path)
    saved = json.loads(path.read_text())
    saved['data']['signed_bytes'] = '00'
    saved['data']['valid'] = True
    path.write_text(json.dumps(saved))
    assert api.load_signature_artifact(path).valid is False

def test_message_artifact_contains_current_input_and_no_private_keys(tmp_path):
    api = module(); path = tmp_path/'message.json'
    api.save_artifact(run_message_trial('custom message — 中文',key=bytes(32)),path)
    saved = json.loads(path.read_text())
    assert saved['kind'] == 'message'
    assert saved['timing_unit']=='ns' and saved['binary_encoding']=='hex' and saved['text_encoding']=='UTF-8'
    assert saved['data']['plaintext'] == saved['data']['recovered_text'] == 'custom message — 中文'
    assert not {'key','aes_key','private_key'} & saved['data'].keys()

def test_maximum_message_can_be_exported_even_when_json_escaping_expands_it(tmp_path):
    path=tmp_path/'escaped-message.json'
    result=run_message_trial('\x00'*16384)
    module().save_artifact(result,path)
    assert json.loads(path.read_text())['data']['plaintext']==result.plaintext

def test_single_custom_trial_export_excludes_original_and_modified_keys(tmp_path):
    from sparc.analysis.sensitivity import custom_sensitivity_trial
    path = tmp_path/'trial.json'; api = module()
    api.save_artifact(custom_sensitivity_trial(bytes(32),bytes(16),'key',3),path)
    data = json.loads(path.read_text())
    assert data['kind'] == 'sensitivity_trial'
    assert data['data']['input_source'] == 'custom'
    assert not {'key','modified_key'} & data['data'].keys()

@pytest.mark.parametrize('content', ['not JSON', '{}', '{"version":99}', '[]', 'x' * 300000])
def test_invalid_and_oversized_artifacts_fail_actionably(tmp_path, content):
    api = module(); path=tmp_path/'bad.json'; path.write_text(content)
    with pytest.raises(ValueError): api.load_signature_artifact(path)

def test_non_signature_artifact_cannot_replace_a_loaded_specimen(tmp_path):
    api = module(); path=tmp_path/'message.json'
    api.save_artifact(run_message_trial('message'),path)
    with pytest.raises(ValueError): api.load_signature_artifact(path)

def test_unsupported_result_preserves_previous_export(tmp_path):
    api=module(); path=tmp_path/'keep.json'; path.write_text('original')
    with pytest.raises(ValueError): api.save_artifact(object(),path)
    assert path.read_text() == 'original'
