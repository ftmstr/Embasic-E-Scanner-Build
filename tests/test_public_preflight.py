"""Offline synthetic-only tests for PUBLIC source/dependency preflight."""
import hashlib
import importlib.util
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'public_preflight.py'
spec = importlib.util.spec_from_file_location('escanner_public_preflight', MODULE)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def populate(root):
    for filename in ('LICENSE', 'THIRD-PARTY-NOTICES.md', 'android/settings.gradle.kts',
                     'android/build.gradle.kts', 'android/app/build.gradle.kts', 'android/gradlew'):
        dst = root / filename
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text('synthetic test placeholder\n')
    wrapper = root / 'android/gradle/wrapper'
    wrapper.mkdir(parents=True)
    (wrapper / 'gradle-wrapper.properties').write_text(
        'distributionUrl=https\\://services.gradle.org/distributions/gradle-8.14.6-bin.zip\n'
        'distributionSha256Sum=' + mod.OFFICIAL_DIST_SHA256 + '\n')
    data = b'synthetic-wrapper-bytes-not-a-real-jar'
    (wrapper / 'gradle-wrapper.jar').write_bytes(data)
    (wrapper / 'gradle-wrapper.jar.sha256').write_text(hashlib.sha256(data).hexdigest() + '\n')
    return wrapper


class TestPreflight(unittest.TestCase):
    def test_missing_repository_gates_blocked(self):
        with TemporaryDirectory() as d:
            result = mod.audit(Path(d))
            self.assertEqual(result['machinePreflight'], 'BLOCKED')
            self.assertFalse(result['releaseApproved'])
            self.assertTrue(all(g['status'] == 'BLOCKED' for g in result['gates']))

    def test_complete_synthetic_structure_still_not_release_approved(self):
        with TemporaryDirectory() as d:
            populate(Path(d))
            result = mod.audit(Path(d))
            # Test bytes are deliberately NOT official Gradle wrapper bytes.
            # A self-consistent synthetic checksum must not count as upstream trust.
            self.assertEqual(result['machinePreflight'], 'BLOCKED')
            self.assertEqual(result['gates'][-2]['status'], 'PASS')
            self.assertEqual(result['gates'][-1]['status'], 'BLOCKED')
            self.assertEqual(result['releaseStatus'], 'NOT_VERIFIED')
            self.assertFalse(result['releaseApproved'])

    def test_wrong_wrapper_checksum_fail_closed(self):
        with TemporaryDirectory() as d:
            wrapper = populate(Path(d))
            (wrapper / 'gradle-wrapper.jar.sha256').write_text('0'*64)
            result = mod.audit(Path(d))
            self.assertEqual(result['gates'][-1]['status'], 'BLOCKED')

    def test_unsafe_distribution_rejected(self):
        with TemporaryDirectory() as d:
            wrapper = populate(Path(d))
            (wrapper / 'gradle-wrapper.properties').write_text(
                'distributionUrl=http://evil.invalid/gradle.zip\n'
                'distributionSha256Sum=' + mod.OFFICIAL_DIST_SHA256 + '\n')
            self.assertEqual(mod.audit(Path(d))['gates'][-2]['status'], 'BLOCKED')

    def test_duplicate_property_rejected(self):
        with TemporaryDirectory() as d:
            wrapper = populate(Path(d))
            with (wrapper / 'gradle-wrapper.properties').open('a') as f:
                f.write('distributionSha256Sum=' + mod.OFFICIAL_DIST_SHA256 + '\n')
            self.assertEqual(mod.audit(Path(d))['gates'][-2]['status'], 'BLOCKED')

    def test_symlink_to_external_file_rejected(self):
        with TemporaryDirectory() as d:
            root = Path(d)
            populate(root)
            (root / 'LICENSE').unlink()
            (root / 'LICENSE').symlink_to('/etc/hosts')
            self.assertEqual(mod.audit(root)['gates'][0]['status'], 'BLOCKED')

    def test_oversized_wrapper_rejected(self):
        with TemporaryDirectory() as d:
            wrapper = populate(Path(d))
            (wrapper / 'gradle-wrapper.jar').write_bytes(b'Z' * (2*1024*1024+1))
            self.assertEqual(mod.audit(Path(d))['gates'][-1]['status'], 'BLOCKED')

    def test_strict_mode_exit_code_is_blocked(self):
        with TemporaryDirectory() as d:
            self.assertEqual(mod.main(['--root', d, '--strict']), 2)


    def test_arbitrary_64_hex_distribution_checksum_not_trusted(self):
        with TemporaryDirectory() as d:
            wrapper = populate(Path(d))
            props = wrapper / 'gradle-wrapper.properties'
            props.write_text(props.read_text().replace(
                mod.OFFICIAL_DIST_SHA256, 'a' * 64))
            self.assertEqual(mod.audit(Path(d))['gates'][-2]['status'], 'BLOCKED')

    def test_forged_jar_with_matching_local_checksum_not_trusted(self):
        with TemporaryDirectory() as d:
            wrapper = populate(Path(d))
            # populate() writes arbitrary synthetic bytes and their own digest.
            # This must NOT match the separately published upstream digest.
            result = mod.audit(Path(d))
            self.assertEqual(result['gates'][-1]['status'], 'BLOCKED')
            self.assertNotEqual(
                (wrapper / 'gradle-wrapper.jar.sha256').read_text().strip(),
                mod.OFFICIAL_WRAPPER_SHA256)

    def test_official_checksum_file_without_jar_is_not_sufficient(self):
        with TemporaryDirectory() as d:
            wrapper = populate(Path(d))
            (wrapper / 'gradle-wrapper.jar').unlink()
            (wrapper / 'gradle-wrapper.jar.sha256').write_text(
                mod.OFFICIAL_WRAPPER_SHA256 + '\\n')
            self.assertEqual(mod.audit(Path(d))['gates'][-1]['status'], 'BLOCKED')


if __name__ == '__main__':
    unittest.main()
