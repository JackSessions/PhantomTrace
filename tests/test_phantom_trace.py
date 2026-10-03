import csv
import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout

import images
import phantom_trace as pt


def checks(path):
    with open(path, "rb") as fh:
        return {f.check for f in pt.analyse(pt.Ntfs(fh))}


@unittest.skipUnless(images.have_tools(), "needs mkntfs and ntfscp (apt install ntfs-3g)")
class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.clean = os.path.join(cls.tmp, "clean.img")
        images.build_clean(cls.clean)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_clean_image_has_no_findings(self):
        self.assertEqual(checks(self.clean), set(), "false positives on a clean filesystem")

    def test_each_tamper_is_detected(self):
        for name, (fn, expected) in images.SCENARIOS.items():
            with self.subTest(name):
                path = os.path.join(self.tmp, f"{name}.img")
                shutil.copy(self.clean, path)
                fn(path)
                found = checks(path)
                self.assertIn(expected, found, f"{name}: expected {expected}, got {found}")

    def test_tamper_does_not_trigger_unrelated_high_severity(self):
        path = os.path.join(self.tmp, "only_flag.img")
        shutil.copy(self.clean, path)
        images.tamper_flag_flip(path)
        self.assertEqual({c for c in checks(path) if pt.SEVERITY[c] == "high"}, {"mft_flag_vs_bitmap"})

    def test_json_csv_and_html_outputs(self):
        path = os.path.join(self.tmp, "outputs.img")
        shutil.copy(self.clean, path)
        images.tamper_bitmap_free(path)
        out_csv, out_html = os.path.join(self.tmp, "r.csv"), os.path.join(self.tmp, "r.html")
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = pt.main([path, "--json", "--csv", out_csv, "--html", out_html])
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertTrue(any(f["check"] == "clusters_free_in_bitmap" for f in data["findings"]))
        rows = list(csv.DictReader(open(out_csv)))
        self.assertEqual(rows[0]["severity"], "high")
        page = open(out_html, encoding="utf-8").read()
        self.assertIn("clusters_free_in_bitmap", page)
        self.assertIn("file1.bin", page)

    def test_clean_text_report_says_so(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            pt.main([self.clean, "--no-color", "-q"])
        self.assertIn("No cross-layer inconsistencies found", buf.getvalue())

    def test_not_ntfs_is_an_error(self):
        path = os.path.join(self.tmp, "junk.img")
        with open(path, "wb") as f:
            f.write(os.urandom(4096))
        self.assertEqual(pt.main([path]), 2)

    def test_exit_codes(self):
        self.assertEqual(pt.main([self.clean]), 0)
        path = os.path.join(self.tmp, "exit.img")
        shutil.copy(self.clean, path)
        images.tamper_bitmap_free(path)
        self.assertEqual(pt.main([path]), 1)


class RunListTests(unittest.TestCase):
    def test_decode_dense_sparse_and_negative_offset(self):
        # run 1: 4 clusters at LCN 0x10; run 2: 8 sparse clusters; run 3: 2 clusters at LCN 0x10 + (-0x10) = 0
        data = bytes([0x11, 0x04, 0x10, 0x01, 0x08, 0x11, 0x02, 0xF0, 0x00])
        self.assertEqual(pt.decode_runs(data, 0, len(data)), [(0x10, 4), (None, 8), (0x00, 2)])

    def test_malformed_run_list_raises(self):
        with self.assertRaises(pt.NtfsError):
            pt.decode_runs(bytes([0x31, 0x01]), 0, 2)


if __name__ == "__main__":
    unittest.main()
