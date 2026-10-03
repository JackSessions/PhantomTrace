import csv
import io
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
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

    def test_timestamp_heuristics_are_opt_in(self):
        path = os.path.join(self.tmp, "stomp.img")
        shutil.copy(self.clean, path)
        images.tamper_timestomp(path)
        self.assertEqual(checks(path), set(), "heuristics must not run by default")
        with open(path, "rb") as fh:
            found = {f.check for f in pt.analyse(pt.Ntfs(fh), heuristics=True)}
        self.assertEqual(found, {"timestomp_si_before_fn", "timestomp_zero_fraction"})
        with open(self.clean, "rb") as fh:
            self.assertEqual(pt.analyse(pt.Ntfs(fh), heuristics=True), [], "heuristics false positive on a clean volume")

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
        with open(out_csv) as cf:
            rows = list(csv.DictReader(cf))
        self.assertEqual(rows[0]["severity"], "high")
        with open(out_html, encoding="utf-8") as hf:
            page = hf.read()
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


@unittest.skipUnless(images.can_mount(), "needs ntfs-3g plus FUSE to mount a volume")
class ChurnedVolumeTests(unittest.TestCase):
    def test_volume_used_through_a_live_mount_has_no_findings(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "churn.img")
            try:
                images.build_churned(path)
            except images.MountUnavailable as e:
                self.skipTest(f"cannot mount an NTFS image here: {e}")
            self.assertEqual(checks(path), set(), "false positives on a realistically used volume")


@unittest.skipUnless(images.have_tools() and shutil.which("sfdisk"), "needs ntfs-3g and sfdisk")
class PartitionTests(unittest.TestCase):
    def test_finds_ntfs_in_mbr_and_gpt_disk_images(self):
        for layout in ("msdos", "gpt"):
            with self.subTest(layout), tempfile.TemporaryDirectory() as d:
                disk = os.path.join(d, "disk.img")
                images.build_disk(disk, layout)
                with open(disk, "rb") as fh:
                    self.assertEqual([o for o, _ in pt.locate_volumes(fh)], [1048576])
                self.assertEqual(pt.main([disk, "-q", "--no-color"]), 0)

    def test_tamper_inside_a_partition_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            disk = os.path.join(d, "disk.img")
            images.build_disk(disk, "gpt", tamper=images.tamper_bitmap_free)
            self.assertEqual(pt.main([disk, "-q", "--no-color"]), 1)


@unittest.skipUnless(images.have_tools(), "needs ntfs-3g image tools")
class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import phantom_trace_gui as gui
        cls.tmp = tempfile.mkdtemp()
        cls.clean = os.path.join(cls.tmp, "clean.img")
        images.build_clean(cls.clean)
        cls.bad = os.path.join(cls.tmp, "bad.img")
        shutil.copy(cls.clean, cls.bad)
        images.tamper_bitmap_free(cls.bad)
        cls.httpd, cls.token = gui.make_server(0)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def call(self, path, body=None, token=True, host=None):
        req = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(), method="POST" if body is not None else "GET")
        if token:
            req.add_header("X-PT-Token", self.token)
        if host:
            req.add_header("Host", host)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def scan(self, path):
        code, raw = self.call("/api/scan", {"path": path})
        self.assertEqual(code, 200)
        job = json.loads(raw)["job"]
        for _ in range(100):
            code, raw = self.call(f"/api/status?job={job}")
            data = json.loads(raw)
            if data["state"] != "running":
                return job, data
            time.sleep(0.05)
        self.fail("scan did not finish")

    def test_requires_token_and_local_host(self):
        self.assertEqual(self.call("/api/ls", token=False)[0], 403)
        self.assertEqual(self.call("/", host="evil.example.com")[0], 403)
        self.assertEqual(self.call(f"/?token={self.token}")[0], 200)

    def test_scan_clean_and_tampered(self):
        _, ok = self.scan(self.clean)
        self.assertEqual((ok["state"], ok["findings"]), ("done", []))
        job, bad = self.scan(self.bad)
        self.assertIn("clusters_free_in_bitmap", {f["check"] for f in bad["findings"]})
        self.assertTrue(bad["cmap"]["cells"] > 0)
        for fmt, needle in (("html", "PhantomTrace"), ("csv", "severity"), ("json", "findings")):
            code, raw = self.call(f"/api/report?job={job}&fmt={fmt}")
            self.assertEqual(code, 200)
            self.assertIn(needle, raw.decode())

    def test_errors_are_reported_not_raised(self):
        _, missing = self.scan(os.path.join(self.tmp, "nope.img"))
        self.assertEqual(missing["state"], "error")
        junk = os.path.join(self.tmp, "junk.bin")
        with open(junk, "wb") as f:
            f.write(os.urandom(8192))
        self.assertEqual(self.scan(junk)[1]["state"], "error")

    def test_directory_listing(self):
        code, raw = self.call("/api/ls?path=" + urllib.request.quote(self.tmp))
        names = {e["name"] for e in json.loads(raw)["entries"]}
        self.assertIn("clean.img", names)


class MetadataTests(unittest.TestCase):
    def test_pyproject_version_matches_the_module(self):
        text = open(os.path.join(os.path.dirname(__file__), "..", "pyproject.toml"), encoding="utf-8").read()
        self.assertIn(f'version = "{pt.__version__}"', text)

    def test_help_and_list_checks_run(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(pt.main(["--list-checks"]), 0)
        self.assertIn("clusters_free_in_bitmap", buf.getvalue())
        with self.assertRaises(SystemExit) as cm, redirect_stdout(io.StringIO()):
            pt.main(["--help"])
        self.assertEqual(cm.exception.code, 0)


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
