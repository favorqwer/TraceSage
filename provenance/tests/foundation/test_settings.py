"""参数文件读取的单测（不需要数据库、不需要模型）。

钉住三件事：参数文件的取值生效；缺项 / 类型不对 / 超范围都回落到内置默认值并留一条说明；
文件缺失时全部用默认值。
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from config_support import temp_config  # noqa: E402
import settings as settings  # noqa: E402


class ConfigFileTest(unittest.TestCase):
    def test_values_come_from_file(self) -> None:
        with temp_config({"bundle": {"batch": 5}, "llm": {"timeout_seconds": 9},
                          "logging": {"text_limit": 33}}):
            self.assertEqual(settings.bundle_batch(), 5)
            self.assertEqual(settings.llm_timeout_seconds(), 9)
            self.assertEqual(settings.log_text_limit(), 33)
            self.assertEqual(settings.config_warnings(), [])

    def test_missing_key_falls_back_to_default(self) -> None:
        with temp_config({"bundle": {"batch": 5}}):
            self.assertEqual(settings.bundle_batch(), 5)
            self.assertEqual(settings.max_concurrency(), 12, "没写的项用内置默认值")

    def test_missing_file_uses_all_defaults(self) -> None:
        with temp_config({}):
            path = settings.use_config(pathlib.Path(tempfile.gettempdir()) / "not-there.toml")
            try:
                self.assertEqual(settings.bundle_batch(), 40)
                self.assertEqual(settings.bundle_samples(), 2)
                self.assertTrue(settings.risk_schedule_enabled())
                self.assertFalse(settings.config_warnings(), "文件缺失不算问题，静默用默认值")
            finally:
                settings.use_config(None)
                self.assertFalse(path.exists())

    def test_bad_type_and_range_fall_back_with_warning(self) -> None:
        with temp_config({"bundle": {"batch": "很多", "cap_calls": -1},
                          "render": {"reason_max_chars": "40"}}):
            self.assertEqual(settings.bundle_batch(), 40)
            self.assertEqual(settings.bundle_cap_calls(), 60)
            self.assertEqual(settings.reason_max_chars(), 40)
            warnings = settings.config_warnings()
            self.assertEqual(len(warnings), 3, warnings)
            self.assertTrue(any("bundle.batch" in w for w in warnings))
            self.assertTrue(any("bundle.cap_calls" in w for w in warnings))
            self.assertTrue(any("render.reason_max_chars" in w for w in warnings))

    def test_boolean_switch_and_enum(self) -> None:
        with temp_config({"judge": {"thinking": True},
                          "bundle": {"vacuous_guard": False, "none_guard": "别的写法"}}):
            self.assertTrue(settings.thinking_enabled())
            self.assertFalse(settings.vacuous_guard_enabled())
            self.assertEqual(settings.none_guard(), "hot", "档位取值不认识时回到受支持的默认档")

    def test_default_file_is_the_repo_one(self) -> None:
        settings.use_config(None)
        self.assertEqual(settings.config_path(), settings.CONFIG_FILE)
        self.assertTrue(settings.config_path().is_file(), "默认参数文件必须存在")
        self.assertEqual(settings.bundle_batch(), 40)
        self.assertEqual(settings.warrant_rules(), ["deriv", "proc"])
        self.assertEqual(settings.config_warnings(), [])


if __name__ == "__main__":
    unittest.main()
