import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from provenance.adapters.cdm import decode as D  # noqa: E402


SAMPLE = (
    b'{"datum":{"com.bbn.tc.schema.avro.cdm18.Event":{"uuid":"E87FB82D-6375-C469-6974-AACF2B7F1700",'
    b'"sequence":{"long":36},"type":"EVENT_RECVMSG","threadId":{"int":412},'
    b'"hostId":"E621F964-5A66-0F89-30E0-67ADB2A5EC28",'
    b'"subject":{"com.bbn.tc.schema.avro.cdm18.UUID":"753366C8-7B00-E70F-1E95-2102227BD6E1"},'
    b'"predicateObject":{"com.bbn.tc.schema.avro.cdm18.UUID":"39E846F3-D581-6BBB-4CE1-E7E43D356616"},'
    b'"predicateObjectPath":null,"predicateObject2":null,"predicateObject2Path":null,'
    b'"timestampNanos":1523627788470000000,"name":null,"parameters":null,"location":null,'
    b'"size":{"long":8},"programPoint":null,"properties":{"map":{"rc":"0"}}}},'
    b'"CDMVersion":"18","source":"SOURCE_LINUX_SYSCALL_TRACE"}\n'
)


class DecodeTest(unittest.TestCase):
    def test_datum_of_returns_short_type_and_body(self):
        kind, body = D.datum_of(SAMPLE)
        self.assertEqual(kind, "Event")
        self.assertEqual(body["type"], "EVENT_RECVMSG")

    def test_datum_of_rejects_broken_line(self):
        self.assertIsNone(D.datum_of(b"{not json"))
        self.assertIsNone(D.datum_of(b'{"datum":{}}'))

    def test_union_unwrap(self):
        self.assertEqual(D.number({"int": 412}), 412)
        self.assertEqual(D.number({"long": 36}), 36)
        self.assertEqual(D.text({"string": "/bin/sh"}), "/bin/sh")
        self.assertIsNone(D.number(None))
        self.assertEqual(D.number({"map": {}}), None)

    def test_number_accepts_string_valued_properties(self):
        # properties.map 的值是字符串（实测 {"rc":"0"}），必须能解成整数
        self.assertEqual(D.number("0"), 0)
        self.assertEqual(D.number("-115"), -115)
        self.assertIsNone(D.number(""))

    def test_mapping_extracts_map_payload(self):
        self.assertEqual(D.mapping({"map": {"rc": "0"}}), {"rc": "0"})
        self.assertEqual(D.mapping(None), {})

    def test_uuid_and_null_uuid(self):
        self.assertEqual(
            D.uuid({"com.bbn.tc.schema.avro.cdm18.UUID": "ABC"}),
            "ABC",
        )
        self.assertEqual(D.uuid(None), "")
        self.assertEqual(
            D.uuid({"com.bbn.tc.schema.avro.cdm18.UUID": D.NULL_UUID}),
            "",
        )

    def test_time_helpers_roundtrip(self):
        ns = D.ns_from_iso("2018-04-10T17:30:00Z")
        self.assertEqual(ns, 1523381400 * 1_000_000_000)
        self.assertEqual(D.iso_from_ns(ns), "2018-04-10 17:30:00Z")
        self.assertIsNone(D.ns_from_iso(""))
        self.assertIsNone(D.ns_from_iso("not-a-time"))

    def test_size_field_present(self):
        _, body = D.datum_of(SAMPLE)
        self.assertEqual(D.number(body["size"]), 8)

    def test_json_literal_still_valid(self):
        # 样本必须本身是合法 JSON，避免测试用假数据
        parsed = json.loads(SAMPLE)
        self.assertEqual(parsed["CDMVersion"], "18")


if __name__ == "__main__":
    unittest.main()
