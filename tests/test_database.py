from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from netpulse.infrastructure.database import DB


class DatabaseTests(unittest.TestCase):
    def test_session_stats_and_batch_ip_upsert(self):
        with TemporaryDirectory() as directory:
            db = DB(Path(directory) / "nested" / "test.db")
            session_id = db.new_session("Ethernet")
            db.save_stat(session_id, {"bytes_in": 10, "TCP": 1})
            db.upsert_ips(session_id, [("1.1.1.1", 100, 1), ("1.1.1.1", 50, 2)])
            db.close_session(session_id, 3, 10, 0)

            self.assertEqual(db.get_stats(session_id)[0]["bytes_in"], 10)
            top_ip = db.get_top_ips(session_id)[0]
            self.assertEqual(top_ip["total_bytes"], 150)
            self.assertEqual(top_ip["total_pkts"], 3)
            self.assertEqual(db.list_sessions()[0]["total_pkts"], 3)


if __name__ == "__main__":
    unittest.main()
