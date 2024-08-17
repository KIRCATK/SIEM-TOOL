import unittest
from unittest.mock import MagicMock

class TestSIEMTool(unittest.TestCase):
    def setUp(self):
        self.siem = SIEMTool(root=tk.Tk())

    def test_process_event(self):
        event = MagicMock()
        event.TimeGenerated.Format.return_value = '2024-08-05 10:00:00'
        event.EventID = 4625
        event.EventCategory = 1
        event.EventType = win32evtlog.EVENTLOG_ERROR_TYPE
        event.SourceName = 'Security'
        event.StringInserts = ['Failed login attempt']

        self.siem.process_event(event)

        log_entry = (
            "Time Generated: 2024-08-05 10:00:00\n"
            "Event ID: 4625\n"
            "Category: 1\n"
            "Type: 1\n"
            "Source: Security\n"
            "Message: Failed login attempt\n"
            "--------------------------------------------------------------------------------\n"
        )

        self.assertIn(log_entry, self.siem.log_text.get(1.0, tk.END))
        self.assertIn(log_entry, self.siem.alert_text.get(1.0, tk.END))

if __name__ == "__main__":
    unittest.main()
