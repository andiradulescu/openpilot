import threading

from openpilot.common.hardware.tici import modem


def test_process_esim_notifications_retries(monkeypatch):
  exit_event = threading.Event()

  class FakeLPA:
    calls = 0

    def process_notifications(self):
      self.calls += 1
      if self.calls == 1:
        raise RuntimeError
      exit_event.set()

  lpa = FakeLPA()
  lpa_kwargs = {}

  def fake_lpa(**kwargs):
    lpa_kwargs.update(kwargs)
    return lpa

  monkeypatch.setattr(modem, "TiciLPA", fake_lpa)
  monkeypatch.setattr(modem, "ESIM_NOTIFICATION_RETRY_WAIT", 0)

  modem._process_esim_notifications(exit_event)

  assert lpa_kwargs == {"allow_modem_reset": False}
  assert lpa.calls == 2
