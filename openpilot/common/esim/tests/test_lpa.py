import base64

import pytest

from openpilot.common.esim import lpa


@pytest.mark.parametrize("tag", (lpa.TAG_PROFILE_INSTALL_RESULT, 0x30))
def test_process_notifications_sends_complete_tlv(monkeypatch, tag):
  client = lpa.AtClient("", 0, 0)
  pending_notification = lpa.encode_tlv(tag, b"\x01\x02")
  retrieve_response = lpa.encode_tlv(
    lpa.TAG_RETRIEVE_NOTIFICATION,
    lpa.encode_tlv(lpa.TAG_OK, pending_notification),
  )
  notification_sent_response = lpa.encode_tlv(
    lpa.TAG_NOTIFICATION_SENT,
    lpa.encode_tlv(lpa.TAG_STATUS, b"\x00"),
  )
  responses = iter((retrieve_response, notification_sent_response))
  requests = []

  monkeypatch.setattr(lpa, "list_notifications", lambda _: [{
    "seqNumber": 1,
    "notificationAddress": "smdp.example.com",
  }])
  monkeypatch.setattr(lpa, "es10x_command", lambda *_: next(responses))
  monkeypatch.setattr(lpa, "es9p_request", lambda *args, **kwargs: requests.append((args, kwargs)))

  lpa.process_notifications(client)

  assert len(requests) == 1
  assert base64.b64decode(requests[0][0][2]["pendingNotification"]) == pending_notification


def test_process_notifications_keeps_notification_after_es9p_failure(monkeypatch):
  client = lpa.AtClient("", 0, 0)
  pending_notification = lpa.encode_tlv(lpa.TAG_PROFILE_INSTALL_RESULT, b"\x01\x02")
  retrieve_response = lpa.encode_tlv(
    lpa.TAG_RETRIEVE_NOTIFICATION,
    lpa.encode_tlv(lpa.TAG_OK, pending_notification),
  )
  es10x_requests = []

  monkeypatch.setattr(lpa, "list_notifications", lambda _: [{
    "seqNumber": 1,
    "notificationAddress": "smdp.example.com",
  }])
  monkeypatch.setattr(lpa, "es10x_command", lambda _, request: es10x_requests.append(request) or retrieve_response)

  def fail_es9p_request(*args, **kwargs):
    raise RuntimeError("temporary failure")

  monkeypatch.setattr(lpa, "es9p_request", fail_es9p_request)

  lpa.process_notifications(client)

  assert len(es10x_requests) == 1
