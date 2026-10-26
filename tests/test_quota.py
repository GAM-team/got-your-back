"""Exercise request pacing without making API calls or waiting in real time."""
import heapq
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import httplib2
from googleapiclient.http import BatchHttpRequest, HttpRequest

import gyb


class Clock:
  def __init__(self):
    self.now = 0
    self.timers = []

  def timer(self, interval, callback):
    return SimpleNamespace(start=lambda: heapq.heappush(
      self.timers, (self.now + interval, callback)))

  def event(self):
    clock = self

    class Event:
      ready = False

      def set(self):
        self.ready = True

      def wait(self):
        while not self.ready:
          clock.now, callback = heapq.heappop(clock.timers)
          callback()

    return Event()


class QuotaTests(unittest.TestCase):
  def run_downloads(self, batch_size):
    clock = Clock()
    # Use the production bucket settings, but drive its timers synchronously.
    original = gyb.buckets['gmail']
    requests = []
    with patch.object(gyb.threading, 'Timer', clock.timer), \
         patch.object(gyb.threading, 'Event', clock.event):
      bucket = gyb.QuotaBucket(original.size, original.interval,
                               original.refill_size)
      with patch.dict(gyb.buckets, gmail=bucket):
        for _ in range(600 // batch_size):
          if batch_size == 1:
            method = SimpleNamespace(
              methodId='gmail.users.messages.get',
              execute=lambda: requests.append((clock.now, 20)))
          else:
            method = BatchHttpRequest(batch_uri='https://example.test/batch')
            for _ in range(batch_size):
              method.add(HttpRequest(httplib2.Http(), lambda *args: None,
                'https://example.test/message',
                methodId='gmail.users.messages.get'))
            method.execute = lambda: requests.append((clock.now, 20 * batch_size))
          gyb.callGAPI(method, None)

    # Independent of GYB's cost table: Gmail now charges 20 units per get.
    for end, _ in requests:
      cost = sum(cost for when, cost in requests if end - 60 < when <= end)
      self.assertLessEqual(cost, 6000)
    # Leave headroom for other calls: target about two messages per second.
    self.assertGreaterEqual(clock.now, 299)

  def test_single_message_requests_stay_below_current_quota(self):
    self.run_downloads(1)

  def test_default_batches_stay_below_current_quota(self):
    self.run_downloads(10)

  def test_maximum_batches_stay_below_current_quota(self):
    self.run_downloads(100)


if __name__ == '__main__':
  unittest.main()
