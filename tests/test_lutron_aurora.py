"""Tests for direct Lutron Aurora manufacturer notifications."""

import asyncio
import json
from pathlib import Path

import pytest
from zigpy.zcl import ClusterType
from zigpy.zcl.clusters.general import (
    Basic,
    Groups,
    Identify,
    LevelControl,
    OnOff,
    Ota,
    PowerConfiguration,
)
from zigpy.zcl.clusters.lightlink import LightLink

from zhaquirks.lutron.aurora import AuroraRawCluster

PRESS = bytes.fromhex("1d0b1012000100003000210000")
RELEASE = bytes.fromhex("1d0b1013000100003002210300")
CW = bytes.fromhex("1d0b1006001400013001293800216e00292000216e00293800219001")
CCW = bytes.fromhex("1d0b101400140001300129e4ff216e0029f0ff216e0029e4ff219001")


class EventListener:
    """Collect the public event interface consumed by ZHA."""

    def __init__(self):
        """Initialize captured events."""
        self.events = []

    def zha_send_event(self, command, args):
        """Receive a quirk event."""
        self.events.append((command, args))


@pytest.fixture
def aurora(zigpy_device_from_v2_quirk):
    """Apply the quirk to the observed Aurora cluster set."""
    device = zigpy_device_from_v2_quirk(
        "Lutron",
        "Z3-1BRL",
        firmware_version=0xC12,
        cluster_ids={
            1: {
                Basic.cluster_id: ClusterType.Server,
                PowerConfiguration.cluster_id: ClusterType.Server,
                Identify.cluster_id: ClusterType.Server,
                LightLink.cluster_id: ClusterType.Server,
                AuroraRawCluster.cluster_id: ClusterType.Server,
                Groups.cluster_id: ClusterType.Client,
                OnOff.cluster_id: ClusterType.Client,
                LevelControl.cluster_id: ClusterType.Client,
                Ota.cluster_id: ClusterType.Client,
            }
        },
    )
    # Both directions exist for Identify and LightLink on the real device.
    device.endpoints[1].add_output_cluster(Identify.cluster_id)
    device.endpoints[1].add_output_cluster(LightLink.cluster_id)
    cluster = device.endpoints[1].in_clusters[AuroraRawCluster.cluster_id]
    assert isinstance(cluster, AuroraRawCluster)
    listener = EventListener()
    cluster.add_listener(listener)
    return cluster, listener


def feed(cluster, frame):
    """Pass a wire frame through the normal cluster deserialization path."""
    header, payload = cluster.deserialize(frame)
    cluster.handle_message(header, payload)


def test_button_down_is_immediate_and_lossless(aurora):
    """A button-down frame is forwarded without waiting for release."""
    cluster, listener = aurora
    feed(cluster, PRESS)
    assert listener.events == [
        (
            "aurora_notification",
            {
                "frame_hex": "1d0b1012000100003000210000",
                "payload_hex": "0100003000210000",
                "manufacturer_code": 4107,
                "command_id": 0,
                "sequence": 18,
                "control_id": 1,
                "prefix_hex": "010000",
                "event_code": 0,
                "fields": [
                    {"offset": 3, "type": 48, "value": 0},
                    {"offset": 5, "type": 33, "value": 0},
                ],
            },
        )
    ]


@pytest.mark.parametrize(
    ("frame", "values", "rotation"),
    [
        (CW, [1, 56, 110, 32, 110, 56, 400], 56),
        (CCW, [1, -28, 110, -16, 110, -28, 400], -28),
    ],
)
def test_rotation_preserves_every_numeric_field(aurora, frame, values, rotation):
    """Signed movement and trailing numeric data are preserved without scaling."""
    cluster, listener = aurora
    feed(cluster, frame)
    assert len(listener.events) == 1
    command, event = listener.events[0]
    assert command == "aurora_notification"
    assert event["control_id"] == 0x14
    assert event["event_code"] == 1
    assert event["rotation"] == rotation
    assert [f["value"] for f in event["fields"]] == values
    assert [f["offset"] for f in event["fields"]] == [3, 5, 8, 11, 14, 17, 20]
    assert [f["type"] for f in event["fields"]] == [
        0x30,
        0x29,
        0x21,
        0x29,
        0x21,
        0x29,
        0x21,
    ]
    assert event["frame_hex"] == frame.hex()
    assert "speed" not in event


def test_whole_capture_is_one_event_per_notification(aurora):
    """All 32 captured frames survive, in order, including the release value."""
    cluster, listener = aurora
    capture = json.loads(
        (Path(__file__).parent / "fixtures/lutron_aurora_c12.json").read_text()
    )
    for index, frame in enumerate(capture["frames"], start=1):
        feed(cluster, bytes.fromhex(frame))
        assert len(listener.events) == index
    events = [event for command, event in listener.events]
    assert len(events) == 32
    assert [event["frame_hex"] for event in events] == capture["frames"]
    assert [event["control_id"] for event in events] == [20] * 12 + [1] * 2 + [20] * 18
    assert [event["event_code"] for event in events] == [1] + [2] * 11 + [0, 2] + [
        1
    ] + [2] * 17
    assert events[13]["fields"][-1] == {"offset": 5, "type": 0x21, "value": 3}
    assert [field["value"] for field in events[-1]["fields"]] == [
        2,
        -96,
        400,
        -1152,
        7290,
        -96,
        400,
    ]
    assert all("undecoded_hex" not in event for event in events)
    json.dumps(events)


@pytest.mark.asyncio
async def test_fast_clicks_stay_separate(aurora):
    """Three quick clicks yield six immediate events and no delayed synthesis."""
    cluster, listener = aurora
    for index, frame in enumerate([PRESS, RELEASE] * 3, start=1):
        feed(cluster, frame)
        assert len(listener.events) == index
    assert [event["event_code"] for command, event in listener.events] == [0, 2] * 3
    await asyncio.sleep(0.35)
    assert len(listener.events) == 6


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x01",
        bytes.fromhex("010000"),
        bytes.fromhex("0100003099"),
        bytes.fromhex("9900003000210000"),
    ],
)
def test_unknown_and_short_notifications_are_preserved(aurora, payload):
    """Unknown controls/codes and short payloads remain available to callers."""
    cluster, listener = aurora
    frame = PRESS[:5] + payload
    feed(cluster, frame)
    assert len(listener.events) == 1
    assert listener.events[0][1]["frame_hex"] == frame.hex()
    assert listener.events[0][1]["payload_hex"] == payload.hex()


@pytest.mark.parametrize("tail", ["ff1122", "29aa"])
def test_unknown_or_truncated_typed_tail_is_retained(aurora, tail):
    """An unrecognized or incomplete value stops decoding without losing bytes."""
    cluster, listener = aurora
    frame = PRESS + bytes.fromhex(tail)
    feed(cluster, frame)
    event = listener.events[0][1]
    assert event["frame_hex"] == frame.hex()
    assert event["undecoded_hex"] == tail
    assert event["fields"] == [
        {"offset": 3, "type": 0x30, "value": 0},
        {"offset": 5, "type": 0x21, "value": 0},
    ]


@pytest.mark.parametrize("header", ["1d44111200", "1d0b101299", "150b101200"])
def test_unrelated_cluster_commands_do_not_emit_notifications(aurora, header):
    """Other manufacturers, commands and directions are left to the base cluster."""
    cluster, listener = aurora
    feed(cluster, bytes.fromhex(header) + PRESS[5:])
    assert listener.events == []
