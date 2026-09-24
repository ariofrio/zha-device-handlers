"""Direct Aurora Z3-1BRL notifications for firmware using the Philips protocol.

Firmware 0x00000c12 sends Philips-style command 0 notifications on 0xFC00
with manufacturer code 0x100B. Each notification becomes one immediate
``aurora_notification`` event. Button event codes and dial phases remain
numeric; click grouping and rotation speed classification belong to consumers.

The captured payloads begin with a three-byte prefix, followed by numeric
ZCL type/value pairs. The first byte identifies the control (1 for the button,
0x14 for the dial). The other prefix bytes are preserved without interpretation.
The first enum8 is exposed as ``event_code``; for the dial, the following int16
is also exposed as ``rotation``, with positive clockwise and negative
counterclockwise values in the capture. Physical units are not established.

Every parsed value retains its payload offset and type. Subsequent int16/uint16
fields have not been assigned time/position semantics. Unknown types and
incomplete values leave an ``undecoded_hex`` tail. Full payload and ZCL frame
hex are always retained, including for short or otherwise unknown notifications.

PhilipsRemoteCluster knows the notification prefix but also synthesizes and
delays button events. This handler uses the same cluster/command identifiers
without inheriting that gesture behavior or discarding the extended payload.
"""

from typing import Any

import zigpy.types as t
from zigpy.zcl import foundation
from zigpy.zcl.foundation import BaseCommandDefs, ZCLCommandDef

from zhaquirks.builder import QuirkBuilder
from zhaquirks.clusters import CustomCluster
from zhaquirks.const import ZHA_SEND_EVENT
from zhaquirks.philips import PhilipsRemoteCluster

PHILIPS_MANUFACTURER_CODE = 0x100B
DIAL_CONTROL_ID = 0x14
NUMERIC_TYPES = {
    foundation.DataTypeId.enum8: t.enum8,
    foundation.DataTypeId.uint16: t.uint16_t,
    foundation.DataTypeId.int16: t.int16s,
}


class AuroraRawCluster(CustomCluster):
    """Forward each manufacturer notification without gesture synthesis."""

    cluster_id = PhilipsRemoteCluster.cluster_id
    ep_attribute = "aurora_raw"
    name = "Aurora notifications"

    class ClientCommandDefs(BaseCommandDefs):
        """Keep the whole notification, including extensions and unknown fields."""

        notification = ZCLCommandDef(
            id=PhilipsRemoteCluster.ClientCommandDefs.notification.id,
            schema={"payload": t.List[t.uint8_t]},
            manufacturer_code=PHILIPS_MANUFACTURER_CODE,
        )

    def handle_cluster_request(
        self,
        hdr: foundation.ZCLHeader,
        args: Any,
        *,
        dst_addressing: t.AddrMode | None = None,
    ) -> None:
        """Emit one immediate event with raw bytes and typed numeric fields."""
        if (
            hdr.manufacturer != PHILIPS_MANUFACTURER_CODE
            or hdr.command_id != self.ClientCommandDefs.notification.id
            or hdr.direction != foundation.Direction.Server_to_Client
        ):
            return super().handle_cluster_request(
                hdr, args, dst_addressing=dst_addressing
            )

        payload = bytes(args.payload)
        event: dict[str, Any] = {
            "frame_hex": (hdr.serialize() + payload).hex(),
            "payload_hex": payload.hex(),
            "manufacturer_code": hdr.manufacturer,
            "command_id": hdr.command_id,
            "sequence": hdr.tsn,
        }
        if len(payload) >= 3:
            event["control_id"] = payload[0]
            event["prefix_hex"] = payload[:3].hex()
            fields = []
            offset = 3
            while offset < len(payload):
                type_id = payload[offset]
                value_type = NUMERIC_TYPES.get(type_id)
                if value_type is None:
                    break
                try:
                    value, remainder = value_type.deserialize(payload[offset + 1 :])
                except ValueError:
                    break
                fields.append({"offset": offset, "type": type_id, "value": int(value)})
                offset = len(payload) - len(remainder)
            event["fields"] = fields
            if offset < len(payload):
                event["undecoded_hex"] = payload[offset:].hex()
            if fields and fields[0]["type"] == foundation.DataTypeId.enum8:
                event["event_code"] = fields[0]["value"]
                if (
                    payload[0] == DIAL_CONTROL_ID
                    and len(fields) > 1
                    and fields[1]["type"] == foundation.DataTypeId.int16
                ):
                    event["rotation"] = fields[1]["value"]

        self.listener_event(ZHA_SEND_EVENT, "aurora_notification", event)


(QuirkBuilder("Lutron", "Z3-1BRL").replaces(AuroraRawCluster).add_to_registry())
