# -*- coding: utf-8 -*-
"""Room lifecycle: create, join, leave, delete, list.

Thin wrappers that send one message each -- all the state changes come
back through the server's room_update.
"""
from protocol import MAX_PLAYERS, MIN_PLAYERS, MAX_PLAYERS_LIMIT


class RoomsMixin:
    def _await_registered(self):
        """Wait until the server knows who we are before asking for a room.

        Room requests are rejected before `registered`, and connect() no
        longer blocks long enough to cover that by accident: publishing the
        address used to run first and burn several seconds (or its whole
        budget, when STUN is unreachable), which happened to give the
        register reply time to arrive. Restoring the room before publishing
        removed that accident, so any create/join issued immediately after
        connect() now races the handshake and loses -- the room silently
        never gets created.
        """
        ev = getattr(self, "_registered", None)
        if ev is not None:
            ev.wait(5.0)

    def create_room(self, name, max_players=None, password=None):
        self._await_registered()
        self.room_name = name
        self.is_host = True
        cap = int(max_players) if max_players else MAX_PLAYERS
        # clamp locally too: an old server never echoes the value, and a
        # wrong number in the status panel is worse than none
        cap = max(MIN_PLAYERS, min(MAX_PLAYERS_LIMIT, cap))
        self.max_players = cap
        self.room_password = password or ""
        # an old server ignores the extra field and uses its own default
        msg = {"action": "create_room", "roomName": name,
               "name": self.my_name, "maxPlayers": cap}
        if password:
            msg["password"] = password
        self.send(msg)
        # Last chance to correct a LAN-only address before anyone tries to
        # punch to us. No-op once we already have a public endpoint.
        self._maybe_republish()

    def join_room(self, code, password=None):
        self._await_registered()
        self.is_host = False
        msg = {"action": "join_room", "roomCode": code}
        if password:
            msg["password"] = password
        self.send(msg)
        self._maybe_republish()

    def leave_room(self):
        self._reset_p2p()
        self.send({"action": "leave"})
        self.room_code = ""

    def delete_room(self, code):
        self.send({"action": "delete_room", "roomCode": code})

    def refresh_rooms(self):
        self.send({"action": "list_rooms"})

    # ---------------------------------------------------------- receive
