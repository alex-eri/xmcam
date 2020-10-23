import asyncio
import struct
import hashlib
import weakref
import json
import gettext
from pprint import pprint
from datetime import datetime, timedelta

import constants as C

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

_ = gettext.gettext

CODES = {
    100: _("Success"),
    101: _("Unknown error"),
    102: _("Version not supported"),
    103: _("Illegal request"),
    104: _("User has already logged in"),
    105: _("User is not logged in"),
    106: _("Username or Password is incorrect"),
    107: _("Insufficient permission"),
    108: _("Timeout"),
    109: _("Find failed, file not found"),
    110: _("Find success, returned all files"),
    111: _("Find success, returned part of files"),
    112: _("User already exists"),
    113: _("User does not exist"),
    114: _("User group already exists"),
    115: _("User group does not exist"),
    116: _("Reserved"),
    117: _("Message is malformed"),
    118: _("No PTZ protocol is set"),
    119: _("No query to file"),
    120: _("Configured to be enabled"),
    121: _("Digital channel is not enabled"),
    150: _("Success, device restart required"),
    202: _("User is not logged in"),
    203: _("Incorrect password"),
    204: _("User is illegal"),
    205: _("User is locked"),
    206: _("User is in the blacklist"),
    207: _("User already logged in"),
    208: _("Invalid input"),
    209: _("User already exists"),
    210: _("Object not found"),
    211: _("Object does not exist"),
    212: _("Account in use"),
    213: _("Permission table error"),
    214: _("Illegal password"),
    215: _("Password does not match"),
    216: _("Keep account number"),
    502: _("Illegal command"),
    503: _("Talk channel has ben opened"),
    504: _("Talk channel is not open"),
    511: _("Update started"),
    512: _("Update did not start"),
    513: _("Update data error"),
    514: _("Update failed"),
    515: _("Update succeeded"),
    521: _("Failed to restore default config"),
    522: _("Device restart required"),
    523: _("Default config is illegal"),
    602: _("Application restart required"),
    603: _("System restart required"),
    604: _("Write file error"),
    605: _("Features are not supported"),
    606: _("Verification failed"),
    607: _("Configuration does not exist"),
    608: _("Configuration parsing error"),
}

QCODES = {
    "AuthorityList":1470,
    "Users": 1472,
    "Groups": 1474,
    "AddGroup": 1476,
    "ModifyGroup": 1478,
    "DelGroup": 1480,
    "AddUser": 1482,
    "ModifyUser": 1484,
    "DelUser":1486,
    "ModifyPassword": 1488,
    "AlarmInfo": 1504,
    "AlarmSet": 1500,
    "KeepAlive": 1006,
    "ChannelTitle": 1046,
    "OPTimeQuery": 1452,
    "OPTimeSetting": C.SYSMANAGER_REQ,
    "OPMailTest": 1636,
    # { "Name" : "OPMailTest", "OPMailTest" : { "Enable" : true, "MailServer" : { "Address" : "0x00000000", "Anonymity" : false, "Name" : "Your SMTP Server", "Password" : "", "Port" : 25, "UserName" : "" }, "Recievers" : [ "", "none", "none", "none", "none" ], "Schedule" : [ "0 00:00:00-24:00:00", "0 00:00:00-24:00:00" ], "SendAddr" : "", "Title" : "Alarm Message", "UseSSL" : false }, "SessionID" : "0x1" }
    "OPMachine": C.SYSMANAGER_REQ,
    "OPMonitor": 1413,
    "OPTalk": 1434,
    "OPPTZControl": 1400,
    "OPNetKeyboard": 1550,
    "SystemFunction": 1360,
    "EncodeCapability": 1360,
    "OPSystemUpgrade": 0x5F5,
    "OPSendFile": 0x5F2,
}

KEY_CODES = {
    "M": "Menu",
    "I": "Info",
    "E": "Esc",
    "F": "Func",
    "S": "Shift",
    "L": "Left",
    "U": "Up",
    "R": "Right",
    "D": "Down",
}
OK_CODES = [100, 515, 511, 503, 150,602,603,522,514,504,119,110,111 ]

def sofia_hash(password=""):
    md5 = hashlib.md5(bytes(password, "utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join([chars[sum(x) % 62] for x in zip(md5[::2], md5[1::2])])


class NotConnected(Exception): pass


class XMException(Exception):

    def __init__(self, code):
        self.data = code
        super().__init__(code)

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return f"{self.__class__}({self.data}): " + CODES.get(self.data.get('Ret', 101))


class Connection():
    def __init__(self, ip, port=34567):
        self.ip = ip
        self.port = port
        self.packet_count = 0
        self.session = 0
        self.requests = weakref.WeakValueDictionary()
        self.reader, self.writer = None, None

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.ip, self.port)
        asyncio.create_task(self.readforever())




class IPCam(Connection):
    def __init__(self, ip, user="admin", password="", port=34567, hashPass=None):
        self.user = user
        self.password = hashPass or sofia_hash(password)
        self.alive_time = 20
        self.alive = True
        super().__init__(ip, port=34567)

    async def readforever(self):
        while self.alive and self.reader:
            head = await self.reader.readexactly(20)
            (
                head,
                version,
                self.session,
                sequence_number,
                msgid,
                len_data,
            ) = struct.unpack("BB2xII2xHI", head)
            print(self.session,
                  sequence_number,
                  msgid,
                  len_data)
            reply = await self.reader.readexactly(len_data)
            pprint(dict(self.requests))

            result = json.loads(reply[:-1], encoding="utf-8")
            pprint(result)

            fut = self.requests.get(sequence_number)
            if not fut and sequence_number==self.packet_count:
                fut = self.requests.get(sequence_number-1)
            if not fut:
                continue
            if result["Ret"] in OK_CODES:
                fut.set_result(result)
            else:
                fut.set_exception(XMException(result))



    async def send(self, msg, data=None, writer=None):
        if writer is None:
            writer = self.writer
        if writer is None:
            raise NotConnected()
        if data is not None:
            data = bytes(json.dumps(data, ensure_ascii=False), "utf-8") + b"\x0a\x00"
        else:
            data = b""
        payload = struct.pack(
                "BB2xII2xHI",
                255,
                1,
                self.session,
                self.packet_count,
                msg,
                len(data),
            )
        self.requests[self.packet_count] = fut = asyncio.Future()
        self.packet_count += 1
        self.packet_count %= 4294967296
        writer.write(payload)
        writer.write(data)
        await writer.drain()
        return await fut

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.ip, self.port)
        asyncio.create_task(self.readforever())

    async def login(self, hashPass=None):
        if self.writer is None:
            await self.connect()
        data = await self.send(
            C.LOGIN_REQ,
            {
                "EncryptType": "MD5",
                "LoginType": "DVRIP-Web",
                "PassWord": hashPass or self.password,
                "UserName": self.user,
            },
        )
        self.session = int(data["SessionID"], 16)
        self.alive_time = data["AliveInterval"]
        asyncio.create_task(self.keep_alive())
        self.channels = data.get('ChannelNum')
        self.devtype = data.get('DeviceType')
        return data

    async def keep_alive(self):
        while self.alive:
            await asyncio.sleep(self.alive_time)
            try:
                await self.send(
                    QCODES["KeepAlive"],
                    {"Name": "KeepAlive", "SessionID": "0x%08X" % self.session},
                )
            except:
                self.alive = False

    def get(self, code, command, writer=None):
        return self.send(
            code,
            {"Name": command, "SessionID": "0x%08X" % self.session},
            writer=writer
        )

    def set(self, code, command, data, writer=None):
        return self.send(
            code,
            {"Name": command, "SessionID": "0x%08X" % self.session, command: data},
            writer=writer
        )

    def get_info(self, command):
        return self.get(C.CONFIG_GET, command)

    def set_info(self, command, data):
        return self.set(C.CONFIG_SET, command, data)

    async def get_time(self):
        timestamp =  await self.get(QCODES["OPTimeQuery"], "OPTimeQuery")
        return datetime.strptime(
            timestamp["OPTimeQuery"],
            DATE_FORMAT
        )

    def set_time(self, time=None):
        if time is None:
            time = datetime.now()
        return self.set(
            QCODES["OPTimeSetting"],
            "OPTimeSetting",
            time.strftime(DATE_FORMAT),
        )

    def get_files(self, channel=0, begin=None, end=None):
        if end is None: end = datetime.now()
        if begin is None: begin = end - timedelta(days=1)
        return self.set(
            C.FILESEARCH_REQ,
            "OPFileQuery",
            {
                "BeginTime" : begin.strftime(DATE_FORMAT),
                "Channel" : channel,
                "DriverTypeMask" : "0x0000FFFF",
                "EndTime" : end.strftime(DATE_FORMAT),
                "Event" : "AMRH",
                "Type" : "h264"
            })

    async def play_file(self, file, action="Claim"):
        return await self.set(
            C.PLAY_REQ,
            "OPPlayBack",
            {
                "Action" : action,
                "EndTime" : file['EndTime'],
                "Parameter" : {
                    "FileName" : file['FileName'],
                    "TransMode" : "TCP"
                },
                "StartTime" : file['BeginTime'],
            }
        )

    async def download(self, file, action="DownloadStart"):
        reader, writer = await asyncio.open_connection(self.ip, self.port)
        code = C.PLAY_CLAIM
        command = "OPPlayBack"
        data = {
                "Action" : action,
                "EndTime" : file['EndTime'],
                "Parameter" : {
                    "FileName" : file['FileName'],
                    "TransMode" : "TCP"
                },
                "StartTime" : file['BeginTime'],
            }
        data = bytes(json.dumps(data, ensure_ascii=False), "utf-8") + b"\x0a\x00"
        payload = struct.pack(
                "BB2xII2xHI",
                255,
                1,
                self.session,
                0,
                code,
                len(data),
            )
        writer.write(payload)
        writer.write(data)
        await writer.drain()

        head = await reader.readexactly(20)
        (
            head,
            version,
            self.session,
            sequence_number,
            msgid,
            len_data,
        ) = struct.unpack("BB2xII2xHI", head)

        reply = await reader.readexactly(len_data)

        result = json.loads(reply[:-1], encoding="utf-8")
        pprint(result)
        if result["Ret"] in OK_CODES:
            return reader
