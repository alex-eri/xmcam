import xmdevice
import asyncio

async def amain():
    dev = xmdevice.IPCam("192.168.117.101", user="admin", password="adsxzcQ12", port=34567)
    #dev = xmdevice.IPCam("192.168.125.39", user="sa", password="iddqd", port=34567)
    print(len(dev.requests))
    await dev.login()
    print(len(dev.requests))
    file = (await dev.get_files())['OPFileQuery'][-1]
    print(len(dev.requests))
    await dev.get_time()
    print(len(dev.requests))
    reader = await dev.download(file)
    await dev.play_file(file,  action='DownloadStart')
    with open(file['BeginTime']+'.h264', 'wb') as out:
        while not reader.at_eof():
            out.write(await reader.read(1448))

asyncio.run(amain())
