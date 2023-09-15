import asyncio

from electrum import SimpleConfig
from electrum import Network
from electrum import util
from electrum import ipfs_db

if __name__ == 'x__main__':
    loop, stop_loop, loop_thread = util.create_and_start_event_loop()
    network = Network(SimpleConfig())
    
    db = ipfs_db.IPFSDB('./test_ipfs.json')
    ipfs_hashes = ['QmUuSYPSULsPxW15gs4LPYpei78tZ1EZ5jiLQL13huoPzi', 
                   'QmaSxufBEa9nGaoC5XTtECMmT8t5YNGcJrNcj7uWFqTkSD', 
                   'QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc',
                   'Qmbj2iReDTEfWbu1iKh37soYuMARq6QobC2Zc2CcrMR4Mr',
                   'QmdBPr3SrgGsXhBeWhTziPzst8ES7e1bvnr3CQido6gLk8']
    for hash in ipfs_hashes:
        network.run_from_another_thread(db._download_ipfs_information(hash))

    print('done')
    #loop.call_soon_threadsafe(stop_loop.set_result, 1)
    #loop_thread.join(timeout=1)

