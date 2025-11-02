import time
import threading
import RNS
import RNS.vendor.umsgpack as msgpack

from .LXMF import APP_NAME, stamp_cost_from_app_data, pn_announce_data_is_valid
from .LXMessage import LXMessage

class LXMFDeliveryAnnounceHandler:
    def __init__(self, lxmrouter):
        self.aspect_filter          = APP_NAME+".delivery"
        self.receive_path_responses = True
        self.lxmrouter              = lxmrouter

    def received_announce(self, destination_hash, announced_identity, app_data):
        for lxmessage in self.lxmrouter.pending_outbound:
            if destination_hash     == lxmessage.destination_hash:
                if lxmessage.method == LXMessage.DIRECT or lxmessage.method == LXMessage.OPPORTUNISTIC:
                    lxmessage.next_delivery_attempt = time.time()

                    def outbound_trigger():
                        while self.lxmrouter.processing_outbound: time.sleep(0.1)
                        self.lxmrouter.process_outbound()

                    threading.Thread(target=outbound_trigger, daemon=True).start()

        try:
            stamp_cost = stamp_cost_from_app_data(app_data)
            self.lxmrouter.update_stamp_cost(destination_hash, stamp_cost)

        except Exception as e:
            RNS.log(f"An error occurred while trying to decode announced stamp cost. The contained exception was: {e}", RNS.LOG_ERROR)


class LXMFPropagationAnnounceHandler:
    def __init__(self, lxmrouter):
        self.aspect_filter          = APP_NAME+".propagation"
        self.receive_path_responses = True
        self.lxmrouter              = lxmrouter

    def received_announce(self, destination_hash, announced_identity, app_data, announce_packet_hash, is_path_response):
        try:
            if type(app_data) == bytes:
                if self.lxmrouter.propagation_node:
                    if pn_announce_data_is_valid(app_data):
                        data                               = msgpack.unpackb(app_data)
                        node_timebase                      = int(data[1])
                        propagation_enabled                =     data[2]
                        propagation_transfer_limit         = int(data[3])
                        propagation_sync_limit             = int(data[4])
                        propagation_stamp_cost             = int(data[5][0])
                        propagation_stamp_cost_flexibility = int(data[5][1])
                        peering_cost                       = int(data[5][2])
                        metadata                           =     data[6]
                        
                        if destination_hash in self.lxmrouter.static_peers:
                            static_peer = self.lxmrouter.peers[destination_hash]
                            if not is_path_response or static_peer.last_heard == 0:
                                self.lxmrouter.peer(destination_hash=destination_hash,
                                                    timestamp=node_timebase,
                                                    propagation_transfer_limit=propagation_transfer_limit,
                                                    propagation_sync_limit=propagation_sync_limit,
                                                    propagation_stamp_cost=propagation_stamp_cost,
                                                    propagation_stamp_cost_flexibility=propagation_stamp_cost_flexibility,
                                                    peering_cost=peering_cost,
                                                    metadata=metadata)

                        else:
                            if self.lxmrouter.autopeer and not is_path_response:
                                if propagation_enabled == True:
                                    if RNS.Transport.hops_to(destination_hash) <= self.lxmrouter.autopeer_maxdepth:
                                        self.lxmrouter.peer(destination_hash=destination_hash,
                                                            timestamp=node_timebase,
                                                            propagation_transfer_limit=propagation_transfer_limit,
                                                            propagation_sync_limit=propagation_sync_limit,
                                                            propagation_stamp_cost=propagation_stamp_cost,
                                                            propagation_stamp_cost_flexibility=propagation_stamp_cost_flexibility,
                                                            peering_cost=peering_cost,
                                                            metadata=metadata)

                                    else:
                                        if destination_hash in self.lxmrouter.peers:
                                            RNS.log(f"Peer {self.lxmrouter.peers[destination_hash]} moved outside auto-peering range, breaking peering...")
                                            self.lxmrouter.unpeer(destination_hash, node_timebase)

                                elif propagation_enabled == False:
                                    self.lxmrouter.unpeer(destination_hash, node_timebase)

        except Exception as e:
            RNS.log("Error while evaluating propagation node announce, ignoring announce.", RNS.LOG_DEBUG)
            RNS.log(f"The contained exception was: {str(e)}", RNS.LOG_DEBUG)
