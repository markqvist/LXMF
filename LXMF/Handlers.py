import time
import RNS
import RNS.vendor.umsgpack as msgpack

from .LXMF import APP_NAME, stamp_cost_from_app_data

from .LXMessage import LXMessage

class LXMFDeliveryAnnounceHandler:
    def __init__(self, lxmrouter):
        self.aspect_filter = APP_NAME+".delivery"
        self.receive_path_responses = True
        self.lxmrouter = lxmrouter

    def received_announce(self, destination_hash, announced_identity, app_data):
        for lxmessage in self.lxmrouter.pending_outbound:
            if destination_hash == lxmessage.destination_hash:
                if lxmessage.method == LXMessage.DIRECT:
                    lxmessage.next_delivery_attempt = time.time()

                    while self.lxmrouter.processing_outbound:
                        time.sleep(0.1)

                    self.lxmrouter.process_outbound()

        try:
            stamp_cost = stamp_cost_from_app_data(app_data)
            self.lxmrouter.update_stamp_cost(destination_hash, stamp_cost)

        except Exception as e:
            RNS.log(f"An error occurred while trying to decode announced stamp cost. The contained exception was: {e}", RNS.LOG_ERROR)


class LXMFPropagationAnnounceHandler:
    def __init__(self, lxmrouter):
        self.aspect_filter = APP_NAME+".propagation"
        self.receive_path_responses = False
        self.lxmrouter = lxmrouter

    def received_announce(self, destination_hash, announced_identity, app_data):
        try:
            if type(app_data) == bytes:
                data = msgpack.unpackb(app_data)

                if self.lxmrouter.propagation_node and self.lxmrouter.autopeer:
                    node_timebase = data[1]
                    propagation_transfer_limit = None
                    if len(data) >= 3:
                        try:
                            propagation_transfer_limit = float(data[2])
                        except:
                            propagation_transfer_limit = None

                    if data[0] == True:
                        if RNS.Transport.hops_to(destination_hash) <= self.lxmrouter.autopeer_maxdepth:
                            self.lxmrouter.peer(destination_hash, node_timebase, propagation_transfer_limit)

                    elif data[0] == False:
                        self.lxmrouter.unpeer(destination_hash, node_timebase)

        except Exception as e:
            RNS.log("Error while evaluating propagation node announce, ignoring announce.", RNS.LOG_DEBUG)
            RNS.log("The contained exception was: "+str(e), RNS.LOG_DEBUG)
