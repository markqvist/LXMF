import RNS
import RNS.Stamps

import os
import time
import math
import itertools
import multiprocessing

from RNS.Stamps import stamp_workblock
from RNS.Stamps import stamp_valid
from RNS.Stamps import stamp_value
from RNS.Stamps import cancel_work

# LXMF-specific stamp parameters
WORKBLOCK_EXPAND_ROUNDS         = 3000
WORKBLOCK_EXPAND_ROUNDS_PN      = 1000
WORKBLOCK_EXPAND_ROUNDS_PEERING = 25
STAMP_SIZE                      = RNS.Identity.HASHLENGTH//8
PN_VALIDATION_POOL_MIN_SIZE     = 256

# Wrapper that forces the LXMF-specific stamp size
def generate_stamp(message_id, stamp_cost, expand_rounds=WORKBLOCK_EXPAND_ROUNDS, no_expand=False):
    return RNS.Stamps.generate_stamp(message_id, stamp_cost, expand_rounds=expand_rounds, no_expand=no_expand, size=STAMP_SIZE)

def validate_peering_key(peering_id, peering_key, target_cost):
    # Transitory mechanism, check non-expanded workblock validity first. ##
    workblock_ne = stamp_workblock(peering_id, no_expand=True)            #
    if stamp_valid(peering_key, target_cost, workblock_ne): return True   #
    #######################################################################

    workblock = stamp_workblock(peering_id, expand_rounds=WORKBLOCK_EXPAND_ROUNDS_PEERING)
    if not stamp_valid(peering_key, target_cost, workblock): return False
    else: return True

def validate_pn_stamp(transient_data, target_cost):
    from .LXMessage import LXMessage
    if len(transient_data) <= LXMessage.LXMF_OVERHEAD+STAMP_SIZE: return None, None, None, None
    else:
        lxm_data     = transient_data[:-STAMP_SIZE]
        stamp        = transient_data[-STAMP_SIZE:]
        transient_id = RNS.Identity.full_hash(lxm_data)

        # Transitory mechanism, check non-expanded workblock validity first. ##
        workblock_ne = stamp_workblock(transient_id, no_expand=True)          #
        if stamp_valid(stamp, target_cost, workblock_ne):                     #
            value = stamp_value(workblock_ne, stamp)                          #
            return transient_id, lxm_data, value, stamp                       #
        #######################################################################
        
        workblock = stamp_workblock(transient_id, expand_rounds=WORKBLOCK_EXPAND_ROUNDS_PN)
        if not stamp_valid(stamp, target_cost, workblock): return None, None, None, None
        else:
            value = stamp_value(workblock, stamp)
            return transient_id, lxm_data, value, stamp

def validate_pn_stamps_job_simple(transient_list, target_cost):
    validated_messages = []
    for transient_data in transient_list:
        transient_id, lxm_data, value, stamp_data = validate_pn_stamp(transient_data, target_cost)
        if transient_id: validated_messages.append([transient_id, lxm_data, value, stamp_data])

    return validated_messages

def validate_pn_stamps_job_multip(transient_list, target_cost):
    cores      = multiprocessing.cpu_count()
    pool_count = min(cores, math.ceil(len(transient_list) / PN_VALIDATION_POOL_MIN_SIZE))
        
    RNS.log(f"Validating {len(transient_list)} stamps using {pool_count} processes...", RNS.LOG_VERBOSE)
    with multiprocessing.get_context("spawn").Pool(pool_count) as p:
        validated_entries = p.starmap(validate_pn_stamp, zip(transient_list, itertools.repeat(target_cost)))
    
    RNS.log(f"Validation pool completed for {len(transient_list)} stamps", RNS.LOG_VERBOSE)

    return [e for e in validated_entries if e[0] != None]

def validate_pn_stamps(transient_list, target_cost):
    non_mp_platform = RNS.vendor.platformutils.is_android()
    if len(transient_list) <= PN_VALIDATION_POOL_MIN_SIZE or non_mp_platform: return validate_pn_stamps_job_simple(transient_list, target_cost)
    else:                                                                     return validate_pn_stamps_job_multip(transient_list, target_cost)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        RNS.log("No cost argument provided", RNS.LOG_ERROR)
        exit(1)
    else:
        try: cost = int(sys.argv[1])
        except Exception as e:
            RNS.log(f"Invalid cost argument provided: {e}", RNS.LOG_ERROR)
            exit(1)

        rounds = 1
        if len(sys.argv) > 2:
            try: rounds = int(sys.argv[2])
            except Exception as e:
                RNS.log(f"Invalid rounds argument provided: {e}", RNS.LOG_ERROR)
                exit(1)

    RNS.loglevel = RNS.LOG_DEBUG
    
    for i in range(rounds):
        RNS.log("", RNS.LOG_DEBUG)
        RNS.log(f"Round {i+1} of {rounds}", RNS.LOG_DEBUG)

        RNS.log("Testing LXMF stamp generation", RNS.LOG_DEBUG)
        message_id = os.urandom(32)
        generate_stamp(message_id, cost)

        RNS.log("", RNS.LOG_DEBUG)
        RNS.log("Testing propagation stamp generation", RNS.LOG_DEBUG)
        message_id = os.urandom(32)
        generate_stamp(message_id, cost, expand_rounds=WORKBLOCK_EXPAND_ROUNDS_PN)

        RNS.log("", RNS.LOG_DEBUG)
        RNS.log("Testing peering key generation", RNS.LOG_DEBUG)
        message_id = os.urandom(32)
        generate_stamp(message_id, cost, expand_rounds=WORKBLOCK_EXPAND_ROUNDS_PEERING)

        RNS.log("", RNS.LOG_DEBUG)
        RNS.log("Testing non-expanded workblock generation", RNS.LOG_DEBUG)
        message_id = os.urandom(32)
        generate_stamp(message_id, cost, expand_rounds=0)

        # transient_list = []
        # st = time.time(); count = 10000
        # for i in range(count): transient_list.append(os.urandom(256))
        # validate_pn_stamps(transient_list, 5)
        # dt = time.time()-st; mps = count/dt
        # RNS.log(f"Validated {count} PN stamps in {RNS.prettytime(dt)}, {round(mps,1)} m/s", RNS.LOG_DEBUG)
