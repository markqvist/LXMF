import os
import time
import sqlite3
import threading

import RNS
import RNS.vendor.umsgpack as msgpack


class LXMFStore:
    CURRENT_VERSION     = 1

    TRANSIENT_ID_LENGTH = RNS.Identity.HASHLENGTH//8
    DESTINATION_LENGTH  = RNS.Identity.TRUNCATED_HASHLENGTH//8
    TICKET_LENGTH       = RNS.Identity.TRUNCATED_HASHLENGTH//8

    IMPORT_CHUNK        = 4096
    CULL_CHUNK          = 4096
    IN_CHUNK            = 512
    VACUUM_PAGES        = 512

    def __init__(self, db_path):
        if sqlite3.threadsafety < 3: raise RuntimeError("Storage backend requires a SQLite build with serialized threading support")

        self.db_path       = db_path
        self._conn         = None
        self._conn_lock    = threading.Lock()
        self._close_warned = False

        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)

        self._conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA journal_size_limit=8388608")
        self._conn.execute("PRAGMA busy_timeout=1500")

        self.__create_schema()

    def close(self):
        with self._conn_lock:
            if self._conn != None:
                try: self._conn.execute("PRAGMA optimize")
                except Exception: pass
                self._conn.close()
                self._conn = None

    def __create_schema(self):
        db_version = self._conn.execute("PRAGMA user_version").fetchone()[0]

        if db_version > self.CURRENT_VERSION:
            RNS.log(f"Cannot open store {self.db_path}: database version {db_version} is newer than supported version {self.CURRENT_VERSION}", RNS.LOG_CRITICAL)
            self._conn.close(); self._conn = None
            raise ValueError(f"Store database version {db_version} is newer than supported version {self.CURRENT_VERSION}")

        try:
            self._conn.execute("BEGIN")

            self._conn.execute("""CREATE TABLE IF NOT EXISTS stamp_costs (
                destination_hash BLOB PRIMARY KEY,
                updated          REAL NOT NULL,
                used             REAL,
                cost             REAL)""")

            self._conn.execute("""CREATE TABLE IF NOT EXISTS delivered_transient_ids (
                transient_id BLOB PRIMARY KEY,
                received     REAL NOT NULL)""")

            self._conn.execute("""CREATE TABLE IF NOT EXISTS processed_transient_ids (
                transient_id BLOB PRIMARY KEY,
                received     REAL NOT NULL)""")

            self._conn.execute("""CREATE TABLE IF NOT EXISTS tickets_outbound (
                destination_hash BLOB PRIMARY KEY,
                expires          REAL NOT NULL,
                ticket           BLOB NOT NULL)""")

            self._conn.execute("""CREATE TABLE IF NOT EXISTS tickets_inbound (
                ticket           BLOB PRIMARY KEY,
                destination_hash BLOB NOT NULL,
                expires          REAL NOT NULL)""")

            self._conn.execute("""CREATE TABLE IF NOT EXISTS ticket_deliveries (
                destination_hash BLOB PRIMARY KEY,
                timestamp        REAL NOT NULL)""")

            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_delivered_received ON delivered_transient_ids (received)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_processed_received ON processed_transient_ids (received)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_stampcost_updated ON stamp_costs (updated)")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_in_dest ON tickets_inbound (destination_hash)")

            self._conn.execute(f"PRAGMA user_version = {self.CURRENT_VERSION}")
            self._conn.execute("COMMIT")

        except Exception as e:
            RNS.log(f"Could not initialise store schema at {self.db_path}. The contained exception was: {e}", RNS.LOG_CRITICAL)
            try: self._conn.execute("ROLLBACK")
            except Exception: pass
            self._conn.close(); self._conn = None
            raise

    def _ready(self):
        if self._conn == None:
            if not self._close_warned:
                self._close_warned = True
                RNS.log("Store operation attempted after close", RNS.LOG_ERROR)
            return False
        else: return True

    def _claim(self, table, key_column, key, ts_column, timestamp):
        try:
            with self._conn_lock:
                if not self._ready(): return True
                cursor = self._conn.execute(f"INSERT INTO {table} ({key_column}, {ts_column}) VALUES (?, ?) ON CONFLICT({key_column}) DO NOTHING", (key, timestamp))
                return cursor.rowcount == 1

        except Exception as e:
            RNS.log(f"Could not claim entry in {table} of store, treating as claimed. The contained exception was: {e}", RNS.LOG_ERROR)
            return True

    def _upsert_timestamp(self, table, key_column, key, ts_column, timestamp):
        try:
            with self._conn_lock:
                if not self._ready(): return False
                self._conn.execute(f"INSERT INTO {table} ({key_column}, {ts_column}) VALUES (?, ?) ON CONFLICT({key_column}) DO UPDATE SET {ts_column}=excluded.{ts_column}", (key, timestamp))
                return True

        except Exception as e:
            RNS.log(f"Could not upsert entry in {table} of store. The contained exception was: {e}", RNS.LOG_ERROR)
            return False

    def _cull(self, table, ts_column, cutoff, max_entries):
        try:
            with self._conn_lock:
                if not self._ready(): return 0
                cursor = self._conn.execute(f"DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {ts_column} < ? LIMIT {int(max_entries)})", (cutoff,))
                return cursor.rowcount

        except Exception as e:
            RNS.log(f"Could not cull entries in {table} of store. The contained exception was: {e}", RNS.LOG_ERROR)
            return 0


    ########################
    # Outbound Stamp Costs #
    ########################

    def update_stamp_cost(self, destination_hash, cost):
        try:
            with self._conn_lock:
                if not self._ready(): return False
                self._conn.execute("INSERT INTO stamp_costs (destination_hash, updated, used, cost) VALUES (?, ?, NULL, ?) ON CONFLICT(destination_hash) DO UPDATE SET updated=excluded.updated, cost=excluded.cost", (destination_hash, time.time(), cost))
                return True

        except Exception as e:
            RNS.log(f"Could not update outbound stamp cost in store. The contained exception was: {e}", RNS.LOG_ERROR)
            return False

    def get_outbound_stamp_cost(self, destination_hash):
        if not self._ready(): return None
        cost = None
        try:
            with self._conn_lock:
                if not self._ready(): return None
                row = self._conn.execute("SELECT cost FROM stamp_costs WHERE destination_hash=?", (destination_hash,)).fetchone()
                if row != None and len(row) > 0:
                    cost = row[0]
                    try: self._conn.execute("UPDATE stamp_costs SET used=? WHERE destination_hash=?", (time.time(), destination_hash))
                    except Exception as e: RNS.log(f"Could not update stamp cost usage time in store. The contained exception was: {e}", RNS.LOG_ERROR)

        except Exception as e:
            RNS.log(f"Could not recall outbound stamp cost from store. The contained exception was: {e}", RNS.LOG_ERROR)
            return None

        return cost

    def cull_stamp_costs(self, cutoff, max_entries=CULL_CHUNK): return self._cull("stamp_costs", "updated", cutoff, max_entries)


    ##############################
    # Transient ID Deduplication #
    ##############################

    def has_delivered(self, transient_id):
        if not self._ready(): return False
        try:
            with self._conn_lock:
                if not self._ready(): return False
                row = self._conn.execute("SELECT transient_id FROM delivered_transient_ids WHERE transient_id=?", (transient_id,)).fetchone()
                return row != None

        except Exception as e:
            RNS.log(f"Could not query delivered transient ID in store. The contained exception was: {e}", RNS.LOG_ERROR)
            return False

    def known_delivered(self, transient_ids):
        known = set()
        if not self._ready(): return known

        try:
            with self._conn_lock:
                if not self._ready(): return known
                ids = list(set(transient_id for transient_id in transient_ids if type(transient_id) == bytes))
                for i in range(0, len(ids), self.IN_CHUNK):
                    chunk = ids[i:i+self.IN_CHUNK]
                    marks = ",".join("?"*len(chunk))
                    for row in self._conn.execute(f"SELECT transient_id FROM delivered_transient_ids WHERE transient_id IN ({marks})", chunk):
                        known.add(row[0])

        except Exception as e:
            RNS.log(f"Could not query known delivered transient IDs in store. The contained exception was: {e}", RNS.LOG_ERROR)
            return set()

        return known

    def mark_locally_delivered(self, transient_id, received):         return self._upsert_timestamp("delivered_transient_ids", "transient_id", transient_id, "received", received)
    def unconditionally_mark_processed(self, transient_id, received): return self._upsert_timestamp("processed_transient_ids", "transient_id", transient_id, "received", received)
    def conditionally_claim_delivered(self, transient_id, received):  return self._claim("delivered_transient_ids", "transient_id", transient_id, "received", received)
    def conditionally_claim_processed(self, transient_id, received):  return self._claim("processed_transient_ids", "transient_id", transient_id, "received", received)
    def cull_processed(self, cutoff, max_entries=CULL_CHUNK):         return self._cull("processed_transient_ids", "received", cutoff, max_entries)
    def cull_delivered(self, cutoff, max_entries=CULL_CHUNK):         return self._cull("delivered_transient_ids", "received", cutoff, max_entries)


    ###########
    # Tickets #
    ###########

    def remember_ticket(self, destination_hash, ticket_entry):
        try:
            expires, ticket = ticket_entry[0], ticket_entry[1]
            with self._conn_lock:
                if not self._ready(): return False
                self._conn.execute("INSERT INTO tickets_outbound (destination_hash, expires, ticket) VALUES (?, ?, ?) ON CONFLICT(destination_hash) DO UPDATE SET expires=excluded.expires, ticket=excluded.ticket", (destination_hash, expires, ticket))
                return True

        except Exception as e:
            RNS.log(f"Could not remember ticket in store. The contained exception was: {e}", RNS.LOG_ERROR)
            return False

    def get_outbound_ticket(self, destination_hash):
        if not self._ready(): return None
        try:
            with self._conn_lock:
                if not self._ready(): return None
                row = self._conn.execute("SELECT ticket FROM tickets_outbound WHERE destination_hash=? AND expires > ?", (destination_hash, time.time())).fetchone()
                if row != None: return row[0]
                else:           return None

        except Exception as e:
            RNS.log(f"Could not recall outbound ticket from store. The contained exception was: {e}", RNS.LOG_ERROR)
            return None

    def get_outbound_ticket_expiry(self, destination_hash):
        if not self._ready(): return None
        try:
            with self._conn_lock:
                if not self._ready(): return None
                row = self._conn.execute("SELECT expires FROM tickets_outbound WHERE destination_hash=? AND expires > ?", (destination_hash, time.time())).fetchone()
                if row != None: return row[0]
                else:           return None

        except Exception as e:
            RNS.log(f"Could not recall outbound ticket expiry from store. The contained exception was: {e}", RNS.LOG_ERROR)
            return None

    def get_reusable_inbound_ticket(self, destination_hash, renew_before):
        if not self._ready(): return None
        try:
            with self._conn_lock:
                if not self._ready(): return None
                row = self._conn.execute("SELECT expires, ticket FROM tickets_inbound WHERE destination_hash=? AND expires > ? ORDER BY expires DESC LIMIT 1", (destination_hash, time.time()+renew_before)).fetchone()
                if row != None: return [row[0], row[1]]
                else:           return None

        except Exception as e:
            RNS.log(f"Could not recall reusable inbound ticket from store. The contained exception was: {e}", RNS.LOG_ERROR)
            return None

    def store_inbound_ticket(self, destination_hash, ticket, expires):
        try:
            with self._conn_lock:
                if not self._ready(): return False
                self._conn.execute("INSERT INTO tickets_inbound (ticket, destination_hash, expires) VALUES (?, ?, ?) ON CONFLICT(ticket) DO UPDATE SET destination_hash=excluded.destination_hash, expires=excluded.expires", (ticket, destination_hash, expires))
                return True

        except Exception as e:
            RNS.log(f"Could not save inbound ticket in store. The contained exception was: {e}", RNS.LOG_ERROR)
            return False

    def get_inbound_tickets(self, destination_hash):
        if not self._ready(): return None
        try:
            with self._conn_lock:
                if not self._ready(): return None
                tickets = [row[0] for row in self._conn.execute("SELECT ticket FROM tickets_inbound WHERE destination_hash=? AND expires > ?", (destination_hash, time.time()))]
                if len(tickets) > 0: return tickets
                else:                return None

        except Exception as e:
            RNS.log(f"Could not recall inbound tickets from store. The contained exception was: {e}", RNS.LOG_ERROR)
            return None

    def get_last_ticket_delivery(self, destination_hash):
        if not self._ready(): return None
        try:
            with self._conn_lock:
                if not self._ready(): return None
                row = self._conn.execute("SELECT timestamp FROM ticket_deliveries WHERE destination_hash=?", (destination_hash,)).fetchone()
                if row != None: return row[0]
                else:           return None

        except Exception as e:
            RNS.log(f"Could not recall last ticket delivery from store. The contained exception was: {e}", RNS.LOG_ERROR)
            return None

    def mark_last_ticket_delivery(self, destination_hash, timestamp):
        try:
            with self._conn_lock:
                if not self._ready(): return False
                self._conn.execute("INSERT INTO ticket_deliveries (destination_hash, timestamp) VALUES (?, ?) ON CONFLICT(destination_hash) DO UPDATE SET timestamp=excluded.timestamp", (destination_hash, timestamp))
                return True

        except Exception as e:
            RNS.log(f"Could not record last ticket delivery in store. The contained exception was: {e}", RNS.LOG_ERROR)
            return False

    def cull_tickets_outbound(self, cutoff, max_entries=CULL_CHUNK): return self._cull("tickets_outbound", "expires", cutoff, max_entries)
    def cull_tickets_inbound(self, cutoff, max_entries=CULL_CHUNK):  return self._cull("tickets_inbound", "expires", cutoff, max_entries)


    ###############
    # Maintenance #
    ###############

    def incremental_vacuum(self, max_pages=VACUUM_PAGES):
        try:
            with self._conn_lock:
                if not self._ready(): return 0
                freed = 0
                while freed < int(max_pages):
                    before = self._conn.execute("PRAGMA freelist_count").fetchone()[0]
                    self._conn.execute(f"PRAGMA incremental_vacuum({int(max_pages)-freed})")
                    after = self._conn.execute("PRAGMA freelist_count").fetchone()[0]
                    if after >= before: break
                    freed += before-after

                return freed

        except Exception as e:
            RNS.log(f"Could not run incremental vacuum on store. The contained exception was: {e}", RNS.LOG_ERROR)
            return 0


    ############################
    # Legacy Storage Migration #
    ############################

    def import_legacy_delivered(self, path): return self.__import_legacy_timestamps(path, "delivered_transient_ids")
    def import_legacy_processed(self, path): return self.__import_legacy_timestamps(path, "processed_transient_ids")

    def __import_legacy_timestamps(self, path, table):
        st = time.time()
        try:
            with open(path, "rb") as legacy_file: legacy = msgpack.unpackb(legacy_file.read())

        except Exception as e:
            RNS.log(f"Could not read legacy transient ID cache at {path}: {e}", RNS.LOG_ERROR)
            return -1

        if not type(legacy) == dict:
            RNS.log(f"Invalid data format in legacy transient ID cache at {path}, not importing", RNS.LOG_ERROR)
            return -1

        rows = []
        for transient_id, timestamp in legacy.items():
            if type(transient_id) == bytes and len(transient_id) == self.TRANSIENT_ID_LENGTH and type(timestamp) in (int, float) and timestamp > 0:
                rows.append((transient_id, float(timestamp)))

        imported = -1
        with self._conn_lock:
            if self._ready():
                try:
                    self._conn.execute("BEGIN")
                    for i in range(0, len(rows), self.IMPORT_CHUNK): self._conn.executemany(f"INSERT OR IGNORE INTO {table} (transient_id, received) VALUES (?, ?)", rows[i:i+self.IMPORT_CHUNK])
                    self._conn.execute("COMMIT")
                    imported = len(rows)

                except Exception as e:
                    RNS.log(f"Could not import legacy transient ID cache at {path} into store. The contained exception was: {e}", RNS.LOG_ERROR)
                    try: self._conn.execute("ROLLBACK")
                    except Exception: pass

        if imported >= 0:
            try: os.replace(path, path+".imported")
            except Exception as e: RNS.log(f"Could not mark legacy file {path} as imported: {e}", RNS.LOG_WARNING)
            RNS.log(f"Imported {imported} entries from {os.path.split(path)[-1]} into store in {RNS.prettyshorttime(time.time()-st)}", RNS.LOG_VERBOSE)

        return imported

    def import_legacy_stamp_costs(self, path):
        st = time.time()
        try:
            with open(path, "rb") as legacy_file: legacy = msgpack.unpackb(legacy_file.read())

        except Exception as e:
            RNS.log(f"Could not read legacy outbound stamp cost cache at {path}: {e}", RNS.LOG_ERROR)
            return -1

        if not type(legacy) == dict:
            RNS.log(f"Invalid data format in legacy outbound stamp cost cache at {path}, not importing", RNS.LOG_ERROR)
            return -1

        rows = []
        for destination_hash, entry in legacy.items():
            if type(destination_hash) == bytes and len(destination_hash) == self.DESTINATION_LENGTH and type(entry) in (list, tuple) and len(entry) >= 2:
                last_heard, cost = entry[0], entry[1]
                if type(last_heard) not in (int, float):    continue
                if cost != None and type(cost) not in (int, float): continue
                rows.append((destination_hash, float(last_heard), cost))

        imported = -1
        with self._conn_lock:
            if self._ready():
                try:
                    self._conn.execute("BEGIN")
                    for i in range(0, len(rows), self.IMPORT_CHUNK): self._conn.executemany("INSERT OR IGNORE INTO stamp_costs (destination_hash, updated, used, cost) VALUES (?, ?, NULL, ?)", rows[i:i+self.IMPORT_CHUNK])
                    self._conn.execute("COMMIT")
                    imported = len(rows)

                except Exception as e:
                    RNS.log(f"Could not import legacy outbound stamp cost cache at {path} into store. The contained exception was: {e}", RNS.LOG_ERROR)
                    try: self._conn.execute("ROLLBACK")
                    except Exception: pass

        if imported >= 0:
            try: os.replace(path, path+".imported")
            except Exception as e: RNS.log(f"Could not mark legacy file {path} as imported: {e}", RNS.LOG_WARNING)
            RNS.log(f"Imported {imported} entries from {os.path.split(path)[-1]} into store in {RNS.prettyshorttime(time.time()-st)}", RNS.LOG_VERBOSE)

        return imported

    def import_legacy_tickets(self, path):
        st = time.time()
        try:
            with open(path, "rb") as legacy_file: legacy = msgpack.unpackb(legacy_file.read())

        except Exception as e:
            RNS.log(f"Could not read legacy available tickets file at {path}: {e}", RNS.LOG_ERROR)
            return -1

        if not type(legacy) == dict:
            RNS.log(f"Invalid data format in legacy available tickets file at {path}, not importing", RNS.LOG_ERROR)
            return -1

        rows_outbound   = []
        rows_inbound    = []
        rows_deliveries = []

        outbound = legacy.get("outbound"); inbound = legacy.get("inbound"); last_deliveries = legacy.get("last_deliveries")

        if type(outbound) == dict:
            for destination_hash, entry in outbound.items():
                if type(destination_hash) == bytes and len(destination_hash) == self.DESTINATION_LENGTH and type(entry) in (list, tuple) and len(entry) >= 2:
                    if type(entry[0]) in (int, float) and type(entry[1]) == bytes and len(entry[1]) == self.TICKET_LENGTH:
                        rows_outbound.append((destination_hash, float(entry[0]), entry[1]))

        if type(inbound) == dict:
            for destination_hash, tickets in inbound.items():
                if not (type(destination_hash) == bytes and len(destination_hash) == self.DESTINATION_LENGTH and type(tickets) == dict): continue
                for ticket, entry in tickets.items():
                    if type(ticket) == bytes and len(ticket) == self.TICKET_LENGTH and type(entry) in (list, tuple) and len(entry) >= 1:
                        if type(entry[0]) in (int, float):
                            rows_inbound.append((ticket, destination_hash, float(entry[0])))

        if type(last_deliveries) == dict:
            for destination_hash, timestamp in last_deliveries.items():
                if type(destination_hash) == bytes and len(destination_hash) == self.DESTINATION_LENGTH and type(timestamp) in (int, float):
                    rows_deliveries.append((destination_hash, float(timestamp)))

        total    = len(rows_outbound)+len(rows_inbound)+len(rows_deliveries)
        imported = -1
        with self._conn_lock:
            if self._ready():
                try:
                    self._conn.execute("BEGIN")
                    for i in range(0, len(rows_outbound),   self.IMPORT_CHUNK): self._conn.executemany("INSERT OR IGNORE INTO tickets_outbound (destination_hash, expires, ticket) VALUES (?, ?, ?)", rows_outbound[i:i+self.IMPORT_CHUNK])
                    for i in range(0, len(rows_inbound),    self.IMPORT_CHUNK): self._conn.executemany("INSERT OR IGNORE INTO tickets_inbound (ticket, destination_hash, expires) VALUES (?, ?, ?)", rows_inbound[i:i+self.IMPORT_CHUNK])
                    for i in range(0, len(rows_deliveries), self.IMPORT_CHUNK): self._conn.executemany("INSERT OR IGNORE INTO ticket_deliveries (destination_hash, timestamp) VALUES (?, ?)", rows_deliveries[i:i+self.IMPORT_CHUNK])
                    self._conn.execute("COMMIT")
                    imported = total

                except Exception as e:
                    RNS.log(f"Could not import available tickets file at {path} into store. The contained exception was: {e}", RNS.LOG_ERROR)
                    try: self._conn.execute("ROLLBACK")
                    except Exception: pass

        if imported >= 0:
            try: os.replace(path, path+".imported")
            except Exception as e: RNS.log(f"Could not mark legacy file {path} as imported: {e}", RNS.LOG_WARNING)
            RNS.log(f"Imported {imported} entries from {os.path.split(path)[-1]} into store in {RNS.prettyshorttime(time.time()-st)}", RNS.LOG_VERBOSE)

        return imported
