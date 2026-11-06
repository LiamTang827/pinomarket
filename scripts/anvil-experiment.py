#!/usr/bin/env python3
"""Run the Pinomarket AMM experiment on a fresh loopback-only Anvil chain."""

import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import platform
import random
import re
import resource
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
CHAIN_ID = 31337
START_BALANCE = 1_000_000
BUY_AMOUNT = 100_000
NODES = 5
WINDOW_BLOCKS = 12
BLOCK_INTERVAL = "300ms"
EXECUTE = "executeBatch(uint256,bytes32,(address,bool,uint256,uint256,uint256)[],bytes[])"
SWAP = "swap(bool,uint256,uint256)"
OWNERS = ("alice", "bob", "carol")
MEASURED_ROUTES = ("/submit", "/gossip", "/open", "/aion/prove", "/aion/calibrate",
                   "/aion/challenge", "/aion/vote", "/evm/sign-batch")
COUNTERS = ("requests", "request_body_bytes", "response_body_bytes", "failures")
PROTOCOL = "application HTTP body counts only; excludes CometBFT, headers and transport bytes"
LOCAL_HTTP = build_opener(ProxyHandler({}))


def run(*args):
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT, text=True,
                            capture_output=True, timeout=150)
    if result.returncode:
        raise RuntimeError(f"{' '.join(str(arg) for arg in args)}\n{result.stdout}{result.stderr}")
    return result.stdout.strip()


def must(condition, message):
    if not condition:
        raise RuntimeError(message)


def read_json(path):
    return json.loads(path.read_text())


def save_json(path, value):
    pending = path.with_suffix(path.suffix + ".tmp")
    pending.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    pending.replace(path)


def read_http(url, payload=None):
    headers = {"Content-Type": "application/json"}
    data = None if payload is None else json.dumps(payload).encode()
    must(url.startswith("http://127.0.0.1:"), "Experiment RPC and HTTP must stay on loopback")
    with LOCAL_HTTP.open(Request(url, data=data, headers=headers), timeout=5) as response:
        return response.read()


def get_json(url, payload=None):
    return json.loads(read_http(url, payload))


def elapsed_ms(start):
    return round((time.perf_counter() - start) * 1_000, 3)


def ms_between(start, end):
    return round((end - start) * 1_000, 3)


def child_cpu_ms():
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (usage.ru_utime + usage.ru_stime) * 1_000


def reserve_ports(offsets):
    """Find a free loopback port range for this isolated run."""
    for _ in range(100):
        with ExitStack() as stack:
            port = random.randrange(16000, 45000)
            try:
                for offset in offsets:
                    listener = stack.enter_context(socket.socket())
                    listener.bind(("127.0.0.1", port + offset))
            except OSError:
                continue
            return port
    raise RuntimeError("No free local range for the experiment")


def start_process(stack, log, *args):
    handle = stack.enter_context(log.open("w"))
    process = subprocess.Popen([str(arg) for arg in args], cwd=ROOT, stdout=handle,
                               stderr=subprocess.STDOUT)

    def stop():
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=8)

    stack.callback(stop)
    return process


class Anvil:
    def __init__(self, stack, log):
        port = reserve_ports([0])
        self.url = f"http://127.0.0.1:{port}"
        process = start_process(stack, log, "anvil", "--host", "127.0.0.1", "--port", port,
                                "--chain-id", CHAIN_ID, "--no-mining", "--order", "fees")
        for _ in range(100):
            try:
                chain_id = self.rpc("eth_chainId")
            except OSError:
                if process.poll() is not None:
                    break
                time.sleep(0.05)
                continue
            must(int(chain_id, 16) == CHAIN_ID, "Unexpected chain ID")
            self.accounts = self.rpc("eth_accounts")
            must(len(self.accounts) >= 3, "Missing Anvil dev accounts")
            return
        raise RuntimeError(f"Anvil could not start. See {log}")

    def rpc(self, method, *params):
        response = get_json(self.url, {"jsonrpc": "2.0", "id": 1, "method": method,
                                      "params": params})
        if "error" in response:
            raise RuntimeError(f"{method}: {response['error']}")
        return response["result"]

    def send(self, sender, data, target=None, tip=2, gas=2_000_000):
        tx = {"from": sender, "data": data, "gas": hex(gas),
              "maxFeePerGas": hex((10 + tip) * 10**9), "maxPriorityFeePerGas": hex(tip * 10**9),
              "nonce": self.rpc("eth_getTransactionCount", sender, "pending")}
        if target:
            tx["to"] = target
        return self.rpc("eth_sendTransaction", tx)

    def mine(self):
        self.rpc("evm_mine")

    def receipt(self, tx, success=True):
        receipt = self.rpc("eth_getTransactionReceipt", tx)
        must(receipt is not None, f"Transaction {tx} was not mined")
        status = int(receipt["status"], 16)
        must(status == int(success), f"Unexpected status {status} for {tx}")
        gas = int(receipt["gasUsed"], 16)
        price = int(receipt["effectiveGasPrice"], 16)
        return {"tx_hash": tx, "status": status, "block_number": int(receipt["blockNumber"], 16),
                "tx_index": int(receipt["transactionIndex"], 16), "gas_used": gas,
                "effective_gas_price_wei": price, "transaction_fee_wei": gas * price,
                "logs": receipt["logs"], "contract_address": receipt["contractAddress"]}

    def deploy(self, sender, name, traders, signers=None, quorum=None):
        args = [array(traders)]
        constructor = "constructor(address[])"
        if signers is not None:
            constructor = "constructor(address[],address[],uint256)"
            args.extend((array(signers), quorum))
        artifact = ROOT / "evm" / "out" / "Market.sol" / f"{name}.json"
        bytecode = read_json(artifact)["bytecode"]["object"]
        encoded = run("cast", "abi-encode", constructor, *args)
        tx = self.send(sender, bytecode + encoded[2:], gas=8_000_000)
        self.mine()
        receipt = self.receipt(tx)
        return receipt["contract_address"], receipt

    def uint(self, market, signature, *args):
        data = calldata(signature, *args)
        value = self.rpc("eth_call", {"to": market, "data": data}, "latest")
        return int(value, 16)


def array(values):
    return "[" + ",".join(map(str, values)) + "]"


def calldata(signature, *args):
    return run("cast", "calldata", signature, *args)


def abi_bool(value):
    return "true" if value else "false"


def batch_calldata(batch, orders=None, signatures=None):
    orders = batch["orders"] if orders is None else orders
    signatures = batch["signatures"] if signatures is None else signatures
    tuples = [f"({o['trader']},{abi_bool(o['buy'])},{o['amount_in']},{o['min_out']},{o['nonce']})"
              for o in orders]
    return calldata(EXECUTE, batch["number"], batch["lock_id"], array(tuples), array(signatures))


def pool_state(chain, market, traders):
    return {
        "reserve_quote": chain.uint(market, "reserveQuote()"),
        "reserve_asset": chain.uint(market, "reserveAsset()"),
        "traders": {name: {"quote": chain.uint(market, "quoteBalance(address)", address),
                           "asset": chain.uint(market, "assetBalance(address)", address)}
                    for name, address in traders.items()},
    }


def direct_case(chain, ordering, count=None):
    """Queue prearranged, fee-prioritized transactions in a local node."""
    traders = dict(zip(OWNERS, chain.accounts))
    market, deployment = chain.deploy(chain.accounts[0], "DirectMarket", traders.values())
    before = pool_state(chain, market, traders)
    records = []
    submit_times = {}
    first_submission = None
    pending_seen = None
    if ordering == "workload":
        plan = [(f"order_{i + 1}", OWNERS[i % 3], True, BUY_AMOUNT, 4) for i in range(count)]
    else:
        # Submit Alice first in all three cases. Fees determine the mined order.
        plan = [("alice_buy", "alice", True, BUY_AMOUNT, 3)]
        if ordering in ("front_run", "sandwich"):
            plan.append(("bob_buy", "bob", True, BUY_AMOUNT, 4))
        if ordering == "sandwich":
            bob_output = START_BALANCE * BUY_AMOUNT // (START_BALANCE + BUY_AMOUNT)
            plan.append(("bob_sell", "bob", False, bob_output, 2))

    encoded = [calldata(SWAP, abi_bool(buy), amount, 0) for _, _, buy, amount, _ in plan]
    for (label, owner, buy, amount, tip), data in zip(plan, encoded):
        started = time.perf_counter()
        if first_submission is None:
            first_submission = started
        tx = chain.send(traders[owner], data, market, tip)
        submit_times[label] = started
        records.append({"label": label, "owner": owner, "amount_in": amount, "buy": buy,
                        "tip_gwei": tip, "tx_hash": tx, "calldata_bytes": (len(data) - 2) // 2,
                        "rpc_ack_ms": elapsed_ms(started)})
        if label == "alice_buy":
            pending = chain.rpc("eth_getTransactionByHash", tx)
            must(pending["blockNumber"] is None and pending["input"] == data,
                 "Alice plaintext swap was not observable as a pending local transaction")
            pending_seen = {"tx_hash": tx, "input": pending["input"], "block_number": None}

    chain.mine()
    receipts = []
    for record in records:
        receipt = chain.receipt(record["tx_hash"])
        received = time.perf_counter()
        receipts.append({**record, **receipt,
                         "submission_to_receipt_ms": ms_between(submit_times[record["label"]], received)})
    settled = time.perf_counter()
    receipts.sort(key=lambda receipt: receipt["tx_index"])
    must(len({r["block_number"] for r in receipts}) == 1, "Direct swaps spanned multiple blocks")
    if ordering != "workload":
        expected = {
            "control": ["alice_buy"],
            "front_run": ["bob_buy", "alice_buy"],
            "sandwich": ["bob_buy", "alice_buy", "bob_sell"],
        }
        observed = [r["label"] for r in receipts]
        must(observed == expected[ordering], f"Unexpected {ordering} order: {observed}")
    after = pool_state(chain, market, traders)
    if ordering == "sandwich":
        must(after["traders"]["bob"]["asset"] == 0 and after["traders"]["bob"]["quote"] > START_BALANCE,
             "The sandwich fixture did not realize a quote-token gain and fully exit")
    total_gas = sum(r["gas_used"] for r in receipts)
    return {
        "contract": market, "deployment": deployment, "before": before, "after": after,
        "alice_asset_received": after["traders"]["alice"]["asset"],
        "bob_quote_delta_before_gas": after["traders"]["bob"]["quote"] - START_BALANCE,
        "alice_observed_pending": pending_seen, "receipts_in_block_order": receipts,
        "order_count": len(receipts), "execution_gas": total_gas,
        "execution_gas_per_order": round(total_gas / len(receipts), 3),
        "evm_swap_calldata_bytes_total": sum(r["calldata_bytes"] for r in receipts),
        "wall_ms_first_submission_to_last_receipt": ms_between(first_submission, settled),
        "orders_per_second": round(len(receipts) / (settled - first_submission), 3),
    }


def wait_for_peer_states(manifest, ready, quorum, error):
    deadline = time.perf_counter() + 20
    while time.perf_counter() < deadline:
        processed = 0
        for peer in manifest["peers"]:
            state = get_json(peer["api"] + "/state")
            if ready(state):
                processed += 1
        if processed >= quorum:
            return
        time.sleep(0.05)
    raise RuntimeError(error)


def app_metrics(manifest):
    return {peer["id"]: get_json(peer["api"] + "/metrics")["http"] for peer in manifest["peers"]}


def summarize_http(before, after):
    per_node = {}
    total = {route: {key: 0 for key in COUNTERS} for route in MEASURED_ROUTES}
    for node, route_after in after.items():
        per_node[node] = {}
        for route in MEASURED_ROUTES:
            delta = {key: route_after[route][key] - before[node][route][key] for key in COUNTERS}
            must(all(value >= 0 for value in delta.values()), "Application HTTP counter reset")
            per_node[node][route] = delta
            for key, count in delta.items():
                total[route][key] += count
    return {"by_node_and_route": per_node, "by_route": total,
            "body_bytes_total": sum(row["request_body_bytes"] + row["response_body_bytes"]
                                    for row in total.values()), "scope": PROTOCOL}


def configure_comet_metrics(directory, base):
    endpoints = []
    for index in range(NODES):
        config = directory / "consensus" / f"node{index}" / "config" / "config.toml"
        content = config.read_text()
        enabled = content.replace("prometheus = false", "prometheus = true", 1)
        must(enabled != content, "Missing CometBFT Prometheus enable flag")
        address = f"127.0.0.1:{base + index}"
        enabled, changes = re.subn(r'(?m)^prometheus_listen_addr = "[^"]+"$',
                                   f'prometheus_listen_addr = "{address}"', enabled, count=1)
        must(changes == 1, "Missing CometBFT Prometheus listener setting")
        config.write_text(enabled)
        endpoints.append(f"http://{address}/metrics")
    return endpoints


def comet_metrics(endpoints):
    nodes = []
    for endpoint in endpoints:
        text = read_http(endpoint).decode()
        channels = {}
        cpu = None
        for line in text.splitlines():
            message = re.match(r'\w+_p2p_peer_send_bytes_total\{([^}]+)\} (\S+)', line)
            if message:
                channel = re.search(r'chID="([^"]+)"', message[1])[1]
                channels[channel] = channels.get(channel, 0) + int(float(message[2]))
            if line.startswith("process_cpu_seconds_total "):
                cpu = float(line.split()[1])
        nodes.append({"channels": channels, "process_cpu_seconds": cpu})
    return nodes


def summarize_comet(before, after):
    channels = {}
    for start, end in zip(before, after):
        for channel, value in end["channels"].items():
            delta = value - start["channels"].get(channel, 0)
            must(delta >= 0, "CometBFT P2P byte counter reset")
            channels[channel] = channels.get(channel, 0) + delta
    must(sum(channels.values()) > 0, "No CometBFT peer-send counter delta was observed")
    cpu_ms = None
    if all(node["process_cpu_seconds"] is not None for node in before + after):
        cpu_ms = round(sum(end["process_cpu_seconds"] - start["process_cpu_seconds"]
                           for start, end in zip(before, after)) * 1_000, 3)
    return {"sent_message_bytes_by_channel": channels, "sent_message_bytes_total": sum(channels.values()),
            "validator_process_cpu_ms_total": cpu_ms,
            "scope": "CometBFT per-peer outgoing message payload, including idle consensus; "
                     "excludes transport framing, retransmits, RPC and receive counters."}


def denied_attempts(chain, market, batch, traders):
    attacker = chain.accounts[1]
    relay = chain.accounts[0]
    orders = batch["orders"]
    fake_buy = {"trader": traders["bob"], "buy": True, "amount_in": BUY_AMOUNT,
                "min_out": 0, "nonce": 0}
    fake_sell = {**fake_buy, "buy": False, "amount_in": 90_909, "nonce": 1}
    variants = {
        "direct_buy": (attacker, calldata(SWAP, "true", BUY_AMOUNT, 0)),
        "direct_sell": (attacker, calldata(SWAP, "false", 90_909, 0)),
        "insertion_with_original_signatures":
            (relay, batch_calldata(batch, [fake_buy, *orders, fake_sell])),
        "unsigned_sandwich":
            (attacker, batch_calldata(batch, [fake_buy, *orders, fake_sell], signatures=[])),
    }
    variants["duplicate_signer"] = (relay, batch_calldata(
        batch, signatures=[batch["signatures"][0]] * len(batch["signatures"])))
    if len(orders) > 1:
        variants["reorder_with_original_signatures"] = (
            relay, batch_calldata(batch, list(reversed(orders))))
        variants["drop_with_original_signatures"] = (relay, batch_calldata(batch, orders[1:]))
    before = pool_state(chain, market, traders)
    pending = {label: chain.send(sender, data, market) for label, (sender, data) in variants.items()}
    chain.mine()
    result = {label: chain.receipt(tx, success=False) for label, tx in pending.items()}
    must(pool_state(chain, market, traders) == before, "Rejected actions changed market state")
    return result


def protected_case(chain, binary, private_dir, count, adversarial=False):
    directory = private_dir / "network"
    base = reserve_ports([0, 1, 10, 11, 20, 21, 30, 31, 40, 41, 100, 101, 102, 103, 104, 120, 121, 122, 123, 124])
    run(binary, "network", "init", "-dir", directory, "-evm", "-nodes", NODES, "-threshold", 3,
        "-queue-capacity", 30, "-service-capacity", 6, "-base-port", base, "-api-port", base + 100,
        "-window-blocks", WINDOW_BLOCKS, "-block-interval", BLOCK_INTERVAL,
        "-ordering", "aion", "-ingress", "software")
    manifest = read_json(directory / "manifest.json")
    metrics_endpoints = configure_comet_metrics(directory, base + 120)
    config = json.loads(run(binary, "network", "evm-config", "-dir", directory))
    traders = {owner: config["traders"][owner] for owner in OWNERS}
    relay = chain.accounts[0]
    market, deployment = chain.deploy(relay, "BatchMarket", traders.values(),
                                      config["signers"], config["quorum"])
    before = pool_state(chain, market, traders)
    with ExitStack() as nodes:
        for i in range(NODES):
            start_process(nodes, private_dir / f"node{i}.log", binary, "network", "node",
                          "-config", directory / f"node{i}.json")
        run(binary, "network", "ready", "-dir", directory, "-timeout", "60s")
        early_batch_status = None
        if adversarial:
            try:
                get_json(manifest["peers"][0]["api"] + "/evm/sign-batch?number=1")
            except HTTPError as error:
                early_batch_status = error.code
                error.close()
            must(early_batch_status == 409, "Validator signed a batch before it completed")
        http_before = app_metrics(manifest)
        comet_before = comet_metrics(metrics_endpoints)
        open_started = time.perf_counter()
        round_info = json.loads(run(binary, "network", "open", "-dir", directory))
        wait_for_peer_states(manifest,
                             lambda state: (state.get("round") or {}).get("number") == round_info["number"],
                             NODES, "Some validators did not observe the open admission round")
        open_ms = elapsed_ms(open_started)
        submissions = []
        for i in range(count):
            owner, nonce = OWNERS[i % 3], i // 3
            receipt_path = private_dir / f"submission-{i + 1}.json"
            started = time.perf_counter()
            cpu_started = child_cpu_ms()
            run(binary, "network", "submit", "-dir", directory, "-owner", owner, "-nonce", nonce,
                "-kind", "buy", "-listing", f"evm:{CHAIN_ID}:{market}", "-quantity", BUY_AMOUNT,
                "-limit", 0, "-out", receipt_path, "-timeout", "30s")
            client_cpu_ms = round(child_cpu_ms() - cpu_started, 3)
            ack = elapsed_ms(started)
            receipt = read_json(receipt_path)
            must(receipt["quorum_obtained"], f"Submission {i + 1} did not reach admission quorum")
            submissions.append((started, {"owner": owner, "nonce": nonce, "rpc_ack_ms": ack,
                                           "client_command_cpu_ms": client_cpu_ms,
                                           "promise_quorum_ms": receipt.get("quorum_ms"),
                                           "signed_promises": len(receipt["promises"])}))
        wait_started = time.perf_counter()
        run(binary, "network", "wait", "-dir", directory, "-processed", count, "-timeout", "90s")
        go_ready_at = time.perf_counter()
        wait_for_peer_states(manifest, lambda state: len(state.get("results") or []) >= count,
                             config["quorum"], "A quorum did not process the service batch")
        batch_started = time.perf_counter()
        batch = json.loads(run(binary, "network", "evm-batch", "-dir", directory,
                               "-number", 1, "-timeout", "60s"))
        batch_ready_at = time.perf_counter()
        must(batch["contract"].lower() == market.lower(), "Go certified a different market")
        must(len(batch["orders"]) == count, "Unexpected number of certified orders")
        must(len(batch["signatures"]) >= config["quorum"], "Missing batch signature quorum")
        data = batch["calldata"]
        must(data.lower() == batch_calldata(batch).lower(), "Go and Cast calldata disagree")
        denied = denied_attempts(chain, market, batch, traders) if adversarial else {}
        settle_started = time.perf_counter()
        tx = chain.send(relay, data, market, gas=8_000_000)
        chain.mine()
        settlement = chain.receipt(tx)
        settled = time.perf_counter()
        swap_topic = run("cast", "keccak", "Swapped(address,bool,uint256,uint256)").lower()
        applied = []
        for log in settlement["logs"]:
            if log["topics"][0].lower() == swap_topic:
                event_data = log["data"][2:]
                applied.append({
                    "trader": "0x" + log["topics"][1][-40:],
                    "buy": bool(int(event_data[:64], 16)),
                    "amount_in": int(event_data[64:128], 16),
                    "amount_out": int(event_data[128:192], 16),
                })
        must([(o["trader"].lower(), o["buy"], o["amount_in"]) for o in applied] ==
             [(o["trader"].lower(), o["buy"], o["amount_in"]) for o in batch["orders"]],
             "On-chain swaps did not follow the certified list in order")
        traffic = summarize_http(http_before, app_metrics(manifest))
        consensus = summarize_comet(comet_before, comet_metrics(metrics_endpoints))
        audit = json.loads(run(binary, "network", "audit", "-dir", directory, "-timeout", "60s"))
        after = pool_state(chain, market, traders)
        must(chain.uint(market, "nextBatch()") == 2 and
             chain.uint(market, "executedLock(bytes32)", batch["lock_id"]) == 1,
             "EVM batch sequence or lock marker was not updated")
        if adversarial:
            replay = chain.send(relay, data, market)
            chain.mine()
            denied["replay_finalized_batch"] = chain.receipt(replay, success=False)
            must(pool_state(chain, market, traders) == after, "Replaying a batch changed market state")
    must(all(after["traders"][o]["quote"] == START_BALANCE -
             BUY_AMOUNT * sum(entry["owner"] == o for _, entry in submissions) for o in OWNERS),
         "Certified batch did not apply all expected swaps")
    return {
        "contract": market, "deployment": deployment, "before": before, "after": after,
        "alice_asset_received": after["traders"]["alice"]["asset"],
        "bob_quote_delta_before_gas": after["traders"]["bob"]["quote"] - START_BALANCE,
        "round": round_info, "validator_count": NODES, "signing_quorum": config["quorum"],
        "decryption_threshold": 3, "application_http": traffic, "comet_p2p": consensus,
        "go_audit": audit,
        "go_batch": {key: batch[key] for key in ("number", "lock_id", "digest", "orders", "signatures",
                                                "contract", "signers", "go_timings") if key in batch},
        "order_count": count, "submission_records": [
            {**info, "submission_to_receipt_ms": ms_between(started, settled)}
            for started, info in submissions],
        "phase_ms": {"open_round": open_ms, "after_submits_until_go_processed":
                     ms_between(wait_started, go_ready_at), "go_batch_quorum_convergence":
                     ms_between(go_ready_at, batch_started), "go_batch_certificate":
                     ms_between(batch_started, batch_ready_at), "anvil_batch_submit_and_receipt":
                     ms_between(settle_started, settled)},
        "wall_ms_first_submission_to_last_receipt": ms_between(submissions[0][0], settled),
        "orders_per_second": round(count / (settled - submissions[0][0]), 3),
        "execution_gas": settlement["gas_used"],
        "execution_gas_per_order": round(settlement["gas_used"] / count, 3),
        "evm_batch_calldata_bytes": (len(data) - 2) // 2,
        "settlement_receipt": settlement, "settlement_swap_events": applied,
        "pre_lock_batch_signing_http_status": early_batch_status,
        "rejected_attempt_receipts": denied,
    }


def aggregate(trials):
    def percentiles(values):
        ordered = sorted(values)
        return {f"p{p}": ordered[math.ceil(p / 100 * len(ordered)) - 1] for p in (50, 95)}

    summary = {}
    for variant in ("direct", "protected"):
        by_count = {}
        for case in trials:
            by_count.setdefault(case[variant]["order_count"], []).append(case[variant])
        summary[variant] = {}
        for count, measurements in sorted(by_count.items()):
            record_key = "submission_records" if variant == "protected" else "receipts_in_block_order"
            latencies = [r["submission_to_receipt_ms"] for m in measurements for r in m[record_key]]
            rows = {
                "runs": len(measurements), "latency_samples": len(latencies),
                "submission_to_receipt_ms": percentiles(latencies),
                "orders_per_second": percentiles([m["orders_per_second"] for m in measurements]),
                "gas_per_order": percentiles([m["execution_gas_per_order"] for m in measurements]),
            }
            if variant == "protected":
                rows["application_http_body_bytes"] = percentiles(
                    [m["application_http"]["body_bytes_total"] for m in measurements])
                rows["comet_sent_message_bytes"] = percentiles(
                    [m["comet_p2p"]["sent_message_bytes_total"] for m in measurements])
                rows["evm_calldata_bytes"] = percentiles(
                    [m["evm_batch_calldata_bytes"] for m in measurements])
            else:
                rows["evm_calldata_bytes"] = percentiles(
                    [m["evm_swap_calldata_bytes_total"] for m in measurements])
            summary[variant][count] = rows
    return summary


def repeat_protected(chain, binary, work, label, count, results, output, adversarial=False):
    for attempt in (1, 2):
        directory = work / f"{label}-attempt-{attempt}"
        directory.mkdir()
        try:
            return protected_case(chain, binary, directory, count, adversarial)
        except RuntimeError as error:
            if "Aion calibration quorum unavailable" not in str(error):
                raise
            results["transient_failures"].append({
                "case": label, "attempt": attempt, "orders_requested": count,
                "reason": "Aion calibration quorum unavailable",
            })
            save_json(output, results)
            if attempt == 2:
                raise
            print(f"{label}: Aion calibration unavailable, trying a fresh network", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "runs" / "anvil-experiment.json")
    parser.add_argument("--workloads", type=int, nargs="+", default=[1, 3, 6], choices=range(1, 7))
    parser.add_argument("--repeats", type=int, default=1)
    parser.add_argument("--pinocchio", type=Path, help="Use this prebuilt Go CLI")
    build = parser.add_mutually_exclusive_group()
    build.add_argument("--solc", type=Path, help="Use an installed Solidity 0.8.24 executable")
    build.add_argument("--prebuilt-contracts", action="store_true",
                       help="Use existing evm/out/Market.sol artifacts instead of invoking Forge")
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error("--repeats must be positive")
    if len(set(args.workloads)) != len(args.workloads):
        parser.error("--workloads must not repeat sizes; use --repeats")
    programs = ["anvil", "cast"] if args.prebuilt_contracts else ["anvil", "cast", "forge"]
    for program in programs:
        if shutil.which(program) is None:
            parser.error(f"{program} must be on PATH")
    output = args.output.resolve()
    if output.exists():
        parser.error(f"{output} already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Node keys, Anvil keys in logs and temporary submission evidence stay in a private directory.
    with tempfile.TemporaryDirectory(prefix="pinomarket-anvil-run-") as temp, ExitStack() as stack:
        work = Path(temp)
        binary = args.pinocchio.resolve() if args.pinocchio else work / "pinocchio"
        if not args.pinocchio:
            run(ROOT / "scripts" / "go.sh", "build", "-o", binary, "./cmd/pinocchio")
        if not args.prebuilt_contracts:
            compiler = ["--offline", "--use", args.solc.resolve()] if args.solc else []
            run("forge", "build", *compiler)
        chain = Anvil(stack, work / "anvil.log")
        attacks, trials = {}, []
        results = {
            "schema_version": 1, "status": "partial", "created_utc": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(), "logical_cpu_count": os.cpu_count(),
            "tool_versions": {program: run(program, "--version") for program in programs},
            "contract_build": "prebuilt artifacts" if args.prebuilt_contracts else "forge build",
            "chain_id": CHAIN_ID, "topology": "Single host, loopback; five Go/CometBFT processes",
            "config": {"window_blocks": WINDOW_BLOCKS, "block_interval": BLOCK_INTERVAL,
                       "fee_model": "zero AMM fee, local EIP-1559 dev-chain gas",
                       "transaction_amount_in": BUY_AMOUNT, "start_quote_per_trader": START_BALANCE,
                       "start_reserve_each": START_BALANCE, "workloads": args.workloads,
                       "repeats": args.repeats},
            "attack_cases": attacks, "workload_trials": trials, "workload_summary": {},
            "transient_failures": [],
            "measurement_limits": [
                "Prearranged synthetic transactions on Anvil only. No connection to public pools.",
                "Manual mining removes natural EVM block intervals and finality from the measurements.",
                "Protected latency includes the Go registration and service flow, CLI and loopback "
                "overhead. Adversarial cases are separate from timing summaries.",
                "Orders are submitted serially. Observed orders/s is finite-batch service rate, "
                "not a saturated throughput limit.",
                "Application HTTP, CometBFT outgoing message payload and EVM calldata are measured "
                "separately. They do not sum to wire traffic.",
                "Gas prices are synthetic. Bob's quote-token gain and ETH fees use different units.",
                "Software ingress is a clock/signing mock; this experiment does not measure TEE or TNIC.",
                "Latency quantiles use the nearest-rank method; small runs have unstable p95.",
                "A fresh local trial is attempted once after a calibration quorum failure. "
                "Throughput and latency summaries include completed trials, and failures are recorded separately.",
            ],
        }
        for name in ("control", "front_run", "sandwich"):
            attacks[name] = direct_case(chain, name)
        must(attacks["front_run"]["alice_asset_received"] < attacks["control"]["alice_asset_received"],
             "Front-run ordering did not harm Alice relative to the control")
        must(attacks["sandwich"]["alice_asset_received"] == attacks["front_run"]["alice_asset_received"],
             "Alice's output differs across fixtures with the same two leading swaps")
        save_json(output, results)
        attacks["protected"] = repeat_protected(chain, binary, work, "protected-attacks",
                                                1, results, output, adversarial=True)
        must(attacks["protected"]["alice_asset_received"] == attacks["control"]["alice_asset_received"]
             and attacks["protected"]["bob_quote_delta_before_gas"] == 0,
             "Rejected insertion changed the protected outcome")
        save_json(output, results)
        attacks["protected_reorder"] = repeat_protected(chain, binary, work, "protected-reorder",
                                                        3, results, output, adversarial=True)
        save_json(output, results)
        for repeat in range(1, args.repeats + 1):
            for count in args.workloads:
                direct = direct_case(chain, "workload", count)
                protected = repeat_protected(chain, binary, work, f"workload-{repeat}-{count}",
                                             count, results, output)
                trials.append({"repeat": repeat, "direct": direct, "protected": protected})
                results["workload_summary"] = aggregate(trials)
                save_json(output, results)
                print(f"run {repeat}, {count} orders: direct {direct['execution_gas']} gas, "
                      f"protected {protected['execution_gas']} gas", flush=True)
        results["status"] = "complete"
        save_json(output, results)
        print(output)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"experiment failed: {error}", file=sys.stderr)
        sys.exit(1)
