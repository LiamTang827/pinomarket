"""Bounded local protocol overhead samples; no models and no saturation claim.

P2P bytes are CometBFT's delimited MConnection packets, sampled by flowrate.
HTTP bytes are completed server handlers' bodies, with protocol and observers
separated. Neither is a TCP/IP capture. Audit and local CPU microbenchmarks run
after the workload's final snapshots. Raw network directories contain demo keys.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import random
import socket
import subprocess
import threading
import time
import urllib.request
import urllib.parse

PROTOCOL_ROUTES = ('/submit', '/gossip', '/open')
OBSERVER_ROUTES = ('/state', '/health')


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write('\n')


def request(url, timeout=3):
    # All samples are local. macOS/system proxies must never handle these reads.
    parsed = urllib.parse.urlsplit(url)
    host = parsed.hostname
    try:
        loopback = host == 'localhost' or ipaddress.ip_address(host).is_loopback
        valid_port = parsed.port is not None and 1 <= parsed.port <= 65535
    except (TypeError, ValueError):
        loopback, valid_port = False, False
    if parsed.scheme != 'http' or not loopback or not valid_port or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('measurement requests require a plain loopback HTTP URL')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=timeout) as response:
            return json.load(response)
    except Exception as error:
        raise RuntimeError('local request failed: ' + url + ': ' + type(error).__name__ + ': ' + str(error)) from error


def numeric(value, name):
    if isinstance(value, bool):
        raise ValueError(name + ' must be a nonnegative integer')
    result = int(value)
    if result < 0 or str(result) != str(value):
        raise ValueError(name + ' must be a nonnegative integer')
    return result


def net_connections(net):
    """Preserve directed sends: never add receiver counters to this total."""
    value = net.get('result', net)
    if not isinstance(value.get('peers'), list):
        raise ValueError('missing CometBFT peer list')
    result = {}
    for peer in value['peers']:
        identity = peer['node_info']['id']
        if identity in result:
            raise ValueError('duplicate peer identity')
        status = peer['connection_status']
        monitor = status['SendMonitor']
        result[identity] = {
            'bytes': numeric(monitor['Bytes'], 'SendMonitor.Bytes'),
            'start': monitor['Start'],
            'duration_ns': numeric(status['Duration'], 'connection Duration'),
        }
    return result


def p2p_delta(before, after):
    left, right = net_connections(before), net_connections(after)
    if left.keys() != right.keys():
        raise ValueError('peer set changed during measurement')
    total = 0
    for identity, old in left.items():
        new = right[identity]
        if old['start'] != new['start'] or new['duration_ns'] < old['duration_ns']:
            raise ValueError('peer connection restarted: ' + identity)
        if new['bytes'] < old['bytes']:
            raise ValueError('P2P counter decreased: ' + identity)
        total += new['bytes'] - old['bytes']
    return total


def http_delta(before, after):
    if before.get('schema') != 1 or after.get('schema') != 1:
        raise ValueError('unsupported telemetry schema')
    for name in ('node', 'process_started_at'):
        if not before.get(name) or before[name] != after.get(name):
            raise ValueError('node telemetry identity/restart mismatch')
    result = {}
    for route in PROTOCOL_ROUTES + OBSERVER_ROUTES:
        a, b = before['http'][route], after['http'][route]
        row = {}
        for name in ('requests', 'request_body_bytes', 'response_body_bytes', 'failures'):
            row[name] = numeric(b[name], name) - numeric(a[name], name)
            if row[name] < 0:
                raise ValueError('HTTP counter decreased: ' + route)
        row['handler_ms_total'] = float(b['handler_ms_total']) - float(a['handler_ms_total'])
        if row['handler_ms_total'] < 0:
            raise ValueError('handler elapsed counter decreased')
        statuses = set(a.get('status_codes', {})) | set(b.get('status_codes', {}))
        row['status_codes'] = {
            s: numeric(b.get('status_codes', {}).get(s, 0), 'status count') -
               numeric(a.get('status_codes', {}).get(s, 0), 'status count')
            for s in statuses}
        if any(v < 0 for v in row['status_codes'].values()):
            raise ValueError('status counter decreased')
        result[route] = row
    return result


def interval_cost(before, after):
    if before['nodes'].keys() != after['nodes'].keys():
        raise ValueError('sampled node set changed')
    sent = 0
    routes = {r: {'requests': 0, 'request_body_bytes': 0, 'response_body_bytes': 0,
                  'failures': 0, 'handler_ms_total': 0.0, 'status_codes': {}}
              for r in PROTOCOL_ROUTES + OBSERVER_ROUTES}
    for node, a in before['nodes'].items():
        b = after['nodes'][node]
        sent += p2p_delta(a['net_info'], b['net_info'])
        for route, row in http_delta(a['telemetry'], b['telemetry']).items():
            for key in ('requests', 'request_body_bytes', 'response_body_bytes', 'failures', 'handler_ms_total'):
                routes[route][key] += row[key]
            for status, count in row['status_codes'].items():
                routes[route]['status_codes'][status] = routes[route]['status_codes'].get(status, 0) + count
    protocol = sum(routes[r]['request_body_bytes'] + routes[r]['response_body_bytes'] for r in PROTOCOL_ROUTES)
    observer = sum(routes[r]['request_body_bytes'] + routes[r]['response_body_bytes'] for r in OBSERVER_ROUTES)
    return {'p2p_mconnection_sent_bytes': sent,
            'protocol_http_body_bytes': protocol,
            'observer_http_body_bytes': observer,
            'measured_layered_protocol_bytes': sent + protocol,
            'http_routes': routes}


def parse_cpu_time(value):
    """ps TIME: [[days-]hours:]minutes:seconds, including decimal seconds."""
    days, body = (value.split('-', 1) if '-' in value else ('0', value))
    parts = body.split(':')
    if len(parts) == 2:
        hours, minutes, seconds = 0, int(parts[0]), float(parts[1])
    elif len(parts) == 3:
        hours, minutes, seconds = int(parts[0]), int(parts[1]), float(parts[2])
    else:
        raise ValueError('unsupported ps CPU format')
    return int(days)*86400 + hours*3600 + minutes*60 + seconds


def process_sample(processes):
    result = {}
    for index, proc in enumerate(processes):
        if proc.poll() is not None:
            raise RuntimeError('node process exited: ' + str(index))
        data = subprocess.check_output(['ps', '-p', str(proc.pid), '-o', 'time=', '-o', 'rss='], text=True).strip().split()
        if len(data) != 2:
            raise RuntimeError('missing node resource sample')
        result[str(index)] = {'pid': proc.pid, 'cpu_seconds': parse_cpu_time(data[0]),
                              'rss_kib': numeric(data[1], 'RSS')}
    return result


def snapshot(peers):
    started = time.monotonic()
    def one(peer):
        begin = time.monotonic()
        telemetry = request(peer['api'] + '/metrics')
        net = request(peer['rpc'] + '/net_info')
        return peer['id'], {'telemetry': telemetry, 'net_info': net,
                            'started_monotonic_s': begin, 'finished_monotonic_s': time.monotonic()}
    with ThreadPoolExecutor(max_workers=len(peers)) as pool:
        nodes = dict(pool.map(one, peers))
    return {'started_monotonic_s': started, 'finished_monotonic_s': time.monotonic(), 'nodes': nodes}


def source_hashes(root):
    result = {}
    for dirname in ('protocol', 'internal/live', 'internal/consensus', 'threshold', 'harness'):
        for path in sorted((root/dirname).glob('*')):
            if path.suffix in ('.go', '.py'):
                result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def free_ports(n):
    for _ in range(100):
        base = random.SystemRandom().randrange(30000, 48000)
        api = base + 1500
        ports = [base+i*10+j for i in range(n) for j in (0, 1)] + [api+i for i in range(n)]
        sockets = []
        try:
            for port in ports:
                sock = socket.socket()
                sockets.append(sock)
                sock.bind(('127.0.0.1', port))
            return base, api
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    raise RuntimeError('cannot reserve local port ranges')


def run_command(binary, args, log, timeout):
    with open(log, 'w') as stream:
        completed = subprocess.run([str(binary), 'network'] + list(args), stdout=stream,
                                   stderr=subprocess.STDOUT, timeout=timeout)
    return completed.returncode


def stop_processes(processes):
    for proc in processes:
        if proc.poll() is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
    for proc in processes:
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            proc.wait(timeout=5)


class Observation:
    def __init__(self, peers, processes, interval):
        self.peers, self.processes, self.interval = peers, processes, interval
        self.stop = threading.Event()
        self.resources, self.states, self.networks, self.errors = [], [], [], []
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        while not self.stop.is_set():
            begin = time.monotonic()
            try:
                self.resources.append({'monotonic_s': time.monotonic(), 'nodes': process_sample(self.processes)})
                def state_for(peer):
                    return peer['id'], request(peer['api'] + '/state')
                with ThreadPoolExecutor(max_workers=len(self.peers)) as pool:
                    states = dict(pool.map(state_for, self.peers))
                self.states.append({'monotonic_s': time.monotonic(),
                                    'state': states[self.peers[0]['id']], 'nodes': states})
                self.networks.append(snapshot(self.peers))
            except Exception as error:
                self.errors.append({'monotonic_s': time.monotonic(), 'error': type(error).__name__ + ': ' + str(error)})
            self.stop.wait(max(0, self.interval - (time.monotonic()-begin)))

    def finish(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=12)
        if self.thread and self.thread.is_alive():
            raise RuntimeError('measurement observer did not terminate')


def observe_stages(orders, states, started, threshold):
    observed = []
    for order in orders:
        row = dict(order)
        oid, ref = row['id'], row['ref']
        for entry in states:
            state, ms = entry['state'], (entry['monotonic_s']-started)*1000
            if oid not in state.get('orders', {}):
                continue
            row.setdefault('registered_observed_at_ms', ms)
            locks = list(state.get('services') or [])
            if state.get('active_service'):
                locks.append(state['active_service'])
            for lock in locks:
                if oid in lock['items']:
                    row.setdefault('locked_observed_at_ms', ms)
                    if len(lock['shares'].get(oid, [])) >= threshold:
                        row.setdefault('shares_ready_observed_at_ms', ms)
            for result in state.get('results', []):
                if result['order'] == ref:
                    row.setdefault('processed_observed_at_ms', ms)
                    row['result'] = result
        if 'processed_observed_at_ms' in row:
            row['submit_to_processed_observed_ms'] = row['processed_observed_at_ms']-row['submission_started_at_ms']
        observed.append(row)
    return observed


def execute(args, n, repeat, mode, root):
    root.mkdir(mode=0o700)
    network, processes, logs = root/'network', [], []
    result = {'schema': 1, 'nodes': n, 'repeat': repeat, 'mode': mode,
              'requested_orders': args.orders, 'valid': False, 'errors': [],
              'configuration': {'queue_capacity': n*args.orders, 'service_capacity': 2,
                                'window_blocks': args.window_blocks,
                                'block_interval_ms': args.block_interval_ms,
                                'poll_interval_ms': args.poll_interval_ms,
                                'ai_enabled': False}}
    observer = None
    try:
        base, api = free_ports(n)
        code = run_command(args.binary, ['init', '-dir', str(network), '-nodes', str(n),
            '-queue-capacity', str(n*args.orders), '-service-capacity', '2',
            '-threshold', '3', '-window-blocks', str(args.window_blocks),
            '-block-interval', str(args.block_interval_ms)+'ms', '-base-port', str(base),
            '-api-port', str(api)], root/'init.log', args.timeout)
        if code:
            raise RuntimeError('network initialization failed')
        manifest = json.loads((network/'manifest.json').read_text())
        result['policy'] = manifest['policy']
        peers = manifest['peers']
        for i in range(n):
            stream = open(root/f'node{i}.log', 'w')
            logs.append(stream)
            command = [str(args.binary), 'network', 'node', '-config', str(network/f'node{i}.json')]
            if mode == 'omission' and i == 0:
                command.append('-omit-list')
            processes.append(subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT))
        code = run_command(args.binary, ['ready', '-dir', str(network), '-timeout', str(args.timeout)+'s'], root/'ready.log', args.timeout+5)
        if code:
            raise RuntimeError('network readiness failed')
        deadline = time.monotonic()+min(args.timeout, 30)
        while True:
            before = snapshot(peers)
            if all(len(net_connections(value['net_info'])) == n-1 for value in before['nodes'].values()):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('full peer mesh not established before measurement')
            time.sleep(.2)
        cpu_before = process_sample(processes)
        started = time.monotonic()
        result['interval_started_monotonic_s'] = started
        observer = Observation(peers, processes, args.poll_interval_ms/1000)
        observer.start()
        result['before'] = before
        code = run_command(args.binary, ['open', '-dir', str(network), '-timeout', str(args.timeout)+'s'], root/'open.log', args.timeout+5)
        if code:
            raise RuntimeError('opening admission round failed')
        round_info = json.loads((root/'open.log').read_text())
        round_number = round_info['number']
        orders = []
        for index in range(args.orders):
            owner, nonce = ('alice', 'bob', 'carol')[index%3], index//3
            packet = root/f'packet-{index}.json'
            prepare_started = time.monotonic()
            code = run_command(args.binary, ['prepare', '-dir', str(network), '-round', str(round_number),
                '-owner', owner, '-nonce', str(nonce), '-quantity', '1', '-out', str(packet)], root/f'prepare-{index}.log', args.timeout)
            if code:
                raise RuntimeError('order encryption preparation failed')
            prepared = json.loads(packet.read_text())
            row = {'id': prepared['packet_id'], 'ref': owner+':'+str(nonce),
                   'prepare_command_ms': (time.monotonic()-prepare_started)*1000,
                   'submission_started_at_ms': (time.monotonic()-started)*1000}
            receipt = root/f'receipt-{index}.json'
            code = run_command(args.binary, ['submit', '-dir', str(network), '-packet', str(packet),
                '-out', str(receipt), '-timeout', str(args.timeout)+'s'], root/f'submit-{index}.log', args.timeout+5)
            row['submission_command_ms'] = (time.monotonic()-started)*1000-row['submission_started_at_ms']
            row['submit_exit_code'] = code
            if receipt.exists():
                data = json.loads(receipt.read_text())
                row['quorum_obtained'] = bool(data.get('quorum_obtained'))
                row['promise_count'] = len(data.get('promises', []))
                row['receipt_quorum_ms'] = data.get('quorum_ms')
            orders.append(row)
        deadline = started+args.timeout
        while time.monotonic() < deadline:
            if observer.states and all(len(state.get('results', [])) >= args.orders for state in observer.states[-1]['nodes'].values()):
                break
            time.sleep(.05)
        observer.finish()
        after = snapshot(peers)
        cpu_after = process_sample(processes)
        finished = time.monotonic()
        result['after'] = after
        result['interval_finished_monotonic_s'] = finished
        result['interval_duration_ms'] = (finished-started)*1000
        result['observer_errors'] = observer.errors
        result['network_snapshot_count'] = len(observer.networks)+2
        snapshots = [before]+observer.networks+[after]
        # Validate all sampled intervals, including reconnects whose counters regrow.
        for left, right in zip(snapshots, snapshots[1:]):
            interval_cost(left, right)
        result['communication'] = interval_cost(before, after)
        resource_values = [cpu_before]+[sample['nodes'] for sample in observer.resources]+[cpu_after]
        result['resources'] = {
            'node_cpu_seconds': sum(cpu_after[str(i)]['cpu_seconds']-cpu_before[str(i)]['cpu_seconds'] for i in range(n)),
            'peak_sampled_aggregate_node_rss_kib': max(sum(v['rss_kib'] for v in sample.values()) for sample in resource_values),
            'sample_count': len(resource_values),
            'cpu_before': cpu_before, 'cpu_after': cpu_after}
        result['orders'] = observe_stages(orders, observer.states, started, manifest['policy']['threshold'])
        last = observer.states[-1]['state'] if observer.states else {}
        result['all_nodes_processed'] = bool(observer.states) and all(len(state.get('results', [])) >= args.orders for state in observer.states[-1]['nodes'].values())
        result['submitted'] = len(orders)
        result['admitted'] = sum(row.get('quorum_obtained', False) for row in orders)
        result['registered'] = sum(row['id'] in last.get('orders', {}) for row in orders)
        result['processed'] = sum('result' in row for row in result['orders'])
        result['incomplete'] = result['submitted']-result['processed']
        result['evidence_count'] = len(last.get('evidence') or [])
        result['observed_processed_tps'] = result['processed']*1000/result['interval_duration_ms']
        result['communication']['measured_bytes_per_submitted_order'] = result['communication']['measured_layered_protocol_bytes']/result['submitted'] if result['submitted'] else None
        result['communication']['measured_bytes_per_processed_order'] = result['communication']['measured_layered_protocol_bytes']/result['processed'] if result['processed'] else None
        result['snapshot_collection_ms'] = {
            'before': (before['finished_monotonic_s']-before['started_monotonic_s'])*1000,
            'after': (after['finished_monotonic_s']-after['started_monotonic_s'])*1000}
        save(root/'state-public.json', last)
        save(root/'states-final-public.json', observer.states[-1]['nodes'] if observer.states else {})
        save(root/'resource-samples.json', observer.resources)
        save(root/'network-samples.json', snapshots)
        save(root/'stage-observations.json', [{'monotonic_s': x['monotonic_s'], 'height': x['state'].get('height')} for x in observer.states])
        if observer.errors:
            result['errors'].append('observer sampling failed')
        if any(row['submit_exit_code'] for row in orders):
            result['errors'].append('one or more submissions returned failure')
        if result['incomplete'] or not result['all_nodes_processed']:
            result['errors'].append('orders incomplete on one or more nodes at observation deadline')
        # Audit after all measured network/CPU endpoints have been frozen.
        result['audit_started_after_interval'] = time.monotonic() >= finished
        code = run_command(args.binary, ['audit', '-dir', str(network), '-out', str(root/'audit.json'),
            '-timeout', str(args.timeout)+'s'], root/'audit.log', args.timeout+5)
        audit = json.loads((root/'audit.json').read_text()) if (root/'audit.json').exists() else {}
        result['audit_status'] = audit.get('status')
        result['audit_verified'] = (code == 0 and audit.get('status') ==
            'real commit, block replay, threshold openings and independent accounting verified'
            and audit.get('processed') == result['processed']
            and audit.get('commit_signatures', 0) >= manifest['policy']['quorum'])
        if not result['audit_verified']:
            result['errors'].append('post-interval audit failed')
        result['valid'] = not result['errors']
    except Exception as error:
        result['errors'].append(type(error).__name__ + ': ' + str(error))
    finally:
        if observer:
            try:
                observer.finish()
            except Exception as error:
                result['errors'].append('observer cleanup: ' + str(error))
                result['valid'] = False
        stop_processes(processes)
        result['owned_processes_remaining'] = sum(proc.poll() is None for proc in processes)
        for stream in logs:
            stream.close()
        if observer:
            save(root/'state-observations.json', observer.states)
            save(root/'resource-samples.json', observer.resources)
            save(root/'partial-network-samples.json', observer.networks)
            save(root/'observer-errors.json', observer.errors)
        if args.compute_samples and result.get('audit_verified'):
            try:
                code = run_command(args.binary, ['benchmark', '-dir', str(network), '-samples', str(args.compute_samples),
                    '-out', str(root/'compute.json')], root/'compute.log', args.timeout)
                result['compute_benchmark_completed'] = code == 0 and (root/'compute.json').exists()
                result['compute_benchmark_after_nodes_stopped'] = result['owned_processes_remaining'] == 0
                if not result['compute_benchmark_completed']:
                    result['errors'].append('post-interval compute benchmark failed')
            except Exception as error:
                result['errors'].append('compute benchmark: ' + str(error))
            result['valid'] = not result['errors']
        save(root/'result.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--nodes', default='5,8')
    parser.add_argument('--orders', type=int, default=6)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--modes', default='normal')
    parser.add_argument('--window-blocks', type=int, default=20)
    parser.add_argument('--block-interval-ms', type=int, default=300)
    parser.add_argument('--poll-interval-ms', type=int, default=500)
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--compute-samples', type=int, default=30)
    args = parser.parse_args(argv)
    nodes = [int(x) for x in args.nodes.split(',')]
    modes = args.modes.split(',')
    if not nodes or any(n not in (5,8) for n in nodes) or len(set(nodes)) != len(nodes):
        parser.error('nodes must be a distinct subset of 5,8')
    if not 1 <= args.orders <= 8 or not 1 <= args.repeats <= 10:
        parser.error('orders must be 1..8 and repeats 1..10')
    if any(m not in ('normal','omission') for m in modes) or len(set(modes)) != len(modes):
        parser.error('modes must be a distinct subset of normal,omission')
    if args.timeout < 10 or args.poll_interval_ms < 100 or args.block_interval_ms < 100 or args.window_blocks < 3 or not 0 <= args.compute_samples <= 10000:
        parser.error('invalid timing or computation sample bounds')
    args.binary = args.binary.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = Path(__file__).resolve().parent.parent
    provenance = {'schema': 1, 'started_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'python': platform.python_version(), 'platform': platform.platform(),
        'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        'source_sha256': source_hashes(root), 'arguments': {k:str(v) if isinstance(v,Path) else v for k,v in vars(args).items()},
        'limitations': [
            'Local multiprocess finite workload, no AI calls, no saturation throughput or asymptotic bound.',
            'Initialization/DKG and startup excluded; audit and compute benchmark performed after final interval snapshots.',
            'P2P counts delimited protobuf MConnection packets sent, not SecretConnection/TCP/IP wire bytes; ~100ms flowrate boundary quantization.',
            'Protocol HTTP request+response bodies are distinct from P2P; headers, framing, local RPC, model and observer traffic are not included in layered protocol sum.',
            'Cumulative completed HTTP handlers can cross interval boundaries. Snapshots are sampled, not simultaneous, and include background empty-block consensus and periodic repeated gossip.',
            'No idle-baseline subtraction. Per-order bytes are finite-run normalization, not a per-transaction complexity proof.',
            'ps CPU is cumulative node-process time; sampled RSS is not exact peak; host contention, observation overhead and protocol waiting remain.',
            'Queue capacity grows as n*orders to keep equal pernode quota. Service capacity2; actual block scheduling can differ between runs.',
            'Stage times are first node-1 client poll observations; measurement waits for all nodes to process. Prepare/submit command times include CLI startup and are not isolated crypto timings.']}
    save(args.out/'provenance.json', provenance)
    results = []
    for n in nodes:
        for mode in modes:
            for repeat in range(1,args.repeats+1):
                label=f'n{n}-{mode}-{repeat:02d}'
                result=execute(args,n,repeat,mode,args.out/label)
                results.append(dict(run=label,**result))
                save(args.out/'results.json',{'schema':1,'runs':results,'valid_runs':sum(r['valid'] for r in results),
                    'attempted_runs':len(results),'complete':len(results)==len(nodes)*len(modes)*args.repeats})
                print(label+': valid='+str(result['valid'])+' processed='+str(result.get('processed'))+
                      ' errors='+str(result['errors']),flush=True)
    return 0 if all(r['valid'] for r in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
