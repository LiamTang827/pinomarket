"""Small live-model pilot; distinct from precompiled-policy experiments.

Trusted host owns wallets/processes. Only bounded decisions cross the agent
boundary. Run snapshots stay private because network/ contains demo keys.
"""
from __future__ import annotations
import argparse
import concurrent.futures as futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import urllib.error

from agent_experiment import Trial, N, public_request, save
from role_agents import NodeAgent, PolicyServer, honest_plan, scripted_plan, public_observation


def logical_key(observation):
    phase = observation['phase']
    if phase == 'admission':
        p = observation['packet']
        return (phase, p['owner'], p['nonce'])
    if phase == 'seal':
        return (phase, observation['round'])
    return (phase, tuple(sorted((p['owner'], p['nonce']) for p in observation.get('service', []))))


class LatencyHonestAgent:
    """Replay recorded callback wait durations, returning only honest actions.

    It is a matched-wait control, not an exact replay of consensus scheduling.
    Unmatched observations are explicitly logged and receive zero added wait.
    """
    def __init__(self, actor, events, log_path):
        self.actor_id, self.log_path = actor, Path(log_path)
        self.delays = {logical_key(e['observation']): e['agent_elapsed_ms']
                       for e in events if not e.get('cached') and isinstance(e.get('decision'), dict) and not e.get('error')}
        self.events, self.lock, self.cache = [], threading.Lock(), {}

    def decide(self, observation):
        start = time.monotonic_ns()
        safe = public_observation(observation, self.actor_id)
        key = logical_key(safe)
        with self.lock:
            cached = key in self.cache
            target = 0 if cached else self.delays.get(key, 0)
            # Recorded elapsed time already contains any wait for this actor's
            # preceding callback. Do not add that queueing time a second time.
            remaining = max(0, target - (time.monotonic_ns()-start)/1e6)
            time.sleep(remaining / 1000)
            decision = {'action': 'normal', 'delay_ms': 0}
            self.cache[key] = decision
            event = {'actor': self.actor_id, 'received_monotonic_ns': start,
                     'observation': safe, 'decision': decision, 'cached': cached,
                     'matched': key in self.delays, 'target_wait_ms': target,
                     'agent_elapsed_ms': (time.monotonic_ns()-start)/1e6}
            self.events.append(event)
            with self.log_path.open('a') as stream:
                stream.write(json.dumps(event)+'\n')
            return decision

    def summary(self):
        return {'actor': self.actor_id, 'backend': 'latency-matched-honest',
                'requests': len(self.events), 'unmatched': sum(not e['matched'] for e in self.events)}


def replay_controls(args, root, entries):
    """Reuse logged decisions' timing and Bob's buy without calling a model."""
    source = Path(args.controls_from).resolve()
    records = []
    for label in args.control_runs.split(','):
        if label not in ('online-1', 'online-2'):
            raise ValueError('control source must be online-1 or online-2')
        previous = json.loads((source/label/'result.json').read_text())
        if previous.get('protocol_scope') != 'base-protocol':
            raise ValueError('source run is not a base-protocol experiment; withdrawn traces cannot be reused')
        events = {actor: [json.loads(line) for line in (source/label/f'{actor}-decisions.jsonl').read_text().splitlines()]
                  for actor in previous['assigned_adversarial_nodes']}
        def factory(actor, logfile):
            return LatencyHonestAgent(actor, events[actor], logfile) if actor in events else NodeAgent(actor, honest_plan(), logfile)
        def bob_decider(public, logfile):
            time.sleep(previous['bob_model_elapsed_ms']/1000)
            save(logfile, {'backend':'recorded-bob-wait-and-buy', 'plan':previous['bob_plan']})
            return dict(previous['bob_plan'])
        control_entries = [dict(e, liar_assigned=False) for e in entries]
        trial = OnlineTrial(args.binary, root/(label+'-corrected-wait-control'), control_entries, args, factory, bob_decider)
        print('START '+label+' corrected-wait-control (no model)', flush=True)
        try:
            trial.start()
            result = trial.run_online()
            result.update(kind='honest-matched-wait-control', run=label+'-corrected-wait-control', paired_with=label,
                          valid_strategy_comparison=previous.get('model_or_action_failures')==0,
                          wait_method='remaining-time-after-lock', matched_wait_nodes=list(events))
            records.append(result)
        finally:
            # Let in-flight callback logs finish before cancelling owned nodes.
            summaries = [a.summary() for a in trial.agents]
            trial.close()
            save(trial.root/'agents-summary.json', summaries)
    save(root/'summary.json', {'method':'corrected-wait-controls', 'source':str(source), 'runs':records,
         'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
         'binary_sha256':hashlib.sha256(Path(args.binary).read_bytes()).hexdigest()})
    print(root/'summary.json', flush=True)


class OnlineTrial(Trial):
    def __init__(self, binary, root, entries, args, agent_factory, bob_decider):
        super().__init__(binary, root, entries, args)
        self.agent_factory, self.bob_decider = agent_factory, bob_decider

    def start(self):
        self.command('init', '-dir', self.network, '-nodes', N, '-threshold', 3,
                     '-queue-capacity', 32, '-service-capacity', 2,
                     '-window-blocks', self.args.window_blocks, '-block-interval', '250ms',
                     '-ordering', 'identity', '-base-port', self.args.base_port,
                     '-api-port', self.args.api_port)
        self.manifest = json.loads((self.network/'manifest.json').read_text())
        for i, entry in enumerate(self.entries):
            agent = self.agent_factory(entry['actor'], self.root/f"{entry['actor']}-decisions.jsonl")
            server = PolicyServer(agent, self.socket_dir/f'{i}.sock')
            server.start()
            self.agents.append(agent)
            self.servers.append(server)
            with (self.root/f'node{i}.log').open('ab') as log:
                child = subprocess.Popen([self.binary, 'network', 'node', '-config',
                       str(self.network/f'node{i}.json'), '-agent-socket', str(self.socket_dir/f'{i}.sock'),
                       '-agent-timeout-ms', '55000', '-agent-prepare-blocks', str(self.args.prepare_blocks)],
                       stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=self.env)
            self.children.append(child)
        self.command('ready', '-dir', self.network, '-timeout', '35s', timeout=40)
        return self

    def send(self, packet, tag, delay_ms=0):
        def one(index, peer):
            jitter = (index*37 + self.args.seed*11) % 71
            time.sleep((delay_ms+jitter)/1000)
            start = time.monotonic()
            event = {'tag': tag, 'node': peer['id'], 'send_ms': (start-self.origin)*1000,
                     'transport_delay_ms': delay_ms+jitter, 'request_bytes': len(json.dumps(packet).encode())}
            try:
                event.update(ok=True, promise=public_request(peer['api']+'/submit', packet, timeout=125))
            except urllib.error.HTTPError as exc:
                event.update(ok=False, http_status=exc.code, error=exc.read(2048).decode(errors='replace'))
            except (OSError, ValueError, http.client.HTTPException) as exc:
                event.update(ok=False, error=str(exc)[:200])
            event['response_ms'] = (time.monotonic()-self.origin)*1000
            with self.transfer_lock:
                self.transfers.append(event)
            return event
        with futures.ThreadPoolExecutor(max_workers=N) as pool:
            return list(pool.map(lambda pair: one(*pair), enumerate(self.manifest['peers'])))

    def run_online(self):
        alice = self.prepare('alice', 0, 4)
        self.command('open', '-dir', self.network, '-timeout', '10s')
        deadline = time.monotonic()+5
        while True:
            snapshots = [public_request(p['api']+'/state') for p in self.manifest['peers']]
            if all(s.get('round') and s['round']['number']==1 and s['height']<s['round']['close_height'] for s in snapshots):
                break
            if time.monotonic()>deadline:
                raise RuntimeError('all-node admission start barrier failed')
            time.sleep(.05)
        save(self.root/'start-barrier.json', [{'node': p['id'], 'height': s['height'],
             'close_height': s['round']['close_height']} for p,s in zip(self.manifest['peers'], snapshots)])
        self.origin = time.monotonic()
        self.last_state = self.state()
        self.sample_resources()
        self.poll_thread = threading.Thread(target=self.poll, daemon=True)
        self.poll_thread.start()
        # The model call begins only after Alice really starts broadcasting.
        with futures.ThreadPoolExecutor(max_workers=2) as pool:
            alice_future = pool.submit(self.send, alice['packet'], 'alice')
            time.sleep(self.args.lead_ms/1000)
            state = self.state()
            bob_public = {'inventory': state['market']['locked_seller_inventory'], 'price_cents': 60, 'round': state['round']['number'],
                          'height': state['height'], 'close_height': state['round']['close_height'],
                          'observed_packets': [{'id': alice['packet_id'], 'owner': 'alice',
                          'nonce': 0, 'round': 1,
                          'ciphertext_bytes': len(json.dumps(alice['packet']).encode())}]}
            bob_start = time.monotonic()
            plan = self.bob_decider(bob_public, self.root/'bob-decisions.jsonl')
            bob_model_ms = (time.monotonic()-bob_start)*1000
            if set(plan) != {'quantity', 'release_delay_ms'} or type(plan['quantity']) is not int or not 1<=plan['quantity']<=10 or type(plan['release_delay_ms']) is not int or not 0<=plan['release_delay_ms']<=1000:
                raise ValueError('invalid Bob decision')
            bob = self.prepare('bob', 0, plan['quantity'])
            # Quantity and private signed body never enter node-agent observations.
            bob_future = pool.submit(self.send, bob['packet'], 'bob-0', plan['release_delay_ms'])
            alice_responses = alice_future.result()
            bob_future.result()
        save(self.root/'bob-plan.json', dict(plan, model_elapsed_ms=bob_model_ms))
        deadline = self.origin+self.args.deadline
        settled = None
        while time.monotonic()<deadline:
            state = self.last_state
            drained = state.get('round', {}).get('registered') and not state['queue'] and not state['active_service']
            if drained:
                settled = settled or time.monotonic()
                if time.monotonic()-settled >= 1.5:
                    break
            time.sleep(.1)
        self.stop_poll.set()
        self.poll_thread.join(timeout=5)
        state = self.state()
        stop_ms = (time.monotonic()-self.origin)*1000
        save(self.root/'state-public.json', state)
        save(self.root/'transfers.json', self.transfers)
        save(self.root/'resources.json', self.resources)
        audit = json.loads(self.command('audit', '-dir', self.network, '-timeout', '20s', timeout=25))
        save(self.root/'audit.json', audit)
        promises = [r['promise'] for r in alice_responses if r['ok']]
        receipt_path = self.root/'alice-receipt.json'
        save(receipt_path, {'packet': alice['packet'], 'promises': promises})
        verified = json.loads(self.command('verify-receipt', '-dir', self.network, '-packet', receipt_path))
        aid, bid = alice['packet_id'], bob['packet_id']
        regs = state['registrations']
        ids = [oid for reg in regs for oid in reg['ordered_ids']]
        selected = [l for reg in regs for l in reg['selected_lists']]
        a_result = next((r for r in state['results'] if r['order']=='alice:0'), None)
        # Signed committed lists and final membership determine actual applied effects.
        detail = []
        for entry in self.entries:
            actor = entry['actor']
            committed = next((l for l in (state.get('round') or {}).get('lists', []) if l['node']==actor), None)
            chosen = next((l for l in selected if l['node']==actor), None)
            detail.append({'node': actor, 'assigned_adversarial': entry['liar_assigned'],
                           'committed_list': committed is not None, 'selected': chosen is not None,
                           'alice_in_committed_list': committed is not None and any(p['id']==aid for p in committed['promises']),
                           'bob_in_committed_list': committed is not None and any(p['id']==bid for p in committed['promises'])})
        result = {'alice_promises': len(promises), 'alice_receipt_verified': verified['verified'],
                  'alice_quorum': len(promises)>=6, 'alice_registered': aid in ids,
                  'alice_position': ids.index(aid) if aid in ids else None,
                  'bob_position': ids.index(bid) if bid in ids else None,
                  'bob_before_alice': ids.index(bid)<ids.index(aid) if aid in ids and bid in ids else None,
                  'alice_result': a_result, 'alice_filled': a_result['filled'] if a_result else None,
                  'protocol_scope':'base-protocol', 'ordering':'identity-placeholder',
                  'node_list_effects': detail, 'evidence_count': len(state['evidence']),
                  'audit_verified': True, 'bob_plan': plan, 'bob_model_elapsed_ms': bob_model_ms,
                  'actual_alice_lead_ms': min(r['send_ms'] for r in self.transfers if r['tag']=='bob-0')-min(r['send_ms'] for r in self.transfers if r['tag']=='alice'),
                  'observation_stop_ms': stop_ms, 'alice_observed': self.observed.get(aid, {}),
                  'submit_errors': [{'tag': r['tag'], 'node': r['node'], 'error': r.get('error')} for r in self.transfers if not r['ok']],
                  'assigned_adversarial_nodes': [e['actor'] for e in self.entries if e['liar_assigned']],
                  'peak_sampled_nodes_rss_kib': max(r['rss_kib'] for r in self.resources),
                  'node_cpu_before_audit_s': self.resources[-1]['cpu_s']-self.resources[0]['cpu_s'],
                  'http_request_bytes_only': sum(r['request_bytes'] for r in self.transfers)}
        save(self.root/'result.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--state-dir')
    parser.add_argument('--controls-from', help='replay existing online traces without any model/login')
    parser.add_argument('--control-runs', default='online-2')
    parser.add_argument('--model', default='gpt-6.1-sol')
    parser.add_argument('--seed', type=int, default=20261023)
    parser.add_argument('--window-blocks', type=int, default=160)
    parser.add_argument('--prepare-blocks', type=int, default=70)
    parser.add_argument('--deadline', type=float, default=150)
    parser.add_argument('--lead-ms', type=int, default=100)
    parser.add_argument('--base-port', type=int, default=49656)
    parser.add_argument('--api-port', type=int, default=50600)
    parser.add_argument('--online-runs', type=int, default=2)
    parser.add_argument('--skip-known-control', action='store_true')
    args = parser.parse_args()
    if not 1<=args.online_runs<=2 or not 40<=args.window_blocks<=200 or not 1<=args.prepare_blocks<args.window_blocks or not 60<=args.deadline<=240:
        parser.error('pilot bounded to1..2runs,40..200windowblocks,validprefetchmargin,60..240sdeadline')
    root = Path(args.out).resolve()
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    entries = [{'actor': f'node-{i+1}', 'liar_assigned': i<2, 'plan': honest_plan()} for i in range(N)]
    if args.controls_from:
        replay_controls(args, root, entries)
        return
    if not args.state_dir:
        parser.error('--state-dir is required for live model trials')
    from chatgpt_model import ChatGPTModel
    from online_agents import OnlineNodeAgent, make_online_bob_plan
    records = []
    if not args.skip_known_control:
        control_entries = json.loads(json.dumps(entries))
        for e in control_entries[:2]:
            e['plan'] = scripted_plan('omission')
        short_args = argparse.Namespace(**vars(args))
        short_args.window_blocks, short_args.deadline = 12, 25
        trial = Trial(args.binary, root/'known-fault-control', control_entries, short_args)
        print('START known-fault-control (scripted, no model)', flush=True)
        try:
            trial.start()
            result = trial.run('race', {'attack':'race', 'orders':1, 'quantity':10, 'spacing_ms':0})
            result['kind'] = 'known-scripted-fault-control'
            records.append(result)
        finally:
            trial.close()
        save(root/'progress.json', records)
    for repeat in range(args.online_runs):
        label = f'online-{repeat+1}'
        path = root/label
        # Per-actor adapters and budgets avoid shared mutable model-call counters.
        models = {e['actor']: ChatGPTModel(args.state_dir, args.model, max_calls=8,
                  telemetry=root/f"{label}-{e['actor']}-model-calls.jsonl") for e in entries if e['liar_assigned']}
        bob_model = ChatGPTModel(args.state_dir, args.model, max_calls=1, telemetry=root/f'{label}-bob-model-calls.jsonl')
        def factory(actor, logfile):
            return OnlineNodeAgent(actor, models[actor], logfile, max_calls=8) if actor in models else NodeAgent(actor, honest_plan(), logfile)
        def bob_decider(public, logfile):
            return make_online_bob_plan(bob_model, public, own_cash=1000, log_path=logfile)
        trial = OnlineTrial(args.binary, path, entries, args, factory, bob_decider)
        print('START '+label+' (live model at events)', flush=True)
        try:
            trial.start()
            result = trial.run_online()
            result.update(kind='live-model', run=label)
            records.append(result)
        except Exception as exc:
            result = {'kind':'live-model', 'run':label, 'framework_error':type(exc).__name__}
            records.append(result)
            save(path/'error.json', result)
        finally:
            trial.close()
            # Some share callbacks can finish after honest nodes already execute.
            # Snapshot final logs only after owned processes are stopped.
            summaries = [a.summary() for a in trial.agents]
            save(path/'agents-summary.json', summaries)
        result['model_or_action_failures'] = sum(s.get('failed_decisions', 0) for s in summaries)
        save(path/'result.json', result)
        if result.get('framework_error'):
            save(root/'progress.json', records)
            print(json.dumps(result), flush=True)
            continue
        events = {actor: [json.loads(line) for line in (path/f'{actor}-decisions.jsonl').read_text().splitlines()]
                  for actor in models}
        save(root/'progress.json', records)
        print(json.dumps({k: result.get(k) for k in ('run','alice_promises','alice_filled','bob_before_alice','evidence_count')}), flush=True)
        replay_label = label+'-honest-wait-control'
        def replay_factory(actor, logfile):
            return LatencyHonestAgent(actor, events[actor], logfile) if actor in events else NodeAgent(actor, honest_plan(), logfile)
        bob_plan = result['bob_plan']
        def replay_bob(public, logfile):
            time.sleep(result['bob_model_elapsed_ms']/1000)
            save(logfile, {'backend':'same-bob-plan-and-model-wait', 'plan':bob_plan})
            return dict(bob_plan)
        control = OnlineTrial(args.binary, root/replay_label, entries, args, replay_factory, replay_bob)
        print('START '+replay_label+' (no model, matched waits)', flush=True)
        try:
            control.start()
            normal = control.run_online()
            normal.update(kind='honest-matched-wait-control', run=replay_label, paired_with=label,
                          valid_strategy_comparison=result['model_or_action_failures']==0)
            records.append(normal)
        finally:
            control.close()
            save(control.root/'agents-summary.json', [a.summary() for a in control.agents])
        save(root/'progress.json', records)
        print(json.dumps({k: normal.get(k) for k in ('run','alice_promises','alice_filled','bob_before_alice','evidence_count')}), flush=True)
    source_root = Path(__file__).resolve().parent.parent
    sources = {str(p.relative_to(source_root)): hashlib.sha256(p.read_bytes()).hexdigest()
               for folder in ('internal/live','harness') for p in sorted((source_root/folder).glob('*')) if p.suffix in ('.go','.py')}
    save(root/'summary.json', {'schema':1, 'method':'live-LLM-pilot', 'protocol_scope':'base-protocol','ordering':'identity-placeholder', 'n':8, 'f':2, 'q':6, 't':3,
         'model':args.model, 'window_blocks':args.window_blocks, 'prepare_blocks':args.prepare_blocks,
         'binary_sha256':hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(), 'source_sha256':sources,
         'runs':records, 'limitations':['Two online searches are not an attack success probability or a safety proof.',
         'Model callback arrival order is not network first reception time.',
         'Matched-wait controls do not replay exact independent consensus scheduling.',
         'Node agents have no economic utility or Bob coordination; assigned adversarial objective only.',
         'One-host fixed-price market, not full prediction market deployment or AMM sandwich evaluation.',
         'Model self-reported reasons are short explanations, not hidden internal reasoning.']})
    print(root/'summary.json', flush=True)


if __name__=='__main__':
    main()
