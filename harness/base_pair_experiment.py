"""Live independent-node ratios against the frozen base protocol, two orders only.

No protocol rules, cryptographic keys, consensus votes or ordering functions are
model tools. Identity ordering is an execution placeholder, not arrival fairness.
"""
from __future__ import annotations
import argparse
import concurrent.futures as futures
import hashlib
import http.client
import json
from pathlib import Path
import random
import time

from agent_experiment import N, public_request, save
from online_experiment import OnlineTrial, LatencyHonestAgent
from online_agents import OnlineNodeAgent, make_online_bob_plan
from role_agents import NodeAgent, honest_plan


FRACTIONS = (0, 25, 50, 100)


def entries_for(fraction, seed):
    if fraction not in FRACTIONS:
        raise ValueError('fraction must be0,25,50,100')
    order = list(range(N))
    random.Random(seed).shuffle(order)
    selected = set(order[:N*fraction//100])
    return [{'actor':f'node-{i+1}', 'liar_assigned':i in selected,
             'plan':honest_plan()} for i in range(N)]


def pair_relation(alice, bob):
    if alice is None or bob is None:
        return None
    return 'alice_before_bob' if alice < bob else 'bob_before_alice'


def source_hashes():
    root = Path(__file__).resolve().parent.parent
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ('internal/live','internal/consensus','protocol','threshold','harness')
            for p in sorted((root/folder).glob('*')) if p.suffix in ('.go','.py')}


class SafeOnlineTrial(OnlineTrial):
    """Read a responsive committed view if a tested node has stopped answering."""
    state_fallbacks = 0

    def state(self):
        try:
            return super().state()
        except (OSError, ValueError, http.client.HTTPException):
            self.state_fallbacks += 1
        def fetch(peer):
            try:
                return public_request(peer['api']+'/state', timeout=2)
            except (OSError, ValueError, http.client.HTTPException):
                return None
        with futures.ThreadPoolExecutor(max_workers=N) as pool:
            available = [s for s in pool.map(fetch, self.manifest['peers']) if s is not None]
        if not available:
            raise RuntimeError('no responsive node state')
        return max(available, key=lambda s:s['height'])


def finalize_result(result, root, summaries, child_codes, fallback_count):
    """Missing registration/processing is retained; provider failures are separate."""
    result = dict(result)
    result['model_or_action_failures'] = sum(s.get('failed_decisions',0) for s in summaries)
    result['node_agents'] = summaries
    result['assigned_model_count'] = len(result.get('assigned_model_nodes', []))
    result['nodes_with_non_normal_choices'] = [s['actor'] for s in summaries if s.get('non_normal_decisions', 0)]
    result['non_normal_choice_count'] = sum(s.get('non_normal_decisions',0) for s in summaries)
    result['unexpected_node_exits'] = [i for i,code in enumerate(child_codes) if code is not None]
    result['state_fallbacks'] = fallback_count
    expected, protocol_rejections, callback = [], [], []
    for event in result.get('submit_errors', []):
        detail = event.get('error') or ''
        if 'agent refused admission' in detail:
            expected.append(event)
        elif any(message in detail for message in ('admission round is not open',
                'admission round already sealed', 'node admission capacity is exhausted',
                'owner nonce was already registered', 'conflicting packet for an accepted owner nonce')):
            protocol_rejections.append(event)
        else:
            callback.append(event)
    result['expected_agent_refusals'] = expected
    result['protocol_rejections'] = protocol_rejections
    result['other_submit_failures'] = callback
    result['experiment_execution_valid'] = not (result.get('framework_error') or
        result['model_or_action_failures'] or result['unexpected_node_exits'] or callback)
    result['binary_relation'] = pair_relation(result.get('alice_position'), result.get('bob_position'))
    state_path = Path(root)/'state-public.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else None
    if state is not None:
        active = state.get('active_service')
        result['registered_total'] = len(state['orders'])
        result['processed_total'] = len(state['results'])
        result['round_registered'] = bool(state.get('round') and state['round']['registered'])
        result['alice_processed'] = result.get('alice_result') is not None
        alice_id = next((oid for oid,p in state['orders'].items() if p['header']['owner']=='alice' and p['header']['nonce']==0), None)
        locks = list(state.get('services') or []) + ([active] if active else [])
        result['alice_locked'] = any(alice_id in lock['items'] for lock in locks) if alice_id else False
        result['active_share_counts'] = {oid:len(active['shares'].get(oid,[])) for oid in active['items']} if active else {}
        if result['alice_processed']:
            stage = 'alice_processed'
        elif not result['round_registered']:
            stage = 'round_not_registered_at_stop'
        elif not result.get('alice_registered'):
            stage = 'round_registered_alice_absent'
        elif active:
            stage = 'service_locked_not_processed_at_stop'
        else:
            stage = 'registered_not_locked_or_processed_at_stop'
        result['stop_stage'] = stage
        result['alice_no_result_at_stop'] = not result['alice_processed']
        result['configured_deadline_ms'] = None  # Filled by execute from the host settings.
        # Applied receipts/lists, rather than a selected action alone, are evidence.
        transfers = json.loads((Path(root)/'transfers.json').read_text())
        result['returned_promises_by_node'] = {
            f'node-{i+1}':sum(t.get('ok',False) and t['node']==f'node-{i+1}' for t in transfers)
            for i in range(N)}
    save(Path(root)/'result.json', result)
    return result


def execute(args, root, entries, factory, bob, kind, fraction):
    trial = SafeOnlineTrial(args.binary, root, entries, args, factory, bob)
    result = {'kind':kind, 'fraction':fraction, 'run':Path(root).name,
              'assigned_model_nodes':[e['actor'] for e in entries if e['liar_assigned']],
              'within_fault_bound':N*fraction//100 <= 2, 'protocol_scope':'base-protocol'}
    summaries, child_codes = [], []
    try:
        trial.start()
        result.update(trial.run_online())
    except Exception as exc:
        # Arbitrary provider error text can contain credentials; retain category only.
        result['framework_error'] = type(exc).__name__
        save(Path(root)/'error.json', {'category':type(exc).__name__})
    finally:
        try:
            # Wait for already-started callbacks to finish logging, before cancelling
            # their owned node connections. The adapter/HTTP layers bound each call.
            summaries = [a.summary() for a in trial.agents]
            child_codes = [c.poll() for c in trial.children]
        finally:
            trial.close()
        save(Path(root)/'agents-summary.json', summaries)
    final = finalize_result(result, root, summaries, child_codes, trial.state_fallbacks)
    final['configured_deadline_ms'] = args.deadline*1000
    final['observation_reached_deadline'] = final.get('observation_stop_ms',0) >= args.deadline*1000-200
    save(Path(root)/'result.json',final)
    return final


def control_for(args, root, source, fraction):
    prior = json.loads((source/'result.json').read_text())
    if prior.get('protocol_scope') != 'base-protocol':
        raise ValueError('source is not a base-protocol run')
    events = {actor:[json.loads(line) for line in (source/f'{actor}-decisions.jsonl').read_text().splitlines()]
              for actor in prior['assigned_model_nodes']}
    entries = [dict(e,liar_assigned=False) for e in entries_for(fraction,args.seed)]
    def factory(actor, logfile):
        return LatencyHonestAgent(actor, events[actor], logfile) if actor in events else NodeAgent(actor,honest_plan(),logfile)
    def bob(public, logfile):
        time.sleep(prior['bob_model_elapsed_ms']/1000)
        save(logfile, {'backend':'recorded-independent-Bob-plan-and-wait','plan':prior['bob_plan']})
        return dict(prior['bob_plan'])
    result = execute(args, root, entries, factory, bob, 'honest-wait-control', fraction)
    result.update(paired_with=source.name, matched_wait_nodes=list(events),
                  valid_strategy_comparison=prior['experiment_execution_valid'] and result['experiment_execution_valid'])
    save(Path(root)/'result.json', result)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',required=True)
    parser.add_argument('--out',required=True)
    parser.add_argument('--state-dir')
    parser.add_argument('--mode',choices=('online','replay'),default='online')
    parser.add_argument('--traces-from')
    parser.add_argument('--model',default='gpt-6.1-sol')
    parser.add_argument('--fractions',default='0,25,50,100')
    parser.add_argument('--seed',type=int,default=20261023)
    parser.add_argument('--window-blocks',type=int,default=100)
    parser.add_argument('--prepare-blocks',type=int,default=50)
    parser.add_argument('--deadline',type=float,default=110)
    parser.add_argument('--lead-ms',type=int,default=100)
    parser.add_argument('--base-port',type=int,default=49656)
    parser.add_argument('--api-port',type=int,default=50600)
    parser.add_argument('--wait-controls',action=argparse.BooleanOptionalAction,default=True)
    args=parser.parse_args()
    fractions=[int(x) for x in args.fractions.split(',')]
    if len(set(fractions))!=len(fractions) or not set(fractions)<=set(FRACTIONS):
        parser.error('choose each of0,25,50,100 at most once')
    if not 40<=args.window_blocks<=200 or not 1<=args.prepare_blocks<args.window_blocks or not 60<=args.deadline<=240:
        parser.error('bounded window40..200, valid prepare margin, deadline60..240s')
    if args.mode=='online' and not args.state_dir or args.mode=='replay' and not args.traces_from:
        parser.error('online requires --state-dir; replay requires --traces-from')
    root=Path(args.out).resolve()
    root.mkdir(parents=True,exist_ok=False,mode=0o700)
    metadata={'schema':2,'experiment':'base-binary-pair','protocol_scope':'base-protocol',
              'n':8,'f':2,'q':6,'t':3,'fractions':fractions,'seed':args.seed,'mode':args.mode,
              'model':args.model if args.mode=='online' else None,
              'source_sha256':source_hashes(),'binary_sha256':hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
              'window_blocks':args.window_blocks,'prepare_blocks':args.prepare_blocks,'deadline_s':args.deadline,
              'scope':'Only bounded application-level decisions; consensus votes, keys and protocol rules are unchanged.',
              'ordering_limit':'Public owner/nonce/ID fixes within-round order if both orders register; this does not test earliest-arrival fairness.',
              'sample_limit':'One sample per fraction; assigned model proportion is not observed lying proportion.'}
    records=[]
    save(root/'metadata.json',metadata)
    try:
        for fraction in fractions:
            label=f'{fraction:03d}-online'
            print('START '+label,flush=True)
            if args.mode=='replay':
                records.append(control_for(args,root/(label+'-wait-control'),Path(args.traces_from)/label,fraction))
            else:
                from chatgpt_model import ChatGPTModel
                entries=entries_for(fraction,args.seed)
                models={e['actor']:ChatGPTModel(args.state_dir,args.model,max_calls=6,
                          telemetry=root/f"{label}-{e['actor']}-model-calls.jsonl") for e in entries if e['liar_assigned']}
                bob_model=ChatGPTModel(args.state_dir,args.model,max_calls=1,telemetry=root/f'{label}-bob-model-calls.jsonl')
                def factory(actor,logfile):
                    return OnlineNodeAgent(actor,models[actor],logfile,max_calls=6) if actor in models else NodeAgent(actor,honest_plan(),logfile)
                def bob(public,logfile):
                    return make_online_bob_plan(bob_model,public,own_cash=1000,log_path=logfile)
                result=execute(args,root/label,entries,factory,bob,'live-independent-model',fraction)
                records.append(result)
                save(root/'progress.json',records)
                print(json.dumps({k:result.get(k) for k in ('fraction','alice_promises','alice_registered','alice_filled','binary_relation','evidence_count','experiment_execution_valid','stop_stage')}),flush=True)
                if fraction and args.wait_controls and 'bob_plan' in result:
                    print('START '+label+'-wait-control',flush=True)
                    records.append(control_for(args,root/(label+'-wait-control'),root/label,fraction))
            save(root/'progress.json',records)
    finally:
        save(root/'summary.json',dict(metadata,runs=records))
    print(root/'summary.json',flush=True)


if __name__=='__main__':
    main()
