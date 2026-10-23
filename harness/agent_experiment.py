"""Isolated role agents against the actual local CometBFT/threshold protocol.

The trusted host signs/prepares packets and owns processes. Actors receive no
filesystem/shell/controller tools. GPT authors bounded policies BEFORE timing;
separate per-node reactive agents execute those policies on live observations.
"""
from __future__ import annotations
import argparse
import concurrent.futures as futures
import csv
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

from role_agents import NodeAgent, PolicyServer, honest_plan, scripted_plan, make_plan, make_bob_plan

N = 8
SCENARIOS = ('none', 'race', 'flood', 'replay', 'conflict')
FRACTIONS = (0, 25, 50, 100)


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def public_request(url, payload=None, timeout=4):
    raw = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=raw, headers={'Content-Type': 'application/json'})
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=timeout) as response:
        return json.load(response)


def plan_suite(seed, model=None):
    permutation = list(range(N))
    random.Random(seed).shuffle(permutation)
    result = {'schema': 1, 'seed': seed, 'node_order': permutation,
              'backend': 'chatgpt-policy' if model else 'scripted-reference',
              'nodes': {}, 'bob': {}}
    dishonest = {f'node-{i+1}':scripted_plan('mixed',seed=seed,actor_id=f'node-{i+1}') for i in range(N)}
    if model:
        with futures.ThreadPoolExecutor(max_workers=3) as pool:
            pending = {pool.submit(make_plan,model,actor,True,'mixed'):actor for actor in dishonest}
            for future in futures.as_completed(pending):
                dishonest[pending[future]]=future.result()
    for fraction in FRACTIONS:
        liars=set(permutation[:N*fraction//100])
        result['nodes'][str(fraction)]=[
            {'actor':f'node-{i+1}','liar_assigned':i in liars,
             'plan':dict(dishonest[f'node-{i+1}']) if i in liars else honest_plan()}
            for i in range(N)]
    for scenario in SCENARIOS:
        if model and scenario != 'none':
            result['bob'][scenario] = make_bob_plan(model, scenario=scenario)
        else:
            result['bob'][scenario] = {'attack': scenario, 'orders': 8 if scenario in ('flood', 'replay') else 1,
                                        'quantity': 10, 'spacing_ms': 0}
    return result


class Trial:
    def __init__(self, binary, root, entries, args):
        self.binary, self.root, self.entries, self.args = str(Path(binary).resolve()), Path(root), entries, args
        self.root.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.network = self.root/'network'
        self.children, self.servers, self.agents = [], [], []
        self.socket_dir = Path(tempfile.mkdtemp(prefix='pino-ag-'))
        self.env = {key: os.environ[key] for key in ('PATH','HOME','TMPDIR','LANG','LC_ALL') if key in os.environ}
        self.transfers, self.transfer_lock = [], threading.Lock()
        self.observed = {}
        self.resources = []
        self.last_resource_time = 0
        self.stop_poll = threading.Event()
        self.poll_thread = None
        self.origin = None

    def command(self, *args, timeout=60):
        result = subprocess.run([self.binary, 'network', *map(str,args)], capture_output=True,
                                text=True, stdin=subprocess.DEVNULL, env=self.env, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f'network {args[0]} failed: {result.stderr[-1500:]}')
        return result.stdout

    def start(self):
        self.command('init','-dir',self.network,'-nodes',N,'-threshold',3,'-queue-capacity',32,
                     '-service-capacity',2,'-window-blocks',self.args.window_blocks,
                     '-block-interval','250ms','-ordering','identity',
                     '-base-port',self.args.base_port,'-api-port',self.args.api_port)
        self.manifest = json.loads((self.network/'manifest.json').read_text())
        for index, entry in enumerate(self.entries):
            agent = NodeAgent(entry['actor'], entry['plan'], self.root/f"{entry['actor']}-decisions.jsonl")
            server = PolicyServer(agent, self.socket_dir/f'{index}.sock')
            server.start()
            self.agents.append(agent)
            self.servers.append(server)
            with (self.root/f'node{index}.log').open('ab') as log:
                child = subprocess.Popen([self.binary,'network','node','-config',str(self.network/f'node{index}.json'),
                                          '-agent-socket',str(self.socket_dir/f'{index}.sock')],
                                         stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL,env=self.env)
            self.children.append(child)
        self.command('ready','-dir',self.network,'-timeout','35s',timeout=40)
        return self

    def prepare(self, owner, nonce, quantity=10):
        path = self.root/f'packet-{owner}-{nonce}-{quantity}.json'
        self.command('prepare','-dir',self.network,'-owner',owner,'-nonce',nonce,
                     '-quantity',quantity,'-limit',60,'-round',1,'-out',path)
        return json.loads(path.read_text())

    def state(self):
        return public_request(self.manifest['peers'][0]['api']+'/state')

    def sample_resources(self):
        sample = subprocess.run(['ps','-o','pid=,rss=,time=','-p',','.join(str(p.pid) for p in self.children)],
                                capture_output=True,text=True,timeout=3)
        values=[]
        for line in sample.stdout.splitlines():
            parts=line.split()
            if len(parts)!=3:
                continue
            clock=parts[2].split(':')
            seconds=sum(float(part)*60**i for i,part in enumerate(reversed(clock)))
            values.append({'pid':int(parts[0]),'rss_kib':int(parts[1]),'cpu_s':seconds})
        self.resources.append({'elapsed_ms':(time.monotonic()-self.origin)*1000,'processes':values,
                               'rss_kib':sum(v['rss_kib'] for v in values),'cpu_s':sum(v['cpu_s'] for v in values)})

    def poll(self):
        while not self.stop_poll.is_set():
            try:
                state = self.state()
                if time.monotonic()-self.last_resource_time >= .5:
                    self.sample_resources()
                    self.last_resource_time=time.monotonic()
                self.last_state = state
                now = (time.monotonic()-self.origin)*1000
                for registration in state.get('registrations',[]):
                    for position, oid in enumerate(registration['ordered_ids']):
                        event = self.observed.setdefault(oid,{})
                        event.setdefault('registered_observed_ms',now)
                        event.setdefault('registration_position',position)
                        event.setdefault('registration_height',registration['height'])
                locks = list(state.get('services') or [])
                if state.get('active_service'):
                    locks.append(state['active_service'])
                for lock in locks:
                    for oid in lock['items']:
                        event = self.observed.setdefault(oid,{})
                        event.setdefault('locked_observed_ms',now)
                        event.setdefault('lock_height',lock['height'])
                        if len(lock['shares'].get(oid,[])) >= 3:
                            event.setdefault('shares_ready_observed_ms',now)
                refs = {f"{p['header']['owner']}:{p['header']['nonce']}": oid for oid,p in state['orders'].items()}
                for result in state.get('results',[]):
                    if result['order'] in refs:
                        self.observed.setdefault(refs[result['order']],{}).setdefault('processed_observed_ms',now)
            except (OSError, ValueError, KeyError, http.client.HTTPException, subprocess.SubprocessError):
                pass
            self.stop_poll.wait(.08)

    def send(self, packet, tag, delay_ms=0):
        # Delay is trusted experiment transport scheduling, not an actor message.
        # Fixed deterministic per-peer jitter is shared by Alice and Bob.
        def one(index, peer):
            jitter = (index*37 + self.args.seed*11) % 71
            time.sleep((delay_ms+jitter)/1000)
            started = time.monotonic()
            event = {'tag':tag,'node':peer['id'],'send_ms':(started-self.origin)*1000,
                     'transport_delay_ms':delay_ms+jitter,'request_bytes':len(json.dumps(packet).encode())}
            try:
                promise = public_request(peer['api']+'/submit',packet,timeout=4)
                event.update(ok=True,promise=promise)
            except urllib.error.HTTPError as exc:
                detail=exc.read(2048).decode('utf-8',errors='replace')
                event.update(ok=False,http_status=exc.code,error=detail[:1000])
            except (OSError, ValueError, http.client.HTTPException) as exc:
                event.update(ok=False,error=str(exc)[:200])
            event['response_ms']=(time.monotonic()-self.origin)*1000
            with self.transfer_lock:
                self.transfers.append(event)
            return event
        with futures.ThreadPoolExecutor(max_workers=N) as pool:
            return list(pool.map(lambda pair: one(*pair),enumerate(self.manifest['peers'])))

    def run(self, scenario, bob_plan):
        alice = self.prepare('alice',0,4)
        attack = []
        if scenario == 'race':
            attack = [self.prepare('bob',0,bob_plan.get('quantity',10))]
        elif scenario == 'flood':
            attack = [self.prepare('bob',i,bob_plan.get('quantity',10)) for i in range(min(8,bob_plan.get('orders',8)))]
        elif scenario == 'conflict':
            attack = [self.prepare('bob',0,bob_plan.get('quantity',10)),
                      self.prepare('bob',0,max(1,bob_plan.get('quantity',10)-1) if bob_plan.get('quantity',10)>1 else 2)]
        elif scenario == 'replay':
            attack = [alice]*min(8,bob_plan.get('orders',8))
        save(self.root/'effective-policies.json',self.entries)
        save(self.root/'executed-attack.json',{'scenario':scenario,'model_plan':bob_plan,
             'packet_count':len(attack),'packet_ids':[item['packet_id'] for item in attack],
             'initial_lead_ms':self.args.lead_ms,'spacing_ms':bob_plan.get('spacing_ms',0)})
        self.command('open','-dir',self.network,'-timeout','10s')
        barrier_deadline=time.monotonic()+5
        while True:
            try:
                with futures.ThreadPoolExecutor(max_workers=N) as pool:
                    snapshots=list(pool.map(lambda peer:public_request(peer['api']+'/state'),self.manifest['peers']))
                ready=all(snapshot.get('round') and snapshot['round']['number']==1 and
                          not snapshot['round']['registered'] and snapshot['height']<snapshot['round']['close_height']
                          for snapshot in snapshots)
                if ready:
                    save(self.root/'start-barrier.json',[{'node':peer['id'],'height':snapshot['height'],
                         'round':snapshot['round']['number'],'close_height':snapshot['round']['close_height']}
                         for peer,snapshot in zip(self.manifest['peers'],snapshots)])
                    break
            except (OSError,ValueError,http.client.HTTPException):
                pass
            if time.monotonic()>=barrier_deadline:
                raise RuntimeError('start barrier failed: not all nodes observed the open admission window')
            time.sleep(.05)
        self.origin = time.monotonic()
        self.last_state = self.state()
        start_window_remaining=self.last_state['round']['close_height']-self.last_state['height']
        self.sample_resources()
        self.poll_thread = threading.Thread(target=self.poll,daemon=True)
        self.poll_thread.start()
        # Alice starts first. Bob sees only a copy of the broadcast encrypted envelope.
        with futures.ThreadPoolExecutor(max_workers=10) as pool:
            alice_future = pool.submit(self.send,alice['packet'],'alice')
            time.sleep(self.args.lead_ms/1000)
            bob_futures = [pool.submit(self.send,item['packet'],f'bob-{i}',i*bob_plan.get('spacing_ms',0)) for i,item in enumerate(attack)]
            alice_receipts = alice_future.result()
            for future in bob_futures:
                future.result()
        deadline = self.origin+self.args.deadline
        # Wait for all admitted work, or a fixed deadline; never discard stalled samples.
        settled_at = None
        while time.monotonic() < deadline:
            state = self.last_state
            registered = bool(state.get('round') and state['round']['registered'])
            drained = registered and not state['queue'] and not state['active_service']
            if drained:
                if settled_at is None:
                    settled_at = time.monotonic()
                # Give receipt gossip a bounded chance to publish omission contradictions.
                if time.monotonic()-settled_at >= 1.2:
                    break
            time.sleep(.1)
        self.stop_poll.set()
        self.poll_thread.join(timeout=5)
        state = self.state()
        observation_stop_ms=(time.monotonic()-self.origin)*1000
        save(self.root/'state-public.json',state)
        save(self.root/'transfers.json',self.transfers)
        self.sample_resources()
        save(self.root/'resources.json',self.resources)
        audit_ok, audit = False, None
        try:
            audit = json.loads(self.command('audit','-dir',self.network,'-timeout','20s',timeout=25))
            audit_ok = True
        except (RuntimeError, subprocess.TimeoutExpired, ValueError) as exc:
            audit = {'error':str(exc)[:1000]}
        save(self.root/'audit.json',audit)
        aid = alice['packet_id']
        responses = sorted((r for r in alice_receipts if r['ok']),key=lambda r:r['response_ms'])
        receipt_path=self.root/'alice-receipt.json'
        save(receipt_path,{'packet':alice['packet'],'promises':[r['promise'] for r in responses]})
        receipt_verification=json.loads(self.command('verify-receipt','-dir',self.network,'-packet',receipt_path))
        alice_result = next((r for r in state['results'] if r['order']=='alice:0'),None)
        ids = [oid for registration in state['registrations'] for oid in registration['ordered_ids']]
        before = [state['orders'][oid]['header']['owner'] for oid in ids[:ids.index(aid)]] if aid in ids else []
        first_send_alice = min(r['send_ms'] for r in self.transfers if r['tag']=='alice')
        bob_sends = [r['send_ms'] for r in self.transfers if r['tag'].startswith('bob-')]
        node_summaries = [agent.summary() for agent in self.agents]
        outcome = {'scenario':scenario,'alice_receipt_verified':receipt_verification['verified'],
                   'protocol_scope':'base-protocol','alice_sent_first':not bob_sends or first_send_alice<min(bob_sends),
                   'alice_promises':len(responses),'alice_quorum':len(responses)>=6,
                   'alice_quorum_ms':responses[5]['response_ms'] if len(responses)>=6 else None,
                   'alice_registered':aid in ids,'alice_processed':alice_result is not None,
                   'alice_result':alice_result,'alice_filled':alice_result['filled'] if alice_result else 0,
                   'alice_full_fill':bool(alice_result and alice_result['filled']==4),
                   'alice_observed':self.observed.get(aid,{}),'bob_before_alice': 'bob' in before,
                   'alice_no_result_at_stop':alice_result is None,
                   'registered_total':len(ids),'processed_total':len(state['results']),
                   'queued_total':len(state['queue']),'active_service':state['active_service'] is not None,
                   'evidence_count':len(state['evidence']),'audit_verified':audit_ok,
                   'trial_elapsed_including_audit_ms':(time.monotonic()-self.origin)*1000,
                   'observation_stop_ms':observation_stop_ms,'configured_deadline_ms':self.args.deadline*1000,
                   'deadline_exceeded':observation_stop_ms>self.args.deadline*1000+300,
                   'remaining_window_blocks_at_start':start_window_remaining,
                   'http_request_bytes':sum(r['request_bytes'] for r in self.transfers),
                   'node_agents':node_summaries,
                   'node_cpu_before_audit_s':self.resources[-1]['cpu_s']-self.resources[0]['cpu_s'],
                   'peak_sampled_nodes_rss_kib':max(r['rss_kib'] for r in self.resources),
                   'successful_bob_http':sum(r['ok'] for r in self.transfers if r['tag'].startswith('bob-'))}
        save(self.root/'result.json',outcome)
        return outcome

    def close(self):
        self.stop_poll.set()
        if self.poll_thread:
            self.poll_thread.join(timeout=5)
        for child in self.children:
            if child.poll() is None:
                child.terminate()
        for child in self.children:
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        with futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda server:server.close(),self.servers))
        shutil.rmtree(self.socket_dir)


def summarize(root, records, suite, args):
    baseline = {(r['fraction'],r['profile']):r for r in records if r['scenario']=='none' and 'error' not in r}
    for record in records:
        control = baseline.get((record['fraction'],record['profile']))
        if control and 'error' not in record:
            record['alice_fill_loss_vs_control'] = control['alice_filled']-record['alice_filled']
            a = record['alice_observed'].get('processed_observed_ms')
            b = control['alice_observed'].get('processed_observed_ms')
            record['extra_processing_ms_vs_control'] = a-b if a is not None and b is not None else None
    sources = {}
    source_root = Path(__file__).resolve().parent.parent
    for folder in ('internal/live','internal/consensus','threshold','protocol','harness'):
        for path in sorted((source_root/folder).glob('*')):
            if path.suffix in ('.go','.py'):
                sources[str(path.relative_to(source_root))]=hashlib.sha256(path.read_bytes()).hexdigest()
    summary = {'schema':1,'nodes':8,'fault_bound':2,'quorum':6,'threshold':3,
               'ordering':'identity-placeholder','protocol_scope':'base-protocol','seed':args.seed,'backend':suite['backend'],
               'model':args.model if args.backend=='chatgpt' else None,
               'binary_sha256':hashlib.sha256(Path(args.binary).read_bytes()).hexdigest(),
               'source_sha256':sources,'lead_ms':args.lead_ms,'deadline_s':args.deadline,
               'window_blocks':args.window_blocks,'runs':records,
               'profile':getattr(args,'profile','mixed'),'limits':['One local seed/repetition is functional evidence, not statistical efficacy.',
                         'Node policy actions affect application behavior; CometBFT consensus remains unmodified.',
                         'No agent chat, no Bob node-control tools; ordinary signed protocol traffic remains.',
                         'GPT writes bounded policies before timing; runtime agents are deterministic reactive executors.',
                         '50% and 100% exceed f=2; action set excludes early threshold-secret collusion.',
                         'Fixed-price inventory market cannot measure AMM sandwiches or actual information profits.',
                         'HTTP bytes exclude gossip, consensus, TLS overhead; poll times are observation upper bounds.',
                         'Controls share seed/policies, but separate cryptographic keys and consensus scheduling.']}
    save(root/'summary.json',summary)
    fields=['fraction','profile','scenario','alice_promises','alice_quorum','alice_registered','alice_processed',
            'alice_filled','alice_fill_loss_vs_control','bob_before_alice','alice_no_result_at_stop',
            'evidence_count','audit_verified','error']
    with (root/'summary.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields,extrasaction='ignore')
        writer.writeheader()
        writer.writerows(records)
    lines=['# Pinomarket 独立节点 agent 实验','',
           f"后端：{suite['backend']}；8 节点，f=2，收录 q=6，解密 t=3。",'',
           ('GPT 在计时前为每个说谎倾向节点独立生成受限策略；实际收到协议消息后，由各自 agent 执行策略。' if suite['backend']=='chatgpt-policy' and getattr(args,'profile','mixed')=='mixed' else '本组为预设规则策略压力测试，运行期间由各节点独立 agent 执行；不声称本组策略由 GPT 生成。'),
           '模型思考时间不计入交易传播延迟；节点没有私聊工具，Bob 无法控制节点。','',
           '|比例|策略组|Bob 操作|Alice 承诺|成交份额/4|Bob 排在前面|证据数|审计|',
           '|---|---|---|---:|---:|---|---:|---|']
    for r in records:
        lines.append(f"|{r['fraction']}%|{r['profile']}|{r['scenario']}|{r.get('alice_promises','—')}|{r.get('alice_filled','—')}|{r.get('bob_before_alice','—')}|{r.get('evidence_count','—')}|{r.get('audit_verified',False)}|")
    lines += ['', '## 阅读边界','',
              '- 获证、登记、处理、成交分别统计；没有成交结果的超时样本保留。',
              '- 25% 的 2 个节点在容错范围内；50% 和 100% 是超范围压力测试。',
              '- 核对签名承诺与完整名单的矛盾；延迟、拒绝和扣留份额不直接等于可证明的说谎。',
              '- 证据表示同一节点的签名承诺与签名完整名单矛盾；没有自动扣押保证金。',
              '- 仅一组种子；不同链的共识调度会变化，不能当作性能定论。',
              '- 此处仅统计客户端 HTTP 请求体字节；不是全网通信成本。',
              '- 原始 network/ 含演示私钥，只分享汇总、动作、审计文件。','']
    (root/'REPORT.zh-CN.md').write_text('\n'.join(lines))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',default='bin/pinocchio')
    parser.add_argument('--out',required=True)
    parser.add_argument('--backend',choices=('scripted','chatgpt'),default='scripted')
    parser.add_argument('--model',default='gpt-6.1-sol')
    parser.add_argument('--state-dir',default='.local/chatgpt')
    parser.add_argument('--plans-file')
    parser.add_argument('--plan-only',action='store_true')
    parser.add_argument('--seed',type=int,default=20261023)
    parser.add_argument('--fractions',default='0,25,50,100')
    parser.add_argument('--scenarios',default=','.join(SCENARIOS))
    parser.add_argument('--profile',choices=('mixed','omission','refusal','withhold','delay'),default='mixed')
    parser.add_argument('--deadline',type=float,default=25)
    parser.add_argument('--lead-ms',type=int,default=100)
    parser.add_argument('--window-blocks',type=int,default=12)
    parser.add_argument('--base-port',type=int,default=49656)
    parser.add_argument('--api-port',type=int,default=50600)
    args=parser.parse_args()
    fractions=[int(s) for s in args.fractions.split(',')]
    scenarios=args.scenarios.split(',')
    if not set(fractions)<=set(FRACTIONS) or not set(scenarios)<=set(SCENARIOS):
        parser.error('choose documented fractions and scenarios')
    if not 8<=args.deadline<=120 or not 0<=args.lead_ms<=1500 or not 8<=args.window_blocks<=200:
        parser.error('deadline 8..120, lead 0..1500ms, window 8..200 blocks')
    root=Path(args.out).resolve()
    root.mkdir(parents=True,exist_ok=False,mode=0o700)
    model=None
    if args.plans_file:
        suite=json.loads(Path(args.plans_file).read_text())
        if suite.get('seed') != args.seed:
            parser.error('plan seed mismatch')
    else:
        if args.backend=='chatgpt':
            from chatgpt_model import ChatGPTModel
            model=ChatGPTModel(args.state_dir,args.model,max_calls=24,telemetry=root/'model-calls.jsonl')
        suite=plan_suite(args.seed,model)
    save(root/'plans.json',suite)
    if args.plan_only:
        print(root/'plans.json',flush=True)
        return
    records=[]
    try:
        for fraction in fractions:
            entries=json.loads(json.dumps(suite['nodes'][str(fraction)]))
            if args.profile!='mixed':
                for entry in entries:
                    if entry['liar_assigned']:
                        entry['plan']=scripted_plan(args.profile,seed=args.seed,actor_id=entry['actor'])
            for scenario in scenarios:
                label=f'{fraction:03d}-{args.profile}-{scenario}'
                print(f'START {label}',flush=True)
                trial=Trial(args.binary,root/label,entries,args)
                save(trial.root/'effective-policies.json',entries)
                try:
                    trial.start()
                    record=trial.run(scenario,suite['bob'][scenario])
                except (OSError,RuntimeError,ValueError,http.client.HTTPException,subprocess.SubprocessError) as exc:
                    record={'error':str(exc)[:1500]}
                finally:
                    trial.close()
                record.update(fraction=fraction,profile=args.profile,scenario=scenario,run=label,
                              policy_source=suite['backend'] if getattr(args,'profile','mixed')=='mixed' else 'designated-scripted-stress',
                              within_fault_bound=fraction<=25,assigned_liars=N*fraction//100)
                records.append(record)
                save(root/'progress.json',records)
                print(json.dumps({k:record.get(k) for k in ('run','alice_promises','alice_filled','bob_before_alice','evidence_count','audit_verified','error')}),flush=True)
    finally:
        summarize(root,records,suite,args)
    print(root/'REPORT.zh-CN.md',flush=True)
    if any('error' in r or not r.get('audit_verified') for r in records):
        raise SystemExit(1)


if __name__=='__main__':
    main()
