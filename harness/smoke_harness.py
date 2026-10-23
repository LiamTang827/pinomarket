"""Opt-in real five-process test; uses new private run directory and local ports."""
import argparse
import json

from pinocchio_harness import Harness


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--run-dir', required=True)
    parser.add_argument('--base-port', type=int, default=42656)
    parser.add_argument('--api-port', type=int, default=43600)
    args = parser.parse_args()
    with Harness(args.binary, args.run_dir, args.base_port, args.api_port) as h:
        def call(name, **arguments):
            result = h.call(name, arguments)
            if not result['ok']:
                raise RuntimeError(json.dumps(result))
            return result
        call('initialize', ordering='identity')
        for node in range(5):
            call('start_node', node=node)
        call('ready')
        call('status')
        call('set_fault', node=0, fault='delay', delay_ms=100)
        call('ready')
        call('stop_node', node=4)
        result = call('measure', count=3, nonce=0)
        metrics = result['data']
        assert metrics['processed'] == 3 and metrics['incomplete'] == 0
        assert metrics['audit_verified'] is True
        call('audit')
    assert not h.processes
    print(json.dumps({'ok': True, 'processed': metrics['processed'],
                      'audit_verified': metrics['audit_verified'], 'cleanup': True}))


if __name__ == '__main__':
    main()
