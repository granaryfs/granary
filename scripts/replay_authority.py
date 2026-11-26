#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Validate cadence traces, propose a submission bucket, and replay nanotokens."""

import argparse
import collections
import copy
import json
from pathlib import Path
import sys

SECOND = 1_000_000_000
MAX_ATTEMPTS = 64_000


def integer(value, field):
    if type(value) is int:
        return value
    if isinstance(value, str) and value and value.removeprefix('-').isascii() and value.removeprefix('-').isdigit():
        return int(value)
    raise ValueError(f'invalid scalar integer: {field}')


def control_tuple(value):
    """Match ControlsConfig::parse; the serial cap premise is checked separately."""
    if not isinstance(value, str):
        raise ValueError('tuple must be a string')
    fields = value.split(',')
    if (len(fields) != 5 or any(not f or not f.isascii() or not f.isdigit() for f in fields)):
        raise ValueError('invalid experimental tuple')
    parts = [int(f) for f in fields]
    if (min(parts) <= 0 or max(parts) > 18446744073709551615
            or parts[3] < 268435456 or parts[4] >= 8
            or any((burst + rate - 1) // rate > 4294967295
                   for rate, burst in ((parts[0], parts[1]), (parts[2], parts[3])))):
        raise ValueError('invalid experimental tuple')
    return parts


def trace(row):
    """Refuse incomplete serial coordinator evidence before using demand."""
    try:
        if not isinstance(row, dict):
            raise ValueError('measurement row must be an object')
        parts = control_tuple(row['tuple'])
        count = lambda key: integer(row[key], key)
        attempts = row['attempt_trace']
        if isinstance(attempts, str):
            attempts = json.loads(attempts)
        if not isinstance(attempts, list) or not 0 < len(attempts) <= MAX_ATTEMPTS:
            raise ValueError('empty or oversized trace')
        if len(attempts) != count('submissions_including_retransmissions'):
            raise ValueError('missing attempt in trace')
        successes = set()
        last_end = 0
        for index, a in enumerate(attempts):
            if not isinstance(a, dict):
                raise ValueError('malformed attempt trace')
            if type(a['attempt']) is not int:
                raise ValueError('invalid attempt fields')
            if a['attempt'] != index:
                raise ValueError('missing attempt in trace')
            for key in ('send_ns', 'end_ns', 'publication', 'status', 'body_bytes'):
                if type(a[key]) is not int or a[key] < 0:
                    raise ValueError('invalid attempt fields')
            if a['send_ns'] < last_end or a['end_ns'] < a['send_ns']:
                raise ValueError('non-monotonic attempt time')
            if (not isinstance(a['operation'], str) or not a['operation']
                    or not isinstance(a['volume'], str) or not a['volume']
                    or not isinstance(a['token'], str)):
                raise ValueError('invalid attempt identity')
            if a['status'] not in (200, 202, 429):
                raise ValueError('unsuccessful cadence attempt')
            if a['status'] != 429:
                successes.add(a['publication'])
            last_end = a['end_ns']
        if sum(a['status'] == 429 for a in attempts) != count('rate_limited_429'):
            raise ValueError('trace 429 count mismatch')
        completed = count('completed_publications')
        if (not 0 < completed <= len(attempts) or successes != set(range(completed))
                or any(a['publication'] >= completed for a in attempts)):
            raise ValueError('trace completed population mismatch')
        if count('sample_loss') != 0:
            raise ValueError('attempt trace overflow')
        if (count('max_in_flight_writes') != 1
                or max(a['body_bytes'] for a in attempts) != count('max_request_body_bytes')
                or any(not 0 < a['body_bytes'] <= 65536 for a in attempts)):
            raise ValueError('cadence byte or cap premise failed')
        if parts[4] <= 1:
            raise ValueError('cadence byte or cap premise failed')
        credit = parts[3] * SECOND
        previous = 0
        for a in attempts:
            credit = min(parts[3] * SECOND, credit + (a['send_ns'] - previous) * parts[2])
            credit -= a['body_bytes'] * SECOND
            if credit < 0:
                raise ValueError('cadence byte bucket could bind')
            previous = a['send_ns']
        return attempts
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError('malformed attempt trace') from error


def rolling(attempts):
    """All trailing (t-1s,t] windows at integer ns t from run start to completion.

    The p99 is time weighted, including idle windows. A sweep over every change
    point counts the complete domain without sampling aligned seconds.
    """
    end = max(a['end_ns'] for a in attempts)
    changes = collections.Counter()
    for a in attempts:
        if a['status'] != 429:
            changes[a['send_ns']] += 1
            changes[a['send_ns'] + SECOND] -= 1
    changes[0] += 0
    changes[end + 1] += 0
    histogram = collections.Counter()
    previous = 0
    count = 0
    for at, delta in sorted(changes.items()):
        if at > end + 1:
            break
        histogram[count] += at - previous
        count += delta
        previous = at
    population = end + 1
    cumulative = 0
    for value, weight in sorted(histogram.items()):
        cumulative += weight
        if cumulative * 100 >= population * 99:
            return value, max(v for v, weight in histogram.items() if weight)
    raise ValueError('empty rolling window population')


def excursion(attempts, rate):
    """Maximum inclusive event-interval demand minus continuous refill, in nanotokens."""
    minimum = None
    maximum = 0
    index = 0
    for a in attempts:
        if a['status'] == 429:
            continue
        value = index * SECOND - rate * a['send_ns']
        minimum = value if minimum is None else min(minimum, value)
        maximum = max(maximum, (index + 1) * SECOND - rate * a['send_ns'] - minimum)
        index += 1
    return maximum


def replay(attempts, rate, burst):
    if rate < 0 or burst < 1:
        raise ValueError('invalid replay bucket')
    credit = burst * SECOND
    previous = 0
    refused = []
    for a in attempts:
        # Original refusals did not consume a submission token. Demand evidence
        # is validated as non-binding separately; predictions retain identity.
        if a['status'] == 429:
            continue
        credit = min(burst * SECOND, credit + (a['send_ns'] - previous) * rate)
        previous = a['send_ns']
        if credit < SECOND:
            refused.append(dict(a))
        else:
            credit -= SECOND
    return refused


def candidate(rows, rate=None, burst=None):
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('measurement row must be an object')
        if row.get('label') != 'demand':
            raise ValueError('replay requires demand-labelled rows')
    traces = [trace(row) for row in rows]
    if not traces:
        raise ValueError('no demand traces')
    if any(any(a['status'] == 429 for a in attempts) for attempts in traces):
        raise ValueError('demand trace contains 429')
    demands = [rolling(attempts) for attempts in traces]
    selected_rate = 2 * max(p99 for p99, _ in demands) if rate is None else rate
    excursions = [excursion(attempts, selected_rate) for attempts in traces]
    selected_burst = max(1, (2 * max(excursions) + SECOND - 1) // SECOND) if burst is None else burst
    runs = []
    for row, attempts, demand, excess in zip(rows, traces, demands, excursions):
        refused = replay(attempts, selected_rate, selected_burst)
        runs.append(dict(seed=row.get('seed'), sequence=row.get('sequence'),
                         rolling_1s_p99=demand[0], rolling_1s_max=demand[1],
                         excursion_nanotokens=excess, predicted_refusals=refused,
                         predicted_refusal_count=len(refused)))
    return dict(rate=selected_rate, burst=selected_burst,
                window_population='all integer-ns trailing windows from run start through last completion',
                runs=runs, predicted_refusal_count=sum(r['predicted_refusal_count'] for r in runs))


def fixture(times):
    attempts = [dict(attempt=i, send_ns=t, end_ns=t, publication=i, operation=f'{i+1:032x}',
                     volume='v', status=202, token='', body_bytes=200) for i, t in enumerate(times)]
    return dict(label='demand', attempt_trace=attempts, submissions_including_retransmissions=len(times),
                rate_limited_429=0, completed_publications=len(times), sample_loss=0,
                max_in_flight_writes=1, max_request_body_bytes=200,
                tuple='1000000,1000000,1073741824,1073741824,4')


def self_test():
    valid = fixture([0, 250_000_000, 500_000_000, 750_000_000, SECOND])
    result = candidate([valid])
    assert (result['rate'], result['burst'], result['predicted_refusal_count']) == (8, 2, 0), result
    assert rolling(trace(valid)) == (4, 4)
    assert excursion(trace(fixture([0, 0, 100_000_000])), 4) == 2_600_000_000
    # An event-driven maximum catches a burst spanning an aligned-second boundary.
    assert rolling(trace(fixture([990_000_000, 1_010_000_000]))) == (1, 2)
    assert trace(dict(valid, tuple='4,4,33554432,268435456,7')) == valid['attempt_trace']
    cases = []
    for changes, message in [({'submissions_including_retransmissions': 6}, 'missing attempt in trace'),
                             ({'rate_limited_429': 1}, 'trace 429 count mismatch'),
                             ({'completed_publications': 6}, 'trace completed population mismatch'),
                             ({'sample_loss': 1}, 'attempt trace overflow'),
                             ({'max_in_flight_writes': 2}, 'cadence byte or cap premise failed'),
                             ({'max_request_body_bytes': 201}, 'cadence byte or cap premise failed'),
                             ({'tuple': '4,4,1,1,4'}, 'invalid experimental tuple'),
                             ({'tuple': '4,4,33554432,268435456,1'}, 'cadence byte or cap premise failed'),
                             ({'tuple': '4,4,33554432,268435456,8'}, 'invalid experimental tuple'),
                             ({'tuple': '4,4,33554432,268435455,4'}, 'invalid experimental tuple'),
                             ({'tuple': '1,4294967296,33554432,268435456,4'}, 'invalid experimental tuple'),
                             ({'tuple': []}, 'tuple must be a string'),
                             ({'submissions_including_retransmissions': []}, 'invalid scalar integer: submissions_including_retransmissions'),
                             ({'attempt_trace': []}, 'empty or oversized trace'),
                             ({'attempt_trace': [None] * (MAX_ATTEMPTS + 1)}, 'empty or oversized trace'),
                             ({'attempt_trace': '{broken'}, 'malformed attempt trace'),
                             ({'attempt_trace': [None] * 5}, 'malformed attempt trace')]:
        cases.append((dict(copy.deepcopy(valid), **changes), message))
    for key, value, message in [('attempt', 5, 'missing attempt in trace'),
                                ('send_ns', SECOND, 'non-monotonic attempt time'),
                                ('operation', '', 'invalid attempt identity'),
                                ('status', 0, 'unsuccessful cadence attempt'),
                                ('send_ns', [], 'invalid attempt fields'),
                                ('attempt', True, 'invalid attempt fields')]:
        wrong = copy.deepcopy(valid); wrong['attempt_trace'][0][key] = value
        cases.append((wrong, message))
    byte_trace = fixture([0] * 4097)
    byte_trace.update(tuple='4,4,1,268435456,4', max_request_body_bytes=65536)
    for a in byte_trace['attempt_trace']: a['body_bytes'] = 65536
    cases.append((byte_trace, 'cadence byte bucket could bind'))
    for wrong, message in cases:
        try:
            trace(wrong)
        except ValueError as error:
            assert str(error) == message, (str(error), message)
            print(f"replay refusal: {error}")
        else:
            raise AssertionError(f'control survived: {message}')
    assert cases
    labels = [None, 'acceptance', 'defaults', 'positive_control']
    for label in labels:
        wrong = dict(valid, label=label)
        try:
            candidate([wrong])
        except ValueError as error:
            assert str(error) == 'replay requires demand-labelled rows', error
        else:
            raise AssertionError('non-demand control survived')
    assert labels
    print(f'replay label controls: {len(labels)} refusals: replay requires demand-labelled rows')
    assert document_rows({'rows': [valid]}) == [valid]
    assert document_rows(valid) == [valid]
    shapes = [(None, 'measurement JSON root must be an object'),
              ([], 'measurement JSON root must be an object'),
              ({'rows': {}}, 'measurement rows must be objects'),
              ({'rows': [None]}, 'measurement rows must be objects')]
    for document, message in shapes:
        try:
            document_rows(document)
        except ValueError as error:
            assert str(error) == message, error
        else:
            raise AssertionError(f'JSON shape control survived: {message}')
    assert shapes
    print(f'replay JSON shape controls: {len(shapes)} named refusals')
    burst = candidate([fixture([0, 0, 0])], rate=1, burst=1)
    assert burst['predicted_refusal_count'] == 2, burst
    # A refused attempt must leave credit intact, rather than creating debt.
    assert len(replay(trace(fixture([0, 0, SECOND])), 1, 1)) == 1
    print(f'replay controls: valid r=8,b=2,refusals=0; {len(cases)} named malformed refusals; burst refusals=2')


def read_rows(path):
    text = path.read_text()
    if path.suffix == '.tsv':
        row = {}
        for line in text.splitlines():
            key, separator, value = line.partition('\t')
            if not separator or key in row:
                raise ValueError('malformed measurement row')
            row[key] = value
        return [row]
    return document_rows(json.loads(text))


def document_rows(document):
    if not isinstance(document, dict):
        raise ValueError('measurement JSON root must be an object')
    rows = document.get('rows', [document])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('measurement rows must be objects')
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--rate', type=int)
    parser.add_argument('--burst', type=int)
    parser.add_argument('traces', nargs='*', type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test(); return 0
    rows = [row for path in args.traces for row in read_rows(path)]
    result = candidate(rows, args.rate, args.burst)
    print(json.dumps(result, indent=2))
    return int(result['predicted_refusal_count'] > 0)


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('replay-authority.py checks with assert; run it without -O')
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        print(f'authority replay: {error}', file=sys.stderr)
        sys.exit(1)
