#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Adrian Ana <adrian@adrianana.com>
# SPDX-License-Identifier: Apache-2.0
"""Exercise the standalone ready checker through its event-file command."""

import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import cmarkgfm
from cmarkgfm.cmark import Options


CHECK = Path(__file__).resolve().with_name('check-ready-pr-metadata.py')
SPEC = importlib.util.spec_from_file_location('ready_metadata_checker', CHECK)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
BODY = 'Explain why the runner check needs a timeout.'
CLASS = 'Class: E'
ASSISTED = 'Assisted-by: none'
FIELDS = f'{CLASS}\n{ASSISTED}'


class ReadyMetadataTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.event = Path(temp.name) / 'event.json'
        environment = patch.dict('os.environ', {
            'GITHUB_EVENT_NAME': 'pull_request',
            'GITHUB_REPOSITORY': 'granaryfs/granary',
        })
        environment.start()
        self.addCleanup(environment.stop)

    def with_identity(self, event):
        if not isinstance(event, dict) or not isinstance(event.get('pull_request'), dict):
            return event
        event = dict(event)
        pr = dict(event['pull_request'])
        event['pull_request'] = pr
        event.setdefault('action', 'opened')
        event.setdefault('repository', {'full_name': 'granaryfs/granary'})
        event.setdefault('number', 9)
        pr.setdefault('number', 9)
        pr.setdefault('base', {'repo': {'full_name': 'granaryfs/granary'}})
        return event

    def fetch_viewer(self, event):
        body = event['pull_request']['body']
        html = cmarkgfm.github_flavored_markdown_to_html(
            body, Options.CMARK_OPT_UNSAFE | Options.CMARK_OPT_HARDBREAKS,
        )
        return body, html

    def run_check(self, error, error_type=CHECKER.Refused):
        if error is None:
            CHECKER.check_event(self.event, fetcher=self.fetch_viewer)
        else:
            with self.assertRaises(error_type) as caught:
                CHECKER.check_event(self.event, fetcher=self.fetch_viewer)
            self.assertIn(error, str(caught.exception))

    def check(self, event, error=None, error_type=CHECKER.Refused):
        self.event.write_text(json.dumps(self.with_identity(event)), encoding='utf-8')
        self.run_check(error, error_type)

    def ready(self, tail, error=None):
        self.check({'pull_request': {'draft': False, 'title': 'check runner timeout',
                                     'body': f'{BODY}\n\n{tail}'}}, error)

    def test_draft_skips_ready_requirements(self):
        self.check({'pull_request': {'draft': True, 'body': None}})
        self.check({'pull_request': {'draft': True, 'body': BODY}})
        self.check({'pull_request': {'body': BODY}}, 'draft flag', CHECKER.Unavailable)
        self.check({'repository': {'full_name': 'other/repo'}, 'number': 0,
                    'pull_request': {'draft': True, 'body': None}},
                   'event identity', CHECKER.Unavailable)
        self.check({'action': 'ready_for_review',
                    'pull_request': {'draft': True, 'body': None}},
                   'action', CHECKER.Unavailable)
        for action in (None, 'unsubscribed'):
            self.check({'action': action,
                        'pull_request': {'draft': True, 'body': None}},
                       'identity', CHECKER.Unavailable)

    def test_malformed_input(self):
        self.run_check('could not read', CHECKER.Unavailable)
        for data in (b'{', b'\xff'):
            with self.subTest(data=data):
                self.event.write_bytes(data)
                self.run_check('could not read', CHECKER.Unavailable)
        for event in ([], {}, {'pull_request': None}, {'pull_request': []}):
            with self.subTest(event=event):
                self.check(event, 'event has no pull request', CHECKER.Unavailable)
        for state in (None, 0, 1, 0.0, 'false', [], {}):
            with self.subTest(state=state):
                self.check({'pull_request': {'draft': state, 'body': BODY}},
                           'draft flag', CHECKER.Unavailable)
        for pr in ({'draft': False}, {'draft': False, 'body': None}, {'draft': False, 'body': 1}):
            with self.subTest(pr=pr):
                self.check({'pull_request': pr}, 'ready PR body')

    def test_ready_metadata(self):
        for value in 'EIPSR':
            for newline in ('\n', '\r\n'):
                with self.subTest(valid_class=value, newline=newline):
                    body = newline.join((BODY, '', f'Class: {value}', ASSISTED))
                    self.check({'pull_request': {'draft': False, 'body': body}})
        self.ready('Task: Granary #5\nClass: I\nAssisted-by: Codex')
        self.ready('Class: E\nAssisted-by:  agent one')
        self.ready('Class: E\nAssisted-by: model_v2')
        self.ready('Class: E\nAssisted-by: agent one\n'
                   'Signed-off-by: A  Example <a@example.invalid>')
        self.ready("Class: E\nAssisted-by: agent one\n"
                   "Signed-off-by: Jamie O'Neil <jamie.o'neil@example.com>")
        self.ready('Class: E\nAssisted-by: agent one\n'
                   'Signed-off-by: Pat Example <pat+docs@localhost>')
        self.ready('Class: E\nAssisted-by: agent one\n'
                   'Signed-off-by: Pat Example <pat&docs@example.com>')
        self.ready('Class: E\nAssisted-by: agent one\nReviewed-by:\tX')
        self.ready('Task: Granary #5\nTask: Granary #6\nClass: I\nAssisted-by: Codex',
                   'ready PR')
        self.ready('Task:  \nClass: I\nAssisted-by: Codex', 'ready PR')
        self.ready('Task: _hidden_\nClass: I\nAssisted-by: Codex', 'ready PR')
        self.ready('Task: Granary #5  \nClass: I\nAssisted-by: Codex', 'ready PR')
        for label, trailers in (
            ('missing class', ASSISTED),
            ('missing assistance', CLASS),
            ('duplicate class', f'{FIELDS}\n{CLASS}'),
            ('duplicate assistance', f'{FIELDS}\nAssisted-by: editor'),
            ('invalid class', f'Class: X\n{ASSISTED}'),
            ('empty class', f'Class:\n{ASSISTED}'),
            ('blank assistance', f'{CLASS}\nAssisted-by: \t'),
            ('comment', f'<!--\n{FIELDS}\n-->'),
            ('backtick fence', f'```text\n{FIELDS}\n```'),
            ('tilde fence', f'~~~text\n{FIELDS}\n~~~'),
            ('earlier paragraph', f'{FIELDS}\n\nSigned-off-by: Alice Example <alice@example.invalid>'),
        ):
            with self.subTest(case=label):
                self.ready(trailers, 'ready PR')

        examples = f'```text\n{FIELDS}\n```\n\n<!--\n{FIELDS}\n-->'
        credits = 'AI-Reviewed-by: reviewer one\nAI-Reviewed-by: reviewer two'
        self.ready(f'{examples}\n\n{FIELDS}\n{credits}')

    def test_ready_metadata_code_span_boundaries(self):
        self.ready(f'The label is `runner\nnote`.\n\n{FIELDS}')
        self.ready(f'{CLASS}\nAssisted-by: `editor`\nNote: `runner`', 'ready PR')
        self.ready(f'{FIELDS}\nNote: \\`runner\nDetail: timeout`', 'ready PR')
        self.ready(f'{FIELDS}\nNote: ``runner\nDetail: timeout``',
                   'ready PR')
        self.ready(f'Note: \\`<!-- `\n{FIELDS}\nEnd: -->',
                   'ready PR')
        self.ready(f'{FIELDS}\nNote: \\` and `<!-- note -->`', 'ready PR')
        self.ready(f'{FIELDS}\nNote: \\\\`<!-- note -->`', 'ready PR')
        self.ready(f'Note: <span title="`"> <!-- `\n{FIELDS}\nDetail: -->',
                   'ready PR')
        self.ready(f'Note: <span title="`"> ``hello `\n{FIELDS}\nEnd: world``',
                   'ready PR')
        self.ready(f'{FIELDS}\nNote: <span title="`">x\nDetail: `y`',
                   'trailer block contains inline markup')

    def test_ready_metadata_visibility(self):
        for label, tail, error in (
            ('processing instruction', f'<?target\n\n{FIELDS}', 'ready PR'),
            ('declaration', f'<!DOCTYPE html\n\n{FIELDS}', 'ready PR'),
            ('CDATA', f'<![CDATA[\n\n{FIELDS}', 'ready PR'),
            ('pre block', f'<pre>\n\n{FIELDS}', 'ready PR'),
            ('style closer does not end pre block', f'<pre>\n</style>\n\n{FIELDS}', 'ready PR'),
            ('empty link', 'Class: E\nAssisted-by: [](x)', 'ready PR'),
            ('empty titled link', "Class: E\nAssisted-by: [](<a b> 'Codex')", 'ready PR'),
            ('empty image', 'Class: E\nAssisted-by: ![](x)', 'ready PR'),
            ('empty reference link', '[none]: /target\n\nClass: E\nAssisted-by: [][none]', 'ready PR'),
            ('empty reference image', '[x]: /target\n\nClass: E\nAssisted-by: ![][x]', 'ready PR'),
            ('linked empty image', 'Class: E\nAssisted-by: [![](x)](y)', 'ready PR'),
            ('empty HTML label', 'Class: E\nAssisted-by: [<span></span>](x)', 'ready PR'),
            ('visible link label is outside the plain trailer grammar',
             'Class: E\nAssisted-by: [Codex](x)', 'ready PR'),
            ('visible titled label is outside the plain trailer grammar',
             'Class: E\nAssisted-by: [Codex](a(b)c (title))', 'ready PR'),
            ('visible email autolink', 'Class: E\nAssisted-by: <editor@example.invalid>', None),
            ('visible URL autolink', 'Class: E\nAssisted-by: <https://example.invalid>', None),
            ('emphasis changes assistance text', 'Class: E\nAssisted-by: _Codex_', 'ready PR'),
            ('literal angle after email', 'Class: E\nAssisted-by: <editor@example.invalid><', 'ready PR'),
            ('literal link in code span', 'Class: E\nAssisted-by: `[](x)`', 'ready PR'),
            ('empty span', 'Class: E\nAssisted-by: <span></span>', 'ready PR'),
            ('zero width space', 'Class: E\nAssisted-by: \u200b', 'ready PR'),
            ('space entity', 'Class: E\nAssisted-by: &#32;', 'ready PR'),
            ('Hangul filler entity', 'Class: E\nAssisted-by: &#x3164;', 'ready PR'),
            ('Hangul filler with visible text is outside the literal grammar',
             'Class: E\nAssisted-by: &#x3164;한', 'ready PR'),
            ('entity text is outside the literal trailer grammar',
             'Class: E\nAssisted-by: &#x6e;one', 'ready PR'),
            ('bare CR between valid trailers', f'{CLASS}\r{ASSISTED}',
             'ready PR body contains a lone carriage return'),
            ('literal comment in code span', 'Class: E\nAssisted-by: `<!-- note -->`', 'ready PR'),
            ('fenced declaration', f'```text\n<!DOCTYPE html\n```\n\n{FIELDS}', None),
            ('inline comment before raw block',
             f'Explain <!-- note.\n\n<pre>\n-->\n\n{FIELDS}', 'ready PR'),
            ('inline comment before fence',
             f'Explain <!-- note.\n\n```text\n-->\n\n{FIELDS}', 'ready PR'),
        ):
            with self.subTest(case=label):
                self.ready(tail, error)

    def test_hidden_terminal_lines_are_refused(self):
        cases = (
            ('comment interrupted by pre',
             f'Explain <!-- note.\n<pre>\n-->\n\n{FIELDS}',
             'terminal metadata is not a root paragraph'),
            ('multiline HTML attribute',
             f'Note: <span title="\n{FIELDS}\nEnd: ">',
             'at most one literal Task'),
            ('inline processing instruction',
             f'Note: <?xml\n{FIELDS}\nEnd: ?>',
             'at most one literal Task'),
            ('inline declaration',
             f'Note: <!DOCTYPE\n{FIELDS}\nEnd: >',
             'at most one literal Task'),
            ('inline CDATA',
             f'Note: <![CDATA[\n{FIELDS}\nEnd: ]]>',
             'at most one literal Task'),
            ('multiline link title',
             f'Note: [context](https://example.invalid "\n{FIELDS}\nEnd: ")',
             'at most one literal Task'),
            ('hidden signer with rendered decoy',
             'Class: E\nAssisted-by: [none](https://example.invalid "\n'
             'Signed-off-by: Attacker <attacker@example.invalid>\n'
             'Note: ")<br>Signed-off-by: Maintainer '
             '<maintainer@example.invalid><br>Note: ok',
             'trailer block contains inline markup'),
            ('ruby pronunciation fallback is visually hidden',
             'Class: E\nAssisted-by: <ruby><rp>none</rp></ruby>',
             'trailer block contains inline markup'),
        )
        for name, tail, first_refusal in cases:
            with self.subTest(case=name):
                self.ready(tail, first_refusal)

    def test_rendered_declarations_require_viewer_check(self):
        for name, tail, first_refusal in (
            ('split HTML duplicate',
             '<p>Cl<span>ass</span>: E<br>Assisted<span>-by</span>: none</p>\n\n'
             f'{FIELDS}\nSigned-off-by: Adrian Ana <adrian@adrianana.com>',
             'viewer has 2 declarations for class'),
            ('closed disclosure wraps metadata',
             '<details><summary>Notes</summary>\n\n'
             f'{FIELDS}\nSigned-off-by: Adrian Ana <adrian@adrianana.com>',
             'not a root viewer paragraph'),
            ('encoded decoy and hidden literal',
             f'Cl&#97;ss: E  \nAssisted&#45;by: none\n\n<!--\n{FIELDS}',
             'body must end with a standalone trailer block'),
        ):
            with self.subTest(case=name):
                self.ready(tail, first_refusal)

    def test_captured_viewer_structure(self):
        fixtures = (
            (
                '<p>Cl<span>ass</span>: E<br>Assisted<span>-by</span>: none</p>\n\n'
                f'{FIELDS}\nSigned-off-by: Adrian Ana <adrian@adrianana.com>',
                '<p dir="auto">Cl<span>ass</span>: E<br>Assisted<span>-by</span>: none</p>\n'
                '<p dir="auto">Class: E<br>\nAssisted-by: none<br>\n'
                'Signed-off-by: Adrian Ana <a href="mailto:adrian@adrianana.com">'
                'adrian@adrianana.com</a></p>',
                '2 declarations for class',
            ),
            (
                '<details><summary>Notes</summary>\n\n'
                f'{FIELDS}\nSigned-off-by: Adrian Ana <adrian@adrianana.com>',
                '<details><summary>Notes</summary>\n<p dir="auto">Class: E<br>\n'
                'Assisted-by: none<br>\nSigned-off-by: Adrian Ana '
                '<a href="mailto:adrian@adrianana.com">adrian@adrianana.com</a>'
                '</p></details>',
                'root viewer paragraph',
            ),
            (
                f'{BODY}\n\nCl`ass`: E\n\n{FIELDS}',
                '<p dir="auto">Explain why the runner check needs a timeout.</p>\n'
                '<p dir="auto">Cl<code class="notranslate">ass</code>: E</p>\n'
                '<p dir="auto">Class: E<br>\nAssisted-by: none</p>',
                '2 declarations for class',
            ),
            (
                f'{BODY}\n\nAssisted-<span>by</span>: none\n\n{FIELDS}',
                '<p dir="auto">Explain why the runner check needs a timeout.</p>\n'
                '<p dir="auto">Assisted-<span>by</span>: none</p>\n'
                '<p dir="auto">Class: E<br>\nAssisted-by: none</p>',
                '2 declarations for assisted-by',
            ),
        )
        for body, html, message in fixtures:
            with self.subTest(message=message):
                CHECKER.local_origin(body)
                _text, _first, _last, block, class_at = CHECKER.terminal(body)
                with self.assertRaises(CHECKER.Refused) as caught:
                    CHECKER.check_body_html(html, block, class_at)
                self.assertIn(message, str(caught.exception))

    def test_github_generated_html_before_trailers(self):
        _text, _first, _last, block, class_at = CHECKER.terminal(
            f'{BODY}\n\n{FIELDS}'
        )
        for prefix in (
            '<p dir="auto"><a href="https://camo.githubusercontent.com/x">'
            '<img src="https://camo.githubusercontent.com/x" alt="diagram" '
            'style="max-width: 100%;"></a></p>',
            '<div class="markdown-alert markdown-alert-note" dir="auto">'
            '<p class="markdown-alert-title" dir="auto">'
            '<svg aria-hidden="true"><path d="M0 0"></path></svg>Note</p>'
            '<p dir="auto">Relevant warning.</p></div>',
            '<div><p>Note <svg aria-hidden="true"><path d="M0 0"/></svg>'
            '</p></div>',
        ):
            with self.subTest(prefix=prefix[:50]):
                html = prefix + '<p dir="auto">Class: E<br>\nAssisted-by: none</p>'
                self.assertEqual(CHECKER.check_body_html(html, block, class_at),
                                 ('Class: E', 'Assisted-by: none'))

    def test_hidden_terminal_viewer_markup_is_refused(self):
        _text, _first, _last, block, class_at = CHECKER.terminal(
            f'{BODY}\n\n{FIELDS}'
        )
        for html in (
            '<p dir="auto" style="display:none">Class: E<br>Assisted-by: none</p>',
            '<p dir="auto"><span hidden>Class: E</span><br>Assisted-by: none</p>',
            '<p dir="auto">Class: E<br>Assisted-by: '
            '<ruby><rp>none</rp></ruby></p>',
            '<p dir="auto">Class: E<br>Assisted-by: <video>none</video></p>',
            '<p dir="auto">Class: E<br>Assisted-by: <a popover>none</a></p>',
        ):
            with self.subTest(html=html[:60]):
                with self.assertRaises(CHECKER.Refused):
                    CHECKER.check_body_html(html, block, class_at)

    def test_hidden_earlier_inline_text_cannot_mask_duplicate(self):
        _text, _first, _last, block, class_at = CHECKER.terminal(
            f'{BODY}\n\n{FIELDS}'
        )
        for attribute in ('hidden', 'style="display:none"', 'aria-hidden="true"'):
            with self.subTest(attribute=attribute):
                html = (f'<p>Cl<span {attribute}>noise</span>ass: S</p>'
                        '<p dir="auto">Class: E<br>Assisted-by: none</p>')
                with self.assertRaises(CHECKER.Refused):
                    CHECKER.check_body_html(html, block, class_at)
        with self.assertRaisesRegex(CHECKER.Refused, 'direction'):
            CHECKER.check_body_html(
                '<p><bdo dir="rtl">S :ssalC</bdo></p>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, '2 declarations for class'):
            CHECKER.check_body_html(
                '<div><address>Contact</address><address>Class: S</address></div>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, '2 declarations for class'):
            CHECKER.check_body_html(
                '<fieldset><legend>Notes</legend>Class: S</fieldset>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, '2 declarations for class'):
            CHECKER.check_body_html(
                '<blockquote><p dir="auto">English explanation.</p>'
                '<p dir="auto">א<br>123 Class: S</p></blockquote>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, '2 declarations for class'):
            CHECKER.check_body_html(
                '<blockquote><p dir="auto">English explanation.</p>'
                '<div dir="auto">א<br>123 Class: S</div></blockquote>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, '2 declarations for class'):
            CHECKER.check_body_html(
                '<div dir="auto"><span dir="auto">Intro</span>א<br>'
                '123 Class: S</div>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, '2 declarations for class'):
            CHECKER.check_body_html(
                '<div dir="auto"><pre>א</pre>123 Class: S</div>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, '2 declarations for class'):
            CHECKER.check_body_html(
                '<div><span dir="auto">א<br>123 Class: S</span></div>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, 'visible SVG'):
            CHECKER.check_body_html(
                '<p><svg><text>Class: S</text></svg></p>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, 'SVG'):
            CHECKER.check_body_html(
                '<p><svg aria-hidden="true"><text>Class: S</text></svg></p>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )
        with self.assertRaisesRegex(CHECKER.Refused, 'SVG'):
            CHECKER.check_body_html(
                '<p><svg aria-hidden="true"><image href="/declaration.svg">'
                '</image></svg></p>'
                '<p dir="auto">Class: E<br>Assisted-by: none</p>', block, class_at,
            )

    def test_viewer_values_must_match_source(self):
        _text, _first, _last, block, class_at = CHECKER.terminal(
            f'{BODY}\n\n{FIELDS}\nSigned-off-by: Adrian Ana <adrian@adrianana.com>'
        )
        for html in (
            '<p dir="auto">Class: E<br>Assisted-by: other<br>'
            'Signed-off-by: Adrian Ana <a href="mailto:adrian@adrianana.com">'
            'adrian@adrianana.com</a></p>',
            '<p dir="auto">Class: E<br>Assisted-by: none<br>'
            'Signed-off-by: Other <a href="mailto:adrian@adrianana.com">'
            'adrian@adrianana.com</a></p>',
        ):
            with self.subTest(html=html[:70]):
                with self.assertRaises(CHECKER.Refused):
                    CHECKER.check_body_html(html, block, class_at)

    def test_event_body_mismatch_and_draft_skip(self):
        body = f'{BODY}\n\n{FIELDS}'
        event = self.with_identity({'pull_request': {'draft': False, 'body': body}})
        self.event.write_text(json.dumps(event), encoding='utf-8')
        with self.assertRaises(CHECKER.Unavailable) as caught:
            CHECKER.check_event(self.event, fetcher=lambda _event: (body + '!', ''))
        self.assertIn('body differs', str(caught.exception))
        with self.assertRaises(CHECKER.Refused):
            CHECKER.check_event(self.event, fetcher=lambda _event: (body, '<p>unclosed'))
        event['pull_request']['draft'] = True
        self.event.write_text(json.dumps(event), encoding='utf-8')
        CHECKER.check_event(self.event, fetcher=lambda _event: self.fail('draft queried viewer'))
        with patch.object(CHECKER.cmarkgfm, 'github_flavored_markdown_to_html',
                          side_effect=RuntimeError('renderer down')):
            with self.assertRaises(CHECKER.Unavailable):
                CHECKER.local_origin(body)

    def test_missing_viewer_credential_refuses(self):
        repo = 'granaryfs/granary'
        event = {
            'action': 'opened',
            'repository': {'full_name': repo},
            'number': 9,
            'pull_request': {
                'number': 9, 'draft': False, 'body': f'{BODY}\n\n{FIELDS}',
                'base': {'repo': {'full_name': repo}},
            },
        }
        with patch.dict('os.environ', {
            'GITHUB_EVENT_NAME': 'pull_request',
            'GITHUB_REPOSITORY': repo,
            'GITHUB_TOKEN': '',
        }, clear=True):
            with self.assertRaises(CHECKER.Unavailable) as caught:
                CHECKER.fetch_viewer(event)
        self.assertIn('credential', str(caught.exception))

    def test_spaced_visible_label_is_a_duplicate(self):
        for earlier in (
            'Class : S', 'Assisted-by : unknown', 'Cl\u034fass: S',
            'Assisted-\u034fby: unknown', 'Cl\u200dass: S',
            'Class\uff1a S',
            '\u0421lass: S', 'Class\u2236 S', 'Class\ua789 S',
            'Assisted\u2010by: unknown',
            '\u0640 Class: S', '\u05d0 Assisted-by: unknown',
        ):
            with self.subTest(earlier=earlier):
                self.ready(f'{earlier}\n\n{FIELDS}', 'viewer has 2 declarations')
        self.ready(f'\u202eS :ssalC\u202c\n\n{FIELDS}', 'bidirectional controls')
        self.ready(f'\u05d0  \n123 Class: S\n\n{FIELDS}', 'viewer has 2 declarations')

    def test_unicode_shaping_in_description_does_not_hide_trailers(self):
        self.check({'pull_request': {'draft': False,
                                     'body': f'👩\u200d💻 reviewed the change.\n\n{FIELDS}'}})

    def test_block_nested_inside_viewer_paragraph_is_refused(self):
        _text, _first, _last, block, class_at = CHECKER.terminal(
            f'{BODY}\n\n{FIELDS}'
        )
        html = '<p dir="auto">Class: E<br>Assisted-by: none<pre>extra</pre></p>'
        with self.assertRaisesRegex(CHECKER.Refused, 'block nested inside'):
            CHECKER.check_body_html(html, block, class_at)

    def test_source_span_and_viewer_attribute_guards(self):
        body = f'{BODY}\n\n{FIELDS}'
        self.assertEqual(CHECKER.local_origin(body), (3, 1, 4, 17))
        with patch.object(CHECKER.cmarkgfm, 'github_flavored_markdown_to_html',
                          return_value='<p data-sourcepos="1:1-1:1">Class: E</p>'):
            with self.assertRaisesRegex(CHECKER.Refused, 'does not span the literal'):
                CHECKER.local_origin(body)
        with self.assertRaisesRegex(CHECKER.Refused, 'not a root paragraph'):
            CHECKER.local_origin(f'{BODY}\n\n<pre>\n\n{FIELDS}')
        _text, _first, _last, block, class_at = CHECKER.terminal(body)
        with self.assertRaisesRegex(CHECKER.Refused, 'unexpected attributes'):
            CHECKER.check_body_html('<p class="x">Class: E<br>Assisted-by: none</p>',
                                    block, class_at)

    def test_blank_symbol_cannot_fill_assistance(self):
        self.ready('Class: E\nAssisted-by: \u2800', 'ready PR')
        self.ready('Class: E\nAssisted-by: none\u2028Class: S', 'ready PR')
        self.ready('Class: E\nAssisted-by: 🤖', 'visible')

    def test_graphql_response_boundary(self):
        repo = 'granaryfs/granary'
        body = f'{BODY}\n\n{FIELDS}'
        event = {
            'action': 'opened',
            'repository': {'full_name': repo}, 'number': 9,
            'pull_request': {
                'number': 9, 'draft': False, 'body': body,
                'base': {'repo': {'full_name': repo}},
            },
        }

        class Headers:
            def __init__(self, content_type, content_length=None):
                self.content_type = content_type
                self.content_length = content_length

            def get_content_type(self):
                return self.content_type

            def get(self, name):
                return self.content_length if name == 'Content-Length' else None

        class Response:
            def __init__(self, payload, status=200, content_type='application/json',
                         content_length=None):
                self.payload = payload
                self.status = status
                self.headers = Headers(content_type, content_length)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, limit):
                return self.payload[:limit]

        good_html = ('<p dir="auto">Explain why the runner check needs a timeout.</p>'
                     '<p dir="auto">Class: E<br>Assisted-by: none</p>')

        def reply(**changes):
            pull = {'number': 9, 'body': body, 'bodyHTML': good_html}
            pull.update(changes)
            return json.dumps({'data': {'repository': {
                'nameWithOwner': repo, 'pullRequest': pull,
            }}}).encode()

        def run(payload, through_event=False, status=200,
                content_type='application/json', content_length=None):
            class Connection:
                def __init__(self, host, timeout, context):
                    if host != 'api.github.com' or timeout != 5 or context is None:
                        raise AssertionError('viewer query used an unexpected HTTPS destination')

                def request(self, method, path, payload, headers):
                    if (method, path, headers['Authorization']) != (
                        'POST', '/graphql', 'Bearer test-token',
                    ):
                        raise AssertionError('viewer query used an unexpected request')
                    request = json.loads(payload)
                    if request['variables'] != {
                        'owner': 'granaryfs', 'name': 'granary', 'number': 9,
                    } or not re.search(
                        r'\bnameWithOwner\b.*\bpullRequest\s*\(\s*number:\s*\$number\s*\)'
                        r'\s*\{\s*number\s+body\s+bodyHTML\s*\}',
                        request['query'], re.DOTALL,
                    ):
                        raise AssertionError('viewer query addressed the wrong PR or field')

                def getresponse(self):
                    return Response(payload, status, content_type, content_length)

                def close(self):
                    pass

            with patch.dict('os.environ', {
                'GITHUB_EVENT_NAME': 'pull_request',
                'GITHUB_REPOSITORY': repo,
                'GITHUB_TOKEN': 'test-token',
            }, clear=True), patch.object(CHECKER.http.client, 'HTTPSConnection', Connection):
                if through_event:
                    self.event.write_text(json.dumps(event), encoding='utf-8')
                    return CHECKER.check_event(self.event)
                return CHECKER.fetch_viewer(event)

        self.assertEqual(run(reply()), (body, good_html))
        self.assertEqual(run(reply(), through_event=True), (3, 1, 4, 17))
        with self.assertRaisesRegex(CHECKER.Unavailable, 'incomplete'):
            run(reply(), content_length=str(len(reply()) + 1))
        with self.assertRaisesRegex(CHECKER.Unavailable, 'length'):
            run(reply(), content_length='not-a-number')
        with patch.object(CHECKER, 'QUERY',
                          CHECKER.QUERY.replace('number body bodyHTML',
                                                'number bodyHTML')):
            with self.assertRaises(AssertionError):
                run(reply())
        for status, content_type in ((503, 'application/json'), (200, 'text/html')):
            with self.subTest(status=status, content_type=content_type):
                with self.assertRaisesRegex(CHECKER.Unavailable, 'query failed'):
                    run(reply(), status=status, content_type=content_type)
        duplicate_reply = reply().replace(b'"number": 9, "body":',
                                          b'"number": 9, "number": 9, "body":', 1)
        self.assertNotEqual(duplicate_reply, reply())
        with self.assertRaisesRegex(CHECKER.Unavailable, 'duplicate key'):
            run(duplicate_reply)
        for payload in (
            reply(number=10), reply(bodyHTML=None), reply(bodyHTML=good_html + '\0'),
            json.dumps({'data': {'repository': {
                'nameWithOwner': 'other/repo', 'pullRequest': {
                    'number': 9, 'body': body, 'bodyHTML': good_html,
                },
            }}}).encode(),
            b'{"errors":[{"message":"denied"}]}', b'{}', b'{',
            *(reply().replace(b'{"data":',
                               b'{"errors":' + error + b',"data":', 1)
              for error in (b'false', b'null', b'{}', b'[]')),
        ):
            with self.subTest(payload=payload[:40]):
                with self.assertRaises(CHECKER.Unavailable):
                    run(payload)
        oversized = reply() + b' ' * (CHECKER.HTML_CHARS + 1)
        with self.assertRaisesRegex(CHECKER.Unavailable, 'response exceeds byte limit'):
            run(oversized)

    def test_fetcher_event_identity_guard(self):
        repo = 'granaryfs/granary'
        good = {
            'action': 'opened',
            'repository': {'full_name': repo}, 'number': 9,
            'pull_request': {'number': 9, 'base': {'repo': {'full_name': repo}}},
        }
        changes = (
            ('event type', {'GITHUB_EVENT_NAME': 'pull_request_target'}, good),
            ('missing action', {}, {key: value for key, value in good.items()
                                    if key != 'action'}),
            ('action is Boolean', {}, {**good, 'action': True}),
            ('environment repository', {'GITHUB_REPOSITORY': 'other/repo'}, good),
            ('event repository', {}, {**good, 'repository': {'full_name': 'other/repo'}}),
            ('base repository', {}, {**good, 'pull_request': {
                'number': 9, 'base': {'repo': {'full_name': 'other/repo'}},
            }}),
            ('number is Boolean', {}, {**good, 'number': True}),
            ('number is zero', {}, {**good, 'number': 0}),
            ('PR number mismatch', {}, {**good, 'pull_request': {
                'number': 10, 'base': {'repo': {'full_name': repo}},
            }}),
        )
        for name, env_delta, event in changes:
            with self.subTest(case=name):
                env = {'GITHUB_EVENT_NAME': 'pull_request',
                       'GITHUB_REPOSITORY': repo, 'GITHUB_TOKEN': 'test-token'}
                env.update(env_delta)
                with patch.dict('os.environ', env, clear=True), patch.object(
                    CHECKER.http.client, 'HTTPSConnection',
                    side_effect=AssertionError('invalid identity reached network'),
                ):
                    with self.assertRaisesRegex(CHECKER.Unavailable, 'identity'):
                        CHECKER.fetch_viewer(event)

    def test_cli_and_invalid_json_tokens(self):
        valid = json.dumps(self.with_identity({'pull_request': {'draft': True}})).encode()
        ready_without_body = json.dumps(
            self.with_identity({'pull_request': {'draft': False}})
        ).encode()
        duplicate = valid.replace(b'"draft": true', b'"draft": true, "draft": true', 1)
        self.assertNotEqual(duplicate, valid)
        for data, expected, code in (
            (valid, None, 0),
            (ready_without_body, 'ready PR body must be a string', 1),
            (duplicate, 'JSON has a duplicate key', 3),
            (valid[:-1] + b', "n": NaN}', 'JSON has an invalid constant', 3),
            (valid[:-1] + b', "n": ' + b'9' * 5000 + b'}',
             'could not read PR event JSON', 3),
        ):
            with self.subTest(size=len(data), value=data[:80]):
                self.event.write_bytes(data)
                result = subprocess.run([sys.executable, '-I', str(CHECK), str(self.event)],
                                        capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, code)
                if expected is not None:
                    self.assertIn(expected, result.stderr)
                    self.assertNotIn('Traceback', result.stderr)
        usage = subprocess.run([sys.executable, '-I', str(CHECK)],
                               capture_output=True, text=True, check=False)
        self.assertEqual(usage.returncode, 2)
        self.assertIn('usage:', usage.stderr)
        usage_no_dependency = subprocess.run(
            [sys.executable, '-S', '-I', str(CHECK)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(usage_no_dependency.returncode, 2)
        self.assertIn('usage:', usage_no_dependency.stderr)
        self.event.write_text(json.dumps(self.with_identity({'pull_request': {
            'draft': False, 'body': f'{BODY}\n\n{FIELDS}',
        }})), encoding='utf-8')
        unavailable = subprocess.run([sys.executable, '-S', '-I', str(CHECK),
                                      str(self.event)], capture_output=True,
                                     text=True, check=False)
        self.assertEqual(unavailable.returncode, 3)
        self.assertIn('dependency', unavailable.stderr)
        with patch.dict('os.environ', {'GITHUB_TOKEN': ''}):
            api_unavailable = subprocess.run(
                [sys.executable, '-I', str(CHECK), str(self.event)],
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(api_unavailable.returncode, 3)
        self.assertIn('unavailable:', api_unavailable.stderr)
        self.assertIn('GitHub credential is unavailable', api_unavailable.stderr)
        self.assertNotIn('Traceback', api_unavailable.stderr)


if __name__ == '__main__':
    unittest.main()
