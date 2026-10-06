"""Native SMTP attachment verification. Run after copying into Arkime tests/."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(os.environ.get('ARKIME_TEST_ROOT', Path(__file__).resolve().parents[1]))


@unittest.skipUnless((ROOT / 'bin/pipeline.py').exists(), 'requires remote Arkime runtime')
class SmtpAttachment(unittest.TestCase):
    def test_split_attachment_has_sha256(self):
        sys.path[:0] = [str(ROOT/'tests'), str(ROOT/'bin')]
        from fixtures import tcp, record, HEADER
        from test_capture import capture
        payload = b'ordinary synthetic attachment for feature verification\n'
        encoded = base64.b64encode(payload)
        client, server, cp, sp = '192.0.2.100', '198.51.100.100', 43210, 25
        cseq, sseq = 1001, 2001
        events = [tcp(client,server,cp,sp,1000,0,2),
                  tcp(server,client,sp,cp,2000,1001,18),
                  tcp(client,server,cp,sp,cseq,sseq,16)]
        def send(direction, content):
            nonlocal cseq, sseq
            if direction == 'c':
                events.append(tcp(client,server,cp,sp,cseq,sseq,24,content)); cseq += len(content)
            else:
                events.append(tcp(server,client,sp,cp,sseq,cseq,24,content)); sseq += len(content)
        for direction, content in [
            ('s',b'220 fixture.example ESMTP\r\n'), ('c',b'EHLO example.test\r\n'),
            ('s',b'250 fixture.example\r\n'), ('c',b'MAIL FROM:<a@example.test>\r\n'),
            ('s',b'250 OK\r\n'), ('c',b'RCPT TO:<b@example.test>\r\n'),
            ('s',b'250 OK\r\n'), ('c',b'DATA\r\n'), ('s',b'354 Send message\r\n')]:
            send(direction, content)
        message = (b'From: a@example.test\r\nTo: b@example.test\r\nSubject: fixture\r\n'
                   b'MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary="fixture"\r\n\r\n'
                   b'--fixture\r\nContent-Type: application/octet-stream\r\n'
                   b'Content-Disposition: attachment; filename="sample.bin"\r\n'
                   b'Content-Transfer-Encoding: base64\r\n\r\n' + encoded +
                   b'\r\n--fixture--\r\n.\r\n')
        midpoint = len(message) - len(encoded) // 2 - 20
        send('c', message[:midpoint]); boundary = len(events)
        send('c', message[midpoint:]); send('s', b'250 Delivered\r\n')
        events.extend([tcp(client,server,cp,sp,cseq,sseq,17),
                       tcp(server,client,sp,cp,sseq,cseq+1,17)])
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); files = []
            for number, (start, end) in enumerate([(0,boundary),(boundary,len(events))]):
                path = directory / f'{number}.pcap'; files.append(str(path))
                with path.open('wb') as handle:
                    handle.write(HEADER)
                    for index in range(start,end):
                        handle.write(record(1700000000+index*.001, events[index]))
            listing = directory/'files.txt'; listing.write_text('\n'.join(files)+'\n')
            hits = capture(['-F',str(listing)],'test-smtp-sha256-enabled')
            digests = {value for hit in hits for value in hit['_source'].get('email',{}).get('sha256',[])}
            self.assertIn(hashlib.sha256(payload).hexdigest(), digests)


if __name__ == '__main__':
    unittest.main()
