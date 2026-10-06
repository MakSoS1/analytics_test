from pathlib import Path
import difflib,tarfile
R=Path(__file__).resolve().parents[1];S=R/'downloads/arkime-6.8.0/capture'
with tarfile.open(R/'downloads/source.tar.gz') as archive:
    for name in ['arkime.h','packet.c','session.c','parsers/tcp.c','db.c','command.c','plugins/chad.c','reader-scheme.c']:
        (S/name).write_bytes(archive.extractfile('arkime-6.8.0/capture/'+name).read())
original={n:(S/n).read_text() for n in ['arkime.h','packet.c','session.c','parsers/tcp.c','db.c','command.c','plugins/chad.c','reader-scheme.c']}

def replace(name,old,new):
    p=S/name;t=p.read_text();assert t.count(old)==1,(name,old[:60],t.count(old));p.write_text(t.replace(old,new))
replace('arkime.h','    struct timeval         firstPacket;','''    uint64_t               officeInstance;
    uint8_t                officeSeenMask;
    uint8_t                officeFinMask;
    uint8_t                officeClosed;
    uint8_t                officeStartObserved;
    uint8_t                officeEndReason;
    struct timeval         firstPacket;''')
replace('arkime.h','void     arkime_session_flush();','''void arkime_session_flush();
void office_session_sweep(int thread, double now);
void office_session_checkpoint(int thread);
extern uint64_t officeFragmentSeq;
extern double officePacketClock[ARKIME_MAX_PACKET_THREADS];''')
replace('parsers/tcp.c','    if (!isNewSession && (tcphdr->th_flags & TH_SYN)', '    if (FALSE && !isNewSession && (tcphdr->th_flags & TH_SYN)')
replace('session.c','void arkime_session_mark_for_close(ArkimeSession_t *session)\n{','''void arkime_session_mark_for_close(ArkimeSession_t *session)
{
    /* The office lifecycle closes TCP after BOTH FIN directions/RST + idle,
     * not the native first-FIN close queue. DPI processing is unchanged. */
    if (session->ipProtocol == IPPROTO_TCP) return;''')
replace('session.c','    // Sessions Idle Long Time\n','''    // Sessions Idle Long Time
''')
replace('session.c','    for (int mProtocol = ARKIME_MPROTOCOL_MIN; mProtocol < mProtocolCnt; mProtocol++) {\n        for (int count = 0; count < 10; count++) {','''    for (int mProtocol = ARKIME_MPROTOCOL_MIN; mProtocol < mProtocolCnt; mProtocol++) {
        /* Office TCP/UDP expiry is done on the packet clock by full sweep. */
        if (mProtocols[mProtocol].ses == SESSION_TCP || mProtocols[mProtocol].ses == SESSION_UDP) continue;
        for (int count = 0; count < 10; count++) {''')
# One packet thread is a pinned contract. No hash-order early break for mixed timeouts.
with (S/'session.c').open('a') as f:f.write('''
uint64_t officeFragmentSeq;
double officePacketClock[ARKIME_MAX_PACKET_THREADS];
void office_session_sweep(int thread, double now)
{
    static double lastSweep[ARKIME_MAX_PACKET_THREADS];
    if (now > officePacketClock[thread]) officePacketClock[thread] = now;
    if (now - lastSweep[thread] <= 10.0) return;
    lastSweep[thread] = now;
    for (int m = ARKIME_MPROTOCOL_MIN; m < mProtocolCnt; m++) {
        ArkimeSession_t *session, *next;
        DLL_FOREACH_REMOVABLE(q_, &sessionThreadData[thread].sessionsQ[m], session, next) {
            if (session->ipProtocol != IPPROTO_TCP && session->ipProtocol != IPPROTO_UDP) continue;
            double limit = session->ipProtocol == IPPROTO_TCP ? (session->officeClosed ? 10.0 : (session->officeSeenMask == 3 ? 600.0 : 60.0)) : (session->officeSeenMask == 3 ? 300.0 : 30.0);
            double last = session->lastPacket.tv_sec + session->lastPacket.tv_usec / 1000000.0;
            if (now - last > limit) { session->officeEndReason = 1; arkime_session_save(session); }
        }
    }
}
void office_session_checkpoint(int thread)
{
    /* Runs on owning packet thread at file-done, keeps parser/reassembly alive. */
    for (int m = ARKIME_MPROTOCOL_MIN; m < mProtocolCnt; m++) {
        ArkimeSession_t *session;
        DLL_FOREACH(q_, &sessionThreadData[thread].sessionsQ[m], session) {
            if (session->packets[0] + session->packets[1] > 0) arkime_session_mid_save(session, session->lastPacket.tv_sec);
        }
    }
}
''')
replace('packet.c','    // Try at most 2 times\n','''    // Try at most 2 times
    static uint64_t officeNextInstance;
''')
replace('packet.c','            session->saveTime = packet->ts.tv_sec + config.tcpSaveTimeout;','''            session->officeInstance = ++officeNextInstance;
            session->saveTime = packet->ts.tv_sec + config.tcpSaveTimeout;''')
replace('packet.c','        int rc = mProtocols[packet->mProtocol].preProcess(session, packet, isNew);','''        if (!isNew && (packet->ipProtocol == IPPROTO_TCP || packet->ipProtocol == IPPROTO_UDP)) {
            const uint8_t *l4 = packet->pkt + packet->payloadOffset;
            uint16_t sport; memcpy(&sport, l4, 2); sport = ntohs(sport);
            gboolean same = ip4->ip_v == 4 ? (ARKIME_V6_TO_V4(session->addr1) == ip4->ip_src.s_addr) : (memcmp(session->addr1.s6_addr, ip6->ip6_src.s6_addr, 16) == 0);
            int direction = (same && sport == session->port1) ? 0 : 1;
            session->officeSeenMask |= 1 << direction;
            double gap = packet->ts.tv_sec - session->lastPacket.tv_sec + (packet->ts.tv_usec - session->lastPacket.tv_usec) / 1000000.0;
            double limit = packet->ipProtocol == IPPROTO_TCP ? (session->officeClosed ? 10.0 : (session->officeSeenMask == 3 ? 600.0 : 60.0)) : (session->officeSeenMask == 3 ? 300.0 : 30.0);
            gboolean syn = packet->ipProtocol == IPPROTO_TCP && (l4[13] & TH_SYN) && !(l4[13] & TH_ACK);
            if (gap > limit || (syn && session->officeClosed)) {
                session->officeEndReason = gap > limit ? 1 : 2;
                void arkime_session_save(ArkimeSession_t *session);
                arkime_session_save(session); continue;
            }
        }
        int rc = mProtocols[packet->mProtocol].preProcess(session, packet, isNew);''')
replace('packet.c','    session->lastPacket = packet->ts;','''    session->lastPacket = packet->ts;
    if (packet->ipProtocol == IPPROTO_TCP || packet->ipProtocol == IPPROTO_UDP) {
        session->officeSeenMask |= 1 << packet->direction;
        if (packet->ipProtocol == IPPROTO_TCP) {
            uint8_t flags = packet->pkt[packet->payloadOffset + 13];
            if (isNew) session->officeStartObserved = (flags & TH_SYN) && !(flags & TH_ACK);
            if (flags & TH_RST) session->officeClosed = 1;
            if (flags & TH_FIN) session->officeFinMask |= 1 << packet->direction;
            if (session->officeFinMask == 3) session->officeClosed = 1;
        } else if (isNew) session->officeStartObserved = 1;
    }
    if (packet->ipProtocol == IPPROTO_TCP || packet->ipProtocol == IPPROTO_UDP)
        office_session_sweep(thread, packet->ts.tv_sec + packet->ts.tv_usec / 1000000.0);''')
replace('packet.c','        if (unlikely(packet->pktlen == ARKIME_PACKET_LEN_FILE_DONE)) {','''        if (unlikely(packet->pktlen == ARKIME_PACKET_LEN_FILE_DONE)) {
            office_session_checkpoint(thread);''')
replace('db.c','    if (session->ethertype) {','''    BSB_EXPORT_sprintf(jbsb, "\\\"office\\\":{\\\"instance\\\":%" PRIu64 ",\\\"seq\\\":%" PRIu64 ",\\\"final\\\":%s,\\\"startObserved\\\":%s,\\\"closed\\\":%s,\\\"endReason\\\":%u},",
        session->officeInstance, ++officeFragmentSeq, final ? "true" : "false", session->officeStartObserved ? "true" : "false", session->officeClosed ? "true" : "false", session->officeEndReason);

    if (session->ethertype) {''')
replace('db.c','    if (!config.dryRun && !session->filePosArray->len)','    if (!config.dryRun && !session->filePosArray->len && !final)')

replace('arkime.h','extern uint64_t officeFragmentSeq;','extern uint64_t officeFragmentSeq;\nextern uint64_t officeFragmentPackets, officeReassembled;')
replace('packet.c','LOCAL void arkime_packet_frags4(ArkimePacketBatch_t *batch, ArkimePacket_t *const packet)\n{','uint64_t officeFragmentPackets, officeReassembled;\nLOCAL void arkime_packet_frags4(ArkimePacketBatch_t *batch, ArkimePacket_t *const packet)\n{\n    officeFragmentPackets++;')
replace('packet.c','    gboolean process = arkime_packet_frags_process(packet);','    gboolean process = arkime_packet_frags_process(packet);\n    if (process) officeReassembled++;')
replace('command.c','                 fn->filename, fn->packets, fn->bytes);','                 fn->filename, fn->packets, fn->bytes, officeFragmentSeq, arkimeCounters.totalPackets, officeFragmentPackets, officeReassembled, arkime_packet_dropped_frags(), arkimeCounters.packetStats[ARKIME_PACKET_IP_DROPPED] + arkimeCounters.packetStats[ARKIME_PACKET_OVERLOAD_DROPPED] + arkimeCounters.packetStats[ARKIME_PACKET_UNKNOWN_ETHER] + arkimeCounters.packetStats[ARKIME_PACKET_UNKNOWN_IP] + arkimeCounters.packetStats[ARKIME_PACKET_IPPORT_DROPPED] + arkimeCounters.packetStats[ARKIME_PACKET_DUPLICATE_DROPPED]);')
replace('command.c',' bytes=%" PRIu64 "\\n",',' bytes=%" PRIu64 " spiSeq=%" PRIu64 " processed=%" PRIu64 " fragmentPackets=%" PRIu64 " reassembled=%" PRIu64 " droppedFragments=%" PRIu64 " errors=%" PRIu64 "\\n",')
# Keep handshake validation state across mid-save, while flag counters stay deltas.
for statement in ['session->tcpData.ackTime = 0;','session->tcpData.synTime = 0;','session->tcpData.synAckSeq[0] = 0;','session->tcpData.synAckSeq[1] = 0;','session->tcpData.synSeen = 0;','session->tcpData.synAckSeen = 0;','session->tcpData.synValidated = 0;','session->tcpData.synAckValidated = 0;']:
    text=(S/'parsers/tcp.c').read_text();start=text.index('LOCAL void tcp_mid_save');end=text.index('/********',start)
    part=text[start:end];assert statement in part;part=part.replace(statement,'/* office: preserve handshake state */');(S/'parsers/tcp.c').write_text(text[:start]+part+text[end:])
replace('plugins/chad.c','int UNUSED(final))','int final)')
replace('plugins/chad.c','LOCAL void chad_plugin_save(ArkimeSession_t *session, int final)\n{','LOCAL void chad_plugin_save(ArkimeSession_t *session, int final)\n{\n    if (!final) return;')
replace('packet.c','    mProtocols[packet->mProtocol].createSessionId(sessionId, packet);','    mProtocols[packet->mProtocol].createSessionId(sessionId, packet);\n    /* One packet thread: make lookup hash consistent with decoded session ID. */\n    packet->hash = arkime_session_hash(sessionId);')

replace('arkime.h','extern uint64_t officeFragmentPackets, officeReassembled;','extern uint64_t officeFragmentPackets, officeReassembled, officeInputFileNum;\nuint64_t office_frag_hold_file(void);')
replace('reader-scheme.c','    LOG("Processing %s", uri);','    officeInputFileNum++;\n    LOG("Processing %s", uri);')
replace('packet.c','    char                   haveNoFlags;','    uint64_t               officeFirstFile;\n    char                   haveNoFlags;')
replace('packet.c','        frags->secs = packet->ts.tv_sec;','        frags->secs = packet->ts.tv_sec;\n        frags->officeFirstFile = officeInputFileNum;')
with (S/'packet.c').open('a') as f:f.write('\nuint64_t officeInputFileNum;\nuint64_t office_frag_hold_file(void) {\n    uint64_t minimum = officeInputFileNum + 1;\n    ArkimeFrags_t *entry;\n    ARKIME_LOCK(frags);\n    DLL_FOREACH(fragl_, &fragsList, entry) { if (entry->officeFirstFile < minimum) minimum = entry->officeFirstFile; }\n    ARKIME_UNLOCK(frags);\n    return minimum;\n}\n')
replace('command.c',' errors=%" PRIu64 "\\n",',' errors=%" PRIu64 " fileOrdinal=%" PRIu64 " holdFrom=%" PRIu64 "\\n",')
replace('command.c',' + arkimeCounters.packetStats[ARKIME_PACKET_DUPLICATE_DROPPED]);',' + arkimeCounters.packetStats[ARKIME_PACKET_DUPLICATE_DROPPED], officeInputFileNum, office_frag_hold_file());')

replace('session.c','void arkime_session_save(ArkimeSession_t *session)\n{','void arkime_session_save(ArkimeSession_t *session)\n{\n    if (!session->officeEndReason && (session->ipProtocol == IPPROTO_TCP || session->ipProtocol == IPPROTO_UDP)) {\n        double limit = session->ipProtocol == IPPROTO_TCP ? (session->officeClosed ? 10.0 : (session->officeSeenMask == 3 ? 600.0 : 60.0)) : (session->officeSeenMask == 3 ? 300.0 : 30.0);\n        double last = session->lastPacket.tv_sec + session->lastPacket.tv_usec / 1000000.0;\n        if (officePacketClock[session->thread] - last > limit) session->officeEndReason = 1;\n    }')
patch=''
for name,before in original.items():patch+=''.join(difflib.unified_diff(before.splitlines(True),(S/name).read_text().splitlines(True),fromfile='a/capture/'+name,tofile='b/capture/'+name))
(R/'config/office-lifecycle.patch').write_text(patch)
print('office lifecycle + file checkpoint patch written')
