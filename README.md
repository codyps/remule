

## DB

1. get the most recent recv time for peers

    SELECT peer.id, peer.kad_id, peer.ip, peer.udp_port, b.recv_time FROM peer JOIN (SELECT source_peer, MAX(recv_time) recv_time FROM report GROUP BY source_peer) b ON b.source_peer = peer.id;

2. get number of peers never recv'd

    SELECT count(*) FROM peer LEFT OUTER JOIN report ON (report.source_peer = peer.id) WHERE report.source_peer IS NULL;

3. number of peers recv'd

    SELECT count(*) FROM (SELECT DISTINCT source_peer FROM report);

4. number of unqiue ips recv'd

    SELECT count(*) FROM (SELECT DISTINCT peer.ip FROM peer JOIN (SELECT DISTINCT source_peer FROM report) b ON peer.id = b.source_peer);

5. ips with more than 1 peer

    SELECT ip, count(*) FROM peer GROUP BY ip HAVING count(*) > 1;
