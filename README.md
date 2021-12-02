

## DB

1. get the most recent recv time for peers

    SELECT peer.id, peer.kad_id, peer.ip, peer.udp_port, b.recv_time FROM peer JOIN (SELECT source_peer, MAX(recv_time) recv_time FROM report GROUP BY source_peer) b ON b.source_peer = peer.id;

1b. get most recent recv but don't filter peers without recvs

    SELECT peer.*, b.recv_time FROM peer LEFT OUTER JOIN (SELECT source_peer, MAX(recv_time) recv_time FROM report GROUP BY source_peer) b ON b.source_peer = peer.id;

2. get number of peers never recv'd

    SELECT count(*) FROM peer LEFT OUTER JOIN report ON (report.source_peer = peer.id) WHERE report.source_peer IS NULL;

3. number of peers recv'd

    SELECT count(*) FROM (SELECT DISTINCT source_peer FROM report);

4. number of unqiue ips recv'd

    SELECT count(*) FROM (SELECT DISTINCT peer.ip FROM peer JOIN (SELECT DISTINCT source_peer FROM report) b ON peer.id = b.source_peer);

5. ips with more than 1 peer

    SELECT ip, count(*) FROM peer GROUP BY ip HAVING count(*) > 1;

6. kad ids with more than 1 peer

    # TODO: seems like we should be able to optimize this by using the primary key

    SELECT a.* FROM peer a JOIN (SELECT kad_id, COUNT(*) FROM peer GROUP BY kad_id HAVING count(*) > 1) b ON a.kad_id = b.kad_id ORDER BY kad_id;

    # Alternate, but doesn't seem better
    # Also, seems funny that the `SELECT DISTINCT` is required. Implies the JOIN isn't quite right
    # EXPLAIN is shorter than the above option though (which is a real mess in EXPLAIN).
    # also, we'd really need to to another join to get other fields like the above option
    SELECT count(*) FROM (SELECT DISTINCT a.id FROM peer a INNER JOIN peer b ON a.id <> b.id AND a.kad_id = b.kad_id ORDER BY a.kad_id);
