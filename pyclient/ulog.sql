CREATE TABLE IF NOT EXISTS ulog_ct (
        flow_start_sec      INT UNSIGNED,
        flow_start_usec     INT UNSIGNED,
        flow_end_sec        INT UNSIGNED,
        flow_end_usec       INT UNSIGNED,
        orig_ip_saddr       INT UNSIGNED,
        orig_ip_daddr       INT UNSIGNED,
        orig_l4_sport       SMALLINT UNSIGNED,
        orig_l4_dport       SMALLINT UNSIGNED,
        orig_ip_protocol    TINYINT UNSIGNED,
        icmp_type       TINYINT UNSIGNED,
        icmp_code       TINYINT UNSIGNED,
        orig_raw_pktlen     INT UNSIGNED,
        orig_raw_pktcount   INT UNSIGNED,
        reply_raw_pktlen    INT UNSIGNED,
        reply_raw_pktcount  INT UNSIGNED,
        ct_mark         INT UNSIGNED);


