
@load base/frameworks/notice

module SCCREW;

export {
	redef enum Notice::Type += { SCCREW::Domain_Hit };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
	if ( query in SCCREW::domains ) {
		NOTICE([$note=SCCREW::Domain_Hit,
		        $conn=c,
		        $msg=fmt("A domain from the Symantec Comment Crew report was seen: %s", query),
		        $identifier=cat(query)]);
	}
}
