//! DNS message parsing: question-section extraction with RFC 1035 name
//! decompression. We only need the asked name, the type, and the rcode —
//! answers are never inspected, which keeps the parser small and auditable.

