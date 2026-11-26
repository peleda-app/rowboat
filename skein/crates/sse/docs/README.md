# skein-sse

`Parser`: turns chunks of a Server-Sent Events stream into `Event`s (`event`, `data`, `id`), as the JMAP EventSource and other push channels send them. `Parser::new(limit)` refuses an event larger than `limit` bytes with `TooLarge`, so a hostile or broken server cannot make a client buffer without bound. Ported from Holtmail's `holtmail-sse`.
