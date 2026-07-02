package com.crushed.identitydiff;

/** Abstraction over "send this request and get a response" so replay logic is unit-testable
 *  without a live MontoyaApi. The real implementation wraps montoyaApi.http().sendRequest(). */
public interface RequestSender {

    ReplayResult send(ReplayableRequest request);
}
