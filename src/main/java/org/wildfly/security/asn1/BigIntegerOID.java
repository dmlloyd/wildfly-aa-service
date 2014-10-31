/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.asn1;

import java.math.BigInteger;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
final class BigIntegerOID extends OID {

    private static final BigInteger LONG_MAX_VALUE = BigInteger.valueOf(Long.MAX_VALUE);

    private final BigInteger segment;

    BigIntegerOID(final OID next, final BigInteger segment) {
        super(next);
        assert segment.compareTo(LONG_MAX_VALUE) > 0;
        this.segment = segment;
    }

    boolean segmentEquals(final OID other) {
        return other instanceof BigIntegerOID && this.segment.equals(((BigIntegerOID) other).segment);
    }

    int segmentHashCode() {
        return segment.hashCode();
    }

    int getMinimumBerByteLength() {
        return (segment.bitLength() + 6) / 7;
    }

    void appendSegment(final StringBuilder b) {
        b.append(segment);
    }
}
