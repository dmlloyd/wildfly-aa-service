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

import static org.wildfly.security._private.ElytronMessages.log;

import java.math.BigInteger;

/**
 * An ASN.1 object identifier.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public abstract class OID {

    private final OID parent;
    private transient int hashCode;
    private transient String string;

    OID(final OID parent) {
        this.parent = parent;
    }

    abstract int segmentHashCode();

    abstract int getMinimumBerByteLength();

    final int getAggregateBerByteLength() {
        int len = parent == null ? 0 : parent.getAggregateBerByteLength();
        len += getMinimumBerByteLength();
        return len;
    }

    /**
     * Get the OID hash code.
     *
     * @return the OID hash code
     */
    public final int hashCode() {
        int hc = hashCode;
        if (hc == 0) {
            hc = parent == null ? 0 : parent.hashCode();
            hc = 17 * hc + segmentHashCode();
            this.hashCode = hc;
        }
        return hc;
    }

    /**
     * Determine whether this OID is equal to another.
     *
     * @param other the other OID
     * @return {@code true} if the OIDs are equal, {@code false} otherwise
     */
    public final boolean equals(Object other) {
        return other instanceof OID && equalsNN((OID) other);
    }

    /**
     * Determine whether this OID is equal to another.
     *
     * @param other the other OID
     * @return {@code true} if the OIDs are equal, {@code false} otherwise
     */
    public final boolean equals(OID other) {
        return other != null && equalsNN(other);
    }

    private boolean equalsNN(OID other) {
        if (hashCode() != other.hashCode()) return false;
        OID cur = this;
        for (;;) {
            if (! cur.segmentEquals(other)) {
                return false;
            }
            cur = cur.parent;
            other = other.parent;
            if (cur == null) {
                return other == null;
            } else if (other == null) {
                return false;
            }
        }
    }

    abstract boolean segmentEquals(OID segment);

    abstract void appendSegment(StringBuilder b);

    final void toString(StringBuilder b) {
        if (parent != null) {
            parent.toString(b);
            b.append('.');
        }
        appendSegment(b);
    }

    /**
     * Get the string representation of this OID.
     *
     * @return the string representation of this OID
     */
    public final String toString() {
        String string = this.string;
        if (string != null) {
            return string;
        }
        final StringBuilder b = new StringBuilder();
        toString(b);
        return this.string = b.toString();
    }

    /**
     * Get the child OID of this OID with the given sub-ID.
     *
     * @param subId the sub-ID
     * @return the child OID
     */
    public final OID getChild(int subId) {
        if (subId >= 0) {
            return new IntOID(this, subId);
        } else {
            throw log.invalidOidChildId(subId);
        }
    }

    /**
     * Get the parent OID of this OID.  If the OID is a root OID, {@code null} is returned.
     *
     * @return the parent OID, or {@code null} if there is none
     */
    public OID getParent() {
        return parent;
    }

    /**
     * Create an object ID from a string.
     *
     * @param string the string
     * @return the object ID
     */
    public static OID fromString(String string) {
        return fromString(string, 0, string.length());
    }

    private static final long LARGEST_UNSHIFTED_LONG = Long.MAX_VALUE / 10L;

    private static final BigInteger[] digits = {
        BigInteger.ZERO,
        BigInteger.ONE,
        BigInteger.valueOf(2),
        BigInteger.valueOf(3),
        BigInteger.valueOf(4),
        BigInteger.valueOf(5),
        BigInteger.valueOf(6),
        BigInteger.valueOf(7),
        BigInteger.valueOf(8),
        BigInteger.valueOf(9),
    };

    /**
     * Create an object ID from a string fragment.
     *
     * @param string the string
     * @param offs the offset in the string
     * @param len the number of characters to process
     * @return the object ID
     */
    public static OID fromString(String string, int offs, int len) {
        if (len == 0) {
            return null;
        }
        int idx = 0;
        long t = 0L;
        char c;
        OID cur = null;
        a: for (;;) {
            c = string.charAt(offs + idx ++);
            if (Character.isDigit(c)) {
                int digit = Character.digit(c, 10);
                if (t > LARGEST_UNSHIFTED_LONG) {
                    BigInteger bi = BigInteger.valueOf(t).multiply(BigInteger.TEN).add(digits[digit]);
                    t = 0L;
                    for (;;) {
                        c = string.charAt(offs + idx ++);
                        if (Character.isDigit(c)) {
                            digit = Character.digit(c, 10);
                            bi = bi.multiply(BigInteger.TEN).add(digits[digit]);
                        } else if (c == '.') {
                            cur = new BigIntegerOID(cur, bi);
                            continue a;
                        } else {
                            throw log.invalidOidCharacter(c, offs + idx - 1, string);
                        }
                        if (idx == len) {
                            return new BigIntegerOID(cur, bi);
                        }
                    }
                } else {
                    t = 10L * t + (long) digit;
                }
            } else if (c == '.') {
                if (t <= Integer.MAX_VALUE) {
                    cur = new IntOID(cur, (int) t);
                } else {
                    cur = new LongOID(cur, t);
                }
                t = 0L;
            } else {
                throw log.invalidOidCharacter(c, offs + idx - 1, string);
            }
            if (idx == len) {
                if (c == '.') {
                    throw log.invalidOidCharacter(c, offs + idx - 1, string);
                }
                if (t <= Integer.MAX_VALUE) {
                    return new IntOID(cur, (int) t);
                } else {
                    return new LongOID(cur, t);
                }
            }
        }
    }
}
