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

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public class OIDTest {

    @Test
    public void testIntParse() throws Exception {
        assertEquals("1.2.3.4", OID.fromString("1.2.3.4").toString());
        assertEquals("1.2", OID.fromString("1.2").toString());
        assertEquals("1", OID.fromString("1").toString());
        assertEquals(null, OID.fromString(""));
    }

    @Test
    public void testLongParse() throws Exception {
        assertEquals("1000000000.2000000000.3000000000.4000000000", OID.fromString("1000000000.2000000000.3000000000.4000000000").toString());
        assertEquals("1000000000.2000000000", OID.fromString("1000000000.2000000000").toString());
        assertEquals("1000000000", OID.fromString("1000000000").toString());
    }

    @Test
    public void testVeryLongParse() throws Exception {
        assertEquals("1000000000000000000000000000.2000000000000000000000000000.3000000000000000000000000000.4000000000000000000000000000", OID.fromString("1000000000000000000000000000.2000000000000000000000000000.3000000000000000000000000000.4000000000000000000000000000").toString());
        assertEquals("1000000000000000000000000000.2000000000000000000000000000", OID.fromString("1000000000000000000000000000.2000000000000000000000000000").toString());
        assertEquals("1000000000000000000000000000", OID.fromString("1000000000000000000000000000").toString());
    }
}
