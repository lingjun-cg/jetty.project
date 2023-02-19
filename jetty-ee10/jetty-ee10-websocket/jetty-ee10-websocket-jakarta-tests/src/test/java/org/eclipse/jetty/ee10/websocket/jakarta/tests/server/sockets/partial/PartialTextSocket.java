//
// ========================================================================
// Copyright (c) 1995 Mort Bay Consulting Pty Ltd and others.
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License v. 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
// ========================================================================
//

package org.eclipse.jetty.ee10.websocket.jakarta.tests.server.sockets.partial;

import java.io.IOException;

import jakarta.websocket.OnError;
import jakarta.websocket.OnMessage;
import jakarta.websocket.OnOpen;
import jakarta.websocket.Session;
import jakarta.websocket.server.ServerEndpoint;
import org.eclipse.jetty.toolchain.test.StackUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@ServerEndpoint("/echo/partial/text")
public class PartialTextSocket
{
    private static final Logger LOG = LoggerFactory.getLogger(PartialTextSocket.class);
    private Session session;
    private StringBuilder buf = new StringBuilder();

    @OnOpen
    public void onOpen(Session session)
    {
        this.session = session;
    }

    @OnMessage
    public void onPartial(String msg, boolean fin) throws IOException
    {
        buf.append("('").append(msg).append("',").append(fin).append(')');
        if (fin)
        {
            session.getBasicRemote().sendText(buf.toString());
            buf.setLength(0);
        }
    }

    @OnError
    public void onError(Throwable cause) throws IOException
    {
        LOG.warn("Error", cause);
        session.getBasicRemote().sendText("Exception: " + StackUtils.toString(cause));
    }
}
