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

package org.eclipse.jetty.quic.client;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.UnaryOperator;

import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.io.Connection;
import org.eclipse.jetty.io.DatagramChannelEndPoint;
import org.eclipse.jetty.io.EndPoint;
import org.eclipse.jetty.io.ManagedSelector;
import org.eclipse.jetty.io.SocketChannelEndPoint;
import org.eclipse.jetty.quic.common.QuicConfiguration;
import org.eclipse.jetty.quic.quiche.PemExporter;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>A QUIC specific {@link ClientConnector.Configurator}.</p>
 * <p>Since QUIC is based on UDP, this class creates {@link DatagramChannel}s instead of
 * {@link SocketChannel}s, and {@link DatagramChannelEndPoint}s instead of
 * {@link SocketChannelEndPoint}s.</p>
 *
 * @see QuicConfiguration
 */
public class QuicClientConnectorConfigurator extends ClientConnector.Configurator
{
    private static final Logger LOG = LoggerFactory.getLogger(QuicClientConnectorConfigurator.class);

    public static final String PRIVATE_KEY_PATH_KEY = QuicClientConnectorConfigurator.class.getName() + ".privateKeyPath";
    public static final String CERTIFICATE_CHAIN_PATH_KEY = QuicClientConnectorConfigurator.class.getName() + ".certificateChainPath";
    public static final String TRUSTSTORE_PATH_KEY = QuicClientConnectorConfigurator.class.getName() + ".trustStorePath";

    private final QuicConfiguration configuration = new QuicConfiguration();
    private final UnaryOperator<Connection> configurator;
    private Path certificateWorkPath;
    private Path privateKeyPath;
    private Path certificateChainPath;
    private Path trustStorePath;
    private Map<String, Object> extraContext;

    public QuicClientConnectorConfigurator()
    {
        this(UnaryOperator.identity());
    }

    public QuicClientConnectorConfigurator(UnaryOperator<Connection> configurator)
    {
        this.configurator = Objects.requireNonNull(configurator);
        // Initialize to sane defaults for a client.
        configuration.setSessionRecvWindow(16 * 1024 * 1024);
        configuration.setBidirectionalStreamRecvWindow(8 * 1024 * 1024);
        configuration.setDisableActiveMigration(true);
    }

    public QuicConfiguration getQuicConfiguration()
    {
        return configuration;
    }

    public Path getCertificateWorkPath()
    {
        return certificateWorkPath;
    }

    public void setCertificateWorkPath(Path certificateWorkPath)
    {
        this.certificateWorkPath = certificateWorkPath;
    }

    @Override
    protected void configure(ClientConnector clientConnector) throws Exception
    {
        SslContextFactory.Client sslContextFactory = clientConnector.getSslContextFactory();
        KeyStore trustStore = sslContextFactory.getTrustStore();
        if (trustStore != null)
        {
            PemExporter pemExporter = new PemExporter(trustStore);
            trustStorePath = pemExporter.exportTrustStore(certificateWorkPath != null ? certificateWorkPath : Path.of(System.getProperty("java.io.tmpdir")));
            if (extraContext == null)
                extraContext = new HashMap<>();
            extraContext.put(TRUSTSTORE_PATH_KEY, trustStorePath.toString());
        }
        String certAlias = sslContextFactory.getCertAlias();
        if (certAlias != null)
        {
            if (certificateWorkPath == null)
                throw new IllegalStateException("No certificate work path configured");
            KeyStore keyStore = sslContextFactory.getKeyStore();
            PemExporter pemExporter = new PemExporter(keyStore);
            String keyManagerPassword = sslContextFactory.getKeyManagerPassword();
            char[] password = keyManagerPassword == null ? sslContextFactory.getKeyStorePassword().toCharArray() : keyManagerPassword.toCharArray();
            Path[] keyPair = pemExporter.exportKeyPair(certAlias, password, certificateWorkPath);
            privateKeyPath = keyPair[0];
            certificateChainPath = keyPair[1];
            if (extraContext == null)
                extraContext = new HashMap<>();
            extraContext.put(PRIVATE_KEY_PATH_KEY, privateKeyPath.toString());
            extraContext.put(CERTIFICATE_CHAIN_PATH_KEY, certificateChainPath.toString());
        }
    }

    @Override
    protected void unconfigure()
    {
        deleteFile(privateKeyPath);
        deleteFile(certificateChainPath);
        deleteFile(trustStorePath);
    }

    private void deleteFile(Path file)
    {
        try
        {
            if (file != null)
                Files.delete(file);
        }
        catch (IOException x)
        {
            if (LOG.isDebugEnabled())
                LOG.debug("could not delete {}", file, x);
        }
    }

    @Override
    public boolean isIntrinsicallySecure(ClientConnector clientConnector, SocketAddress address)
    {
        return true;
    }

    @Override
    public ChannelWithAddress newChannelWithAddress(ClientConnector clientConnector, SocketAddress address, Map<String, Object> context) throws IOException
    {
        context.put(QuicConfiguration.CONTEXT_KEY, configuration);
        if (extraContext != null)
            context.putAll(extraContext);

        DatagramChannel channel = DatagramChannel.open();
        if (clientConnector.getBindAddress() == null)
        {
            // QUIC must know the local address for connection migration, so we must always bind early.
            channel.bind(null);
        }
        return new ChannelWithAddress(channel, address);
    }

    @Override
    public EndPoint newEndPoint(ClientConnector clientConnector, SocketAddress address, SelectableChannel selectable, ManagedSelector selector, SelectionKey selectionKey)
    {
        return new DatagramChannelEndPoint((DatagramChannel)selectable, selector, selectionKey, clientConnector.getScheduler());
    }

    @Override
    public Connection newConnection(ClientConnector clientConnector, SocketAddress address, EndPoint endPoint, Map<String, Object> context)
    {
        return configurator.apply(new ClientQuicConnection(clientConnector, endPoint, context));
    }
}
