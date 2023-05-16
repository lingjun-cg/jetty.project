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

package org.eclipse.jetty.quic.quiche;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PemExporter
{
    private static final Logger LOG = LoggerFactory.getLogger(PemExporter.class);

    private static final byte[] BEGIN_KEY = "-----BEGIN PRIVATE KEY-----".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] END_KEY = "-----END PRIVATE KEY-----".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] BEGIN_CERT = "-----BEGIN CERTIFICATE-----".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] END_CERT = "-----END CERTIFICATE-----".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LINE_SEPARATOR = System.getProperty("line.separator").getBytes(StandardCharsets.US_ASCII);
    private static final int LINE_LENGTH = 64;

    private final Base64.Encoder encoder = Base64.getMimeEncoder(LINE_LENGTH, LINE_SEPARATOR);
    private final KeyStore keyStore;

    public PemExporter(KeyStore keyStore)
    {
        this.keyStore = keyStore;
    }

    public Path exportTrustStore(Path targetFolder) throws Exception
    {
        if (!Files.isDirectory(targetFolder))
            throw new IllegalArgumentException("Target folder is not a directory: " + targetFolder);

        Path path = targetFolder.resolve("truststore-" + trustStoreHash() + ".crt");
        if (!Files.exists(path))
        {
            try (OutputStream os = Files.newOutputStream(path))
            {
                Enumeration<String> aliases = keyStore.aliases();
                while (aliases.hasMoreElements())
                {
                    String alias = aliases.nextElement();
                    Certificate cert = keyStore.getCertificate(alias);
                    writeAsPEM(os, cert);
                }
            }
        }

        return path;
    }

    private String trustStoreHash() throws NoSuchAlgorithmException, CertificateEncodingException, KeyStoreException
    {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA1");
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements())
        {
            String alias = aliases.nextElement();
            Certificate cert = keyStore.getCertificate(alias);
            byte[] encoded = cert.getEncoded();
            messageDigest.update(encoded);
        }
        StringBuilder sb = new StringBuilder();
        for (byte b : messageDigest.digest())
        {
            sb.append(Integer.toString((b & 0xff), 16));
        }
        return sb.toString();
    }

    /**
     * @return [0] is the key file, [1] is the cert file.
     */
    public Path[] exportKeyPair(String alias, char[] keyPassword, Path targetFolder) throws Exception
    {
        if (!Files.isDirectory(targetFolder))
            throw new IllegalArgumentException("Target folder is not a directory: " + targetFolder);

        Path[] paths = new Path[2];
        paths[0] = targetFolder.resolve(alias + ".key");
        paths[1] = targetFolder.resolve(alias + ".crt");

        try (OutputStream os = Files.newOutputStream(paths[1]))
        {
            Certificate[] certChain = keyStore.getCertificateChain(alias);
            for (Certificate cert : certChain)
                writeAsPEM(os, cert);
            Files.setPosixFilePermissions(paths[1], Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        }
        catch (UnsupportedOperationException e)
        {
            // Expected on Windows.
            if (LOG.isDebugEnabled())
                LOG.debug("Unable to set Posix file permissions", e);
        }
        try (OutputStream os = Files.newOutputStream(paths[0]))
        {
            Key key = keyStore.getKey(alias, keyPassword);
            writeAsPEM(os, key);
            Files.setPosixFilePermissions(paths[0], Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        }
        catch (UnsupportedOperationException e)
        {
            // Expected on Windows.
            if (LOG.isDebugEnabled())
                LOG.debug("Unable to set Posix file permissions", e);
        }

        return paths;
    }

    private void writeAsPEM(OutputStream outputStream, Key key) throws IOException
    {
        byte[] encoded = encoder.encode(key.getEncoded());
        outputStream.write(BEGIN_KEY);
        outputStream.write(LINE_SEPARATOR);
        outputStream.write(encoded);
        outputStream.write(LINE_SEPARATOR);
        outputStream.write(END_KEY);
        outputStream.write(LINE_SEPARATOR);
    }

    private void writeAsPEM(OutputStream outputStream, Certificate certificate) throws CertificateEncodingException, IOException
    {
        byte[] encoded = encoder.encode(certificate.getEncoded());
        outputStream.write(BEGIN_CERT);
        outputStream.write(LINE_SEPARATOR);
        outputStream.write(encoded);
        outputStream.write(LINE_SEPARATOR);
        outputStream.write(END_CERT);
        outputStream.write(LINE_SEPARATOR);
    }
}
