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

package org.eclipse.jetty.xml;

import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.jetty.util.annotation.Name;
import org.eclipse.jetty.util.component.Environment;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.resource.ResourceFactory;

/**
 * A Builder of {@link Environment}s intended to be used in XML
 * files generated by <code>start.jar</code>.
 *
 */
public class EnvironmentBuilder
{
    private final String _name;
    private final List<URL> _classpath = new ArrayList<>();

    public EnvironmentBuilder(@Name("name") String name)
    {
        _name = name;
    }

    public void addModulePath(String arg)
    {
        throw new UnsupportedOperationException();
    }

    public void addClassPath(String... classPaths)
    {
        for (String classPath : classPaths)
        {
            try
            {
                _classpath.add(ResourceFactory.root().newResource(classPath).getURI().toURL());
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }
    }

    public Environment build() throws Exception
    {
        return new Environment.Named(_name, new URLClassLoader(_classpath.toArray(new URL[0]), EnvironmentBuilder.class.getClassLoader()));
    }
}
