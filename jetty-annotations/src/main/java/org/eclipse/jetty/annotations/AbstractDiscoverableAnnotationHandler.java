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

package org.eclipse.jetty.annotations;

import org.eclipse.jetty.annotations.AnnotationParser.AbstractHandler;
import org.eclipse.jetty.webapp.DiscoveredAnnotation;
import org.eclipse.jetty.webapp.WebAppContext;

/**
 * DiscoverableAnnotationHandler
 *
 * Base class for handling the discovery of an annotation.
 */
public abstract class AbstractDiscoverableAnnotationHandler extends AbstractHandler
{
    protected WebAppContext _context;

    public AbstractDiscoverableAnnotationHandler(WebAppContext context)
    {
        _context = context;
    }

    public void addAnnotation(DiscoveredAnnotation a)
    {
        _context.getMetaData().addDiscoveredAnnotation(a);
    }
}
