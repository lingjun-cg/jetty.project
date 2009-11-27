// ========================================================================
// Copyright (c) 2009 Mort Bay Consulting Pty. Ltd.
// ------------------------------------------------------------------------
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v1.0
// and Apache License v2.0 which accompanies this distribution.
// The Eclipse Public License is available at 
// http://www.eclipse.org/legal/epl-v10.html
// The Apache License v2.0 is available at
// http://www.opensource.org/licenses/apache2.0.php
// You may elect to redistribute this code under either of these licenses. 
// ========================================================================

package org.eclipse.jetty.annotations;

import java.util.List;

import javax.servlet.Servlet;

import org.eclipse.jetty.annotations.AnnotationIntrospector.AbstractIntrospectableAnnotationHandler;
import org.eclipse.jetty.annotations.AnnotationIntrospector.IntrospectableAnnotationHandler;
import org.eclipse.jetty.annotations.AnnotationParser.Value;
import org.eclipse.jetty.plus.annotation.RunAsCollection;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.webapp.WebAppContext;

public class RunAsAnnotationHandler extends AbstractIntrospectableAnnotationHandler
{
    protected WebAppContext _wac;

    public RunAsAnnotationHandler (WebAppContext wac)
    {
        super(true);
        _wac = wac;
    }
    
    public void doHandle (Class clazz)
    {
        RunAsCollection runAsCollection = (RunAsCollection)_wac.getAttribute(RunAsCollection.RUNAS_COLLECTION);

        if (!Servlet.class.isAssignableFrom(clazz))
            return;
        
        javax.annotation.security.RunAs runAs = (javax.annotation.security.RunAs)clazz.getAnnotation(javax.annotation.security.RunAs.class);
        if (runAs != null)
        {
            String role = runAs.value();
            if (role != null)
            {
                org.eclipse.jetty.plus.annotation.RunAs ra = new org.eclipse.jetty.plus.annotation.RunAs();
                ra.setTargetClassName(clazz.getCanonicalName());
                ra.setRoleName(role);
                runAsCollection.add(ra);
            }
            else
                Log.warn("Bad value for @RunAs annotation on class "+clazz.getName());
        }

    }

    public void handleField(String className, String fieldName, int access, String fieldType, String signature, Object value, String annotation,
                            List<Value> values)
    {
       Log.warn ("@RunAs annotation not applicable for fields: "+className+"."+fieldName);
    }

    public void handleMethod(String className, String methodName, int access, String params, String signature, String[] exceptions, String annotation,
                             List<Value> values)
    {
        Log.warn("@RunAs annotation ignored on method: "+className+"."+methodName+" "+signature);
    }

}
