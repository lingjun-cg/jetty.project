// ========================================================================
// Copyright (c) 2006-2009 Mort Bay Consulting Pty. Ltd.
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

package org.eclipse.jetty.plus.annotation;

import java.util.HashMap;

import javax.servlet.ServletException;

import org.eclipse.jetty.security.SecurityHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.log.Log;
import org.eclipse.jetty.webapp.WebAppContext;


/**
 * RunAsCollection
 *
 *
 */
public class RunAsCollection
{
    public static final String RUNAS_COLLECTION = "org.eclipse.jetty.runAsCollection";
    private HashMap _runAsMap = new HashMap();//map of classname to run-as
  
    
    
    public void add (RunAs runAs)
    {
        if ((runAs==null) || (runAs.getTargetClassName()==null)) 
            return;
        
        if (Log.isDebugEnabled())
            Log.debug("Adding run-as for class="+runAs.getTargetClassName());
        _runAsMap.put(runAs.getTargetClassName(), runAs);
    }

    public RunAs getRunAs (Object o)
    throws ServletException
    {
        if (o==null)
            return null;
        
        return (RunAs)_runAsMap.get(o.getClass().getCanonicalName());
    }
    
    public void setRunAs(Object o)
    throws ServletException
    {
        if (o == null)
            return;
      
        //TODO get all of the holders matching the class of the object and set their runAs
       /*
        RunAs runAs = (RunAs)_runAsMap.get(className);
        if (runAs == null)
            return;

        runAs.setRunAs(holder); 
        */
    }

}
