/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2014, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.jboss.test.fips;

import java.io.IOException;
import java.security.AuthProvider;
import java.security.Provider;
import java.security.Security;

import javax.security.auth.Subject;
import javax.security.jacc.PolicyContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * @author Josef Cacek
 */
@WebServlet("/login")
public class PKCS11LoginServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        try {
            Provider[] provs = Security.getProviders();
            AuthProvider pkcs11Prov = null;
            for (Provider p : provs) {
                if (p.getName().contains("PKCS11") && p instanceof AuthProvider) {
                    pkcs11Prov = (AuthProvider) p;
                    break;
                }
            }
            if (pkcs11Prov != null) {
                pkcs11Prov
                        .login((Subject) PolicyContext.getContext("javax.security.auth.Subject.container"), new MyCBHandler());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
