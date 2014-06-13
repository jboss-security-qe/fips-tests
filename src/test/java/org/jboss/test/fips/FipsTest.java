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

import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.junit.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Basic test which deploys simple webapp and tries to connect with over SSL. The client truststore is constructed using
 * certificate which is provided by system property 'fips.ca.path'.
 * 
 * @author Josef Cacek
 */
@RunWith(Arquillian.class)
@RunAsClient
public class FipsTest {

    private static final String TLS_V1 = "TLSv1";
    private static final String HELLO_WORLD = "Hello world!";

    @Deployment(testable = false)
    public static WebArchive deployment() {
        final WebArchive war = ShrinkWrap.create(WebArchive.class, "test.war");
        war.addAsWebResource(new StringAsset(HELLO_WORLD), "test.txt");
        return war;
    }

    @Test
    public void test() throws Exception {
        traceInfo();

        // create empty truststore
        final KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(null, null);

        // import certificate from provided path to the truststore
        final String caPath = System.getProperty("fips.ca.path");
        if (caPath != null) {
            final CertificateFactory tmpCertFac = CertificateFactory.getInstance("X.509");
            FileInputStream fileInputStream = new FileInputStream(caPath);
            try {
                @SuppressWarnings("unchecked")
                final Collection<X509Certificate> tmpCertCol = (Collection<X509Certificate>) tmpCertFac
                        .generateCertificates(fileInputStream);
                for (X509Certificate tmpCert : tmpCertCol) {
                    trustStore.setCertificateEntry(tmpCert.getSerialNumber().toString(Character.MAX_RADIX), tmpCert);
                }
            } finally {
                fileInputStream.close();
            }
        } else {
            System.err.println("The fips.ca.path system property is not set.");
        }
        // Trust own CA and all self-signed certs
        SSLContext sslcontext = SSLContexts.custom().useProtocol(TLS_V1).loadTrustMaterial(trustStore).build();
        // Allow TLSv1 protocol only
        SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, new String[] { TLS_V1 }, null,
                SSLConnectionSocketFactory.BROWSER_COMPATIBLE_HOSTNAME_VERIFIER);
        CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();
        try {

            HttpGet httpget = new HttpGet("https://localhost:8443/test/test.txt");
            System.out.println("Executing request: " + httpget.getRequestLine());
            CloseableHttpResponse response = httpclient.execute(httpget);
            try {
                HttpEntity entity = response.getEntity();
                System.out.println("Response status: " + response.getStatusLine());
                assertEquals(HELLO_WORLD, EntityUtils.toString(entity));
            } finally {
                response.close();
            }
        } finally {
            httpclient.close();
        }
    }

    public static void main(String args[]) {
        traceInfo();
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    private static void traceInfo() {
        System.out.println("====== SYSTEM PROPERTIES =======================");
        for (Map.Entry e : System.getProperties().entrySet()) {
            System.out.println(e.getKey() + "=" + e.getValue());
        }
        System.out.println("====== SECURITY PROVIDERS ======================");
        try {
            Provider[] aProvider = Security.getProviders();
            for (int i = 0; i < aProvider.length; i++) {
                Provider provider = aProvider[i];
                System.out.println("Provider " + (i + 1) + " : " + provider.getName() + " " + provider.getInfo() + " :");
                List keyList = new ArrayList(provider.keySet());
                try {
                    Collections.sort(keyList);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                Iterator keyIterator = keyList.iterator();
                while (keyIterator.hasNext()) {
                    String key = (String) keyIterator.next();
                    System.out.println(key + ": " + provider.getProperty(key));
                }
                System.out.println("------------------------------------------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("================================================");
    }

}
