package org.jboss.test.fips;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Prints debug info environment and security providers.
 * 
 * @author Josef Cacek
 */
@WebServlet(TraceSecurityProviders.SERVLET_PATH)
public class TraceSecurityProviders extends HttpServlet {

    private static final long serialVersionUID = 825438762242693059L;
    public static final String SERVLET_PATH = "/SecurityProviders";

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/plain");
        traceInfo(resp.getWriter());
        traceInfo(new PrintWriter(System.out));
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    public static void traceInfo(PrintWriter pw) {
        pw.println("====== SYSTEM PROPERTIES =======================");
        SortedMap<String, String> map = new TreeMap<String, String>();
        for (Map.Entry e : System.getProperties().entrySet()) {
            map.put((String) e.getKey(), (String) e.getValue());
        }
        for (Map.Entry<String, String> e : map.entrySet()) {
            pw.println(e.getKey() + "=" + e.getValue());
        }
        pw.println("====== SECURITY PROVIDERS ======================");
        try {
            Provider[] aProvider = Security.getProviders();
            for (int i = 0; i < aProvider.length; i++) {
                Provider provider = aProvider[i];
                pw.println("Provider " + (i + 1) + " : " + provider.getName() + " " + provider.getInfo() + " :");
                List keyList = new ArrayList(provider.keySet());
                try {
                    Collections.sort(keyList);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                Iterator keyIterator = keyList.iterator();
                while (keyIterator.hasNext()) {
                    String key = (String) keyIterator.next();
                    pw.println(key + ": " + provider.getProperty(key));
                }
                pw.println("------------------------------------------------");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        pw.println("================================================");
    }

}
