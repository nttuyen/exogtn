package org.gatein.security.oauth.consumer.util;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created by tuyennt on 12/4/14.
 */
public class OAuth {
    public static String getRequestPath(HttpServletRequest request) {
        URL url;
        try {
            url = new URL(getRequestURL(request));
        } catch (Exception ex) {
            return request.getRequestURI();
        }
        StringBuilder path = new StringBuilder(url.getPath());
        String queryString = url.getQuery();
        if (queryString != null) {
            path.append("?").append(queryString);
        }
        return path.toString();
    }

    public static String getRequestURL(HttpServletRequest request) {
        StringBuffer url = request.getRequestURL();
        String queryString = request.getQueryString();
        if (queryString != null) {
            url.append("?").append(queryString);
        }
        return url.toString();
    }
}
