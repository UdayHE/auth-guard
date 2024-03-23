package io.github.UdayHE.authguard.util;

/**
 * @author udayhegde
 */
public class Constants {

    public static final String[] WHITE_LIST_URLS = {"/auth/**", "/actuator/health",
            "/index.html", "styles.css"};
    public static final String AUTH_GUARD_TOKEN = "auth-guard-token";
    public static final String BEARER = "Bearer ";
}
