import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronGlintSafe {

    public static String data;

    public void handleSaffronGlint() {
        data = System.getenv("SAFFRON_GLINT_USER");
        (new CWE117_P10_V1_SaffronGlintSafeSink()).logSaffronGlint();
    }
}

class CWE117_P10_V1_SaffronGlintSafeSink {
    public void logSaffronGlint() {
        String data = CWE117_P10_V1_SaffronGlintSafe.data;
        Logger saffronGlintLogger = Logger.getLogger("saffronGlint.audit");
        saffronGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
