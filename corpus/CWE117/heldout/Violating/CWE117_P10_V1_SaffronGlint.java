import java.util.logging.Logger;

public class CWE117_P10_V1_SaffronGlint {

    public static String data;

    public void handleSaffronGlint() {
        data = System.getenv("SAFFRON_GLINT_USER");
        (new CWE117_P10_V1_SaffronGlintSink()).logSaffronGlint();
    }
}

class CWE117_P10_V1_SaffronGlintSink {
    public void logSaffronGlint() {
        String data = CWE117_P10_V1_SaffronGlint.data;
        Logger saffronGlintLogger = Logger.getLogger("saffronGlint.audit");
        saffronGlintLogger.info("Login attempt for user " + data);
    }
}
