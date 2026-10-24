import java.util.logging.Logger;

public class CWE117_P10_V1_VividGlint {

    public static String data;

    public void handleVividGlint() {
        data = System.getenv("VIVID_GLINT_USER");
        (new CWE117_P10_V1_VividGlintSink()).logVividGlint();
    }
}

class CWE117_P10_V1_VividGlintSink {
    public void logVividGlint() {
        String data = CWE117_P10_V1_VividGlint.data;
        Logger vividGlintLogger = Logger.getLogger("vividGlint.audit");
        vividGlintLogger.info("Login attempt for user " + data);
    }
}
