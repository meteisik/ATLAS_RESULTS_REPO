import java.util.logging.Logger;

public class CWE117_P06_V1_NovaGlintSafe {

    public void handleNovaGlint() {
        String data;
        data = System.getenv("NOVA_GLINT_USER");
        (new CWE117_P06_V1_NovaGlintSafeSink()).logNovaGlint(data);
    }
}

class CWE117_P06_V1_NovaGlintSafeSink {
    public void logNovaGlint(String data) {
        Logger novaGlintLogger = Logger.getLogger("novaGlint.audit");
        novaGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
