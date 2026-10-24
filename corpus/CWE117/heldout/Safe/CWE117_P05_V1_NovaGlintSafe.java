import java.util.logging.Logger;

public class CWE117_P05_V1_NovaGlintSafe {

    private String novaGlintData;

    private void logNovaGlint() {
        String data = novaGlintData;
        Logger novaGlintLogger = Logger.getLogger("novaGlint.audit");
        novaGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleNovaGlint() {
        String data;
        data = System.getenv("NOVA_GLINT_USER");
        novaGlintData = data;
        logNovaGlint();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
