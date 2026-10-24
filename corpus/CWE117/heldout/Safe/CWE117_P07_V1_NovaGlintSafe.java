import java.util.logging.Logger;

public class CWE117_P07_V1_NovaGlintSafe {

    public void handleNovaGlint() {
        String data;
        data = (new CWE117_P07_V1_NovaGlintSafeSource()).readNovaGlint();
        Logger novaGlintLogger = Logger.getLogger("novaGlint.audit");
        novaGlintLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_NovaGlintSafeSource {
    public String readNovaGlint() {
        String data;
        data = System.getenv("NOVA_GLINT_USER");
        return data;
    }
}
