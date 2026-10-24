import java.util.logging.Logger;

public class CWE117_P06_V1_NovaGlint {

    public void handleNovaGlint() {
        String data;
        data = System.getenv("NOVA_GLINT_USER");
        (new CWE117_P06_V1_NovaGlintSink()).logNovaGlint(data);
    }
}

class CWE117_P06_V1_NovaGlintSink {
    public void logNovaGlint(String data) {
        Logger novaGlintLogger = Logger.getLogger("novaGlint.audit");
        novaGlintLogger.info("Login attempt for user " + data);
    }
}
