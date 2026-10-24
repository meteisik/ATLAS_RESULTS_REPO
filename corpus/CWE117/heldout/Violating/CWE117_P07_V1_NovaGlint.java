import java.util.logging.Logger;

public class CWE117_P07_V1_NovaGlint {

    public void handleNovaGlint() {
        String data;
        data = (new CWE117_P07_V1_NovaGlintSource()).readNovaGlint();
        Logger novaGlintLogger = Logger.getLogger("novaGlint.audit");
        novaGlintLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_NovaGlintSource {
    public String readNovaGlint() {
        String data;
        data = System.getenv("NOVA_GLINT_USER");
        return data;
    }
}
