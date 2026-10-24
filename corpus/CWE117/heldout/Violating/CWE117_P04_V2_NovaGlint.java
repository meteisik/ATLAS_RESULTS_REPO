import java.util.logging.Logger;

public class CWE117_P04_V2_NovaGlint {

    private String readNovaGlint() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("NOVA_GLINT_USER");
            break;
        default:
            data = null;
            break;
        }
        return data;
    }

    public void handleNovaGlint() {
        String data = readNovaGlint();
        Logger novaGlintLogger = Logger.getLogger("novaGlint.audit");
        novaGlintLogger.info("Login attempt for user " + data);
    }
}
