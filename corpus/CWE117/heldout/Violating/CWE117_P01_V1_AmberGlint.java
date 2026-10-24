import java.util.logging.Logger;

public class CWE117_P01_V1_AmberGlint {

    public void handleAmberGlint() {
        String data;
        data = System.getenv("AMBER_GLINT_USER");
        Logger amberGlintLogger = Logger.getLogger("amberGlint.audit");
        amberGlintLogger.info("Login attempt for user " + data);
    }
}
