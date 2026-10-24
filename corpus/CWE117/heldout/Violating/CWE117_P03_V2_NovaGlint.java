import java.util.logging.Logger;

public class CWE117_P03_V2_NovaGlint {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logNovaGlint(String data) {
        Logger novaGlintLogger = Logger.getLogger("novaGlint.audit");
        novaGlintLogger.info("Login attempt for user " + data);
    }

    public void handleNovaGlint() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("NOVA_GLINT_USER");
        } else {
            data = null;
        }
        logNovaGlint(data);
    }
}
