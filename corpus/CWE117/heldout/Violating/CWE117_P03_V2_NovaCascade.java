import java.util.logging.Logger;

public class CWE117_P03_V2_NovaCascade {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logNovaCascade(String data) {
        Logger novaCascadeLogger = Logger.getLogger("novaCascade.audit");
        novaCascadeLogger.info("Login attempt for user " + data);
    }

    public void handleNovaCascade() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("NOVA_CASCADE_USER");
        } else {
            data = null;
        }
        logNovaCascade(data);
    }
}
