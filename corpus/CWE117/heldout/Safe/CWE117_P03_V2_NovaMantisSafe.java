import java.util.logging.Logger;

public class CWE117_P03_V2_NovaMantisSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private void logNovaMantis(String data) {
        Logger novaMantisLogger = Logger.getLogger("novaMantis.audit");
        novaMantisLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleNovaMantis() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("NOVA_MANTIS_USER");
        } else {
            data = null;
        }
        logNovaMantis(data);
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
