import java.util.logging.Logger;

public class CWE117_P05_V2_RuneHarborSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeHarborData;

    private void logRuneHarbor() {
        String data = runeHarborData;
        Logger runeHarborLogger = Logger.getLogger("runeHarbor.audit");
        runeHarborLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleRuneHarbor() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("RUNE_HARBOR_USER");
        } else {
            data = null;
        }
        runeHarborData = data;
        logRuneHarbor();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
