import java.util.logging.Logger;

public class CWE117_P05_V2_RuneCometSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String runeCometData;

    private void logRuneComet() {
        String data = runeCometData;
        Logger runeCometLogger = Logger.getLogger("runeComet.audit");
        runeCometLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleRuneComet() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("RUNE_COMET_USER");
        } else {
            data = null;
        }
        runeCometData = data;
        logRuneComet();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
