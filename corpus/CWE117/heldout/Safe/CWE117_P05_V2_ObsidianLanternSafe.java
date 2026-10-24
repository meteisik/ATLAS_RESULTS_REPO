import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianLanternSafe {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianLanternData;

    private void logObsidianLantern() {
        String data = obsidianLanternData;
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleObsidianLantern() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("OBSIDIAN_LANTERN_USER");
        } else {
            data = null;
        }
        obsidianLanternData = data;
        logObsidianLantern();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
