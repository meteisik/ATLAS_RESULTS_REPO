import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianKestrel {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianKestrelData;

    private void logObsidianKestrel() {
        String data = obsidianKestrelData;
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianKestrel() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("OBSIDIAN_KESTREL_USER");
        } else {
            data = null;
        }
        obsidianKestrelData = data;
        logObsidianKestrel();
    }
}
