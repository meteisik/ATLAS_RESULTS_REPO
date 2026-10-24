import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianHelix {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianHelixData;

    private void logObsidianHelix() {
        String data = obsidianHelixData;
        Logger obsidianHelixLogger = Logger.getLogger("obsidianHelix.audit");
        obsidianHelixLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianHelix() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_HELIX_USER");
        } else {
            data = null;
        }
        obsidianHelixData = data;
        logObsidianHelix();
    }
}
