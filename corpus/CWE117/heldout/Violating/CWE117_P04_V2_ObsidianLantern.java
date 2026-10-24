import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianLantern {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readObsidianLantern() {
        String data;
        if (IO.STATIC_FINAL_TRUE) {
            data = System.getenv("OBSIDIAN_LANTERN_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianLantern() {
        String data = readObsidianLantern();
        Logger obsidianLanternLogger = Logger.getLogger("obsidianLantern.audit");
        obsidianLanternLogger.info("Login attempt for user " + data);
    }
}
