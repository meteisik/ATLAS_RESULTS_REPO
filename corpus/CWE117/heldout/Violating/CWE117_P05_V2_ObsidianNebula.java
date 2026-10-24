import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianNebulaData;

    private void logObsidianNebula() {
        String data = obsidianNebulaData;
        Logger obsidianNebulaLogger = Logger.getLogger("obsidianNebula.audit");
        obsidianNebulaLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianNebula() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("OBSIDIAN_NEBULA_USER");
        } else {
            data = null;
        }
        obsidianNebulaData = data;
        logObsidianNebula();
    }
}
