import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianRaven {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readObsidianRaven() {
        String data;
        if (IO.staticFive == 5) {
            data = System.getenv("OBSIDIAN_RAVEN_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianRaven() {
        String data = readObsidianRaven();
        Logger obsidianRavenLogger = Logger.getLogger("obsidianRaven.audit");
        obsidianRavenLogger.info("Login attempt for user " + data);
    }
}
