import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianNebula {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readObsidianNebula() {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("OBSIDIAN_NEBULA_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianNebula() {
        String data = readObsidianNebula();
        Logger obsidianNebulaLogger = Logger.getLogger("obsidianNebula.audit");
        obsidianNebulaLogger.info("Login attempt for user " + data);
    }
}
