import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianLotus {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String readObsidianLotus() {
        String data;
        if (IO.staticTrue) {
            data = System.getenv("OBSIDIAN_LOTUS_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianLotus() {
        String data = readObsidianLotus();
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + data);
    }
}
