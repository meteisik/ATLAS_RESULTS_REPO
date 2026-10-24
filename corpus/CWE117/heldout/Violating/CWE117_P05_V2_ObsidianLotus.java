import java.util.logging.Logger;

public class CWE117_P05_V2_ObsidianLotus {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    private String obsidianLotusData;

    private void logObsidianLotus() {
        String data = obsidianLotusData;
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianLotus() {
        String data;
        if (IO.STATIC_FINAL_FIVE == 5) {
            data = System.getenv("OBSIDIAN_LOTUS_USER");
        } else {
            data = null;
        }
        obsidianLotusData = data;
        logObsidianLotus();
    }
}
