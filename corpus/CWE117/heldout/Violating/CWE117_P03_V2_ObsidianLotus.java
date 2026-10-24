import java.util.logging.Logger;

public class CWE117_P03_V2_ObsidianLotus {
    private static boolean privateReturnsTrue() { return true; }

    private void logObsidianLotus(String data) {
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + data);
    }

    public void handleObsidianLotus() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_LOTUS_USER");
        } else {
            data = null;
        }
        logObsidianLotus(data);
    }
}
