import java.util.logging.Logger;

public class CWE117_P04_V2_ObsidianKestrel {
    private static boolean privateReturnsTrue() { return true; }

    private String readObsidianKestrel() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("OBSIDIAN_KESTREL_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleObsidianKestrel() {
        String data = readObsidianKestrel();
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + data);
    }
}
