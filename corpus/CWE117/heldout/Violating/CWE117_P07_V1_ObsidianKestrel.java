import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianKestrel {

    public void handleObsidianKestrel() {
        String data;
        data = (new CWE117_P07_V1_ObsidianKestrelSource()).readObsidianKestrel();
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianKestrelSource {
    public String readObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_USER");
        return data;
    }
}
