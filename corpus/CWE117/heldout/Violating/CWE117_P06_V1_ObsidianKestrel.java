import java.util.logging.Logger;

public class CWE117_P06_V1_ObsidianKestrel {

    public void handleObsidianKestrel() {
        String data;
        data = System.getenv("OBSIDIAN_KESTREL_USER");
        (new CWE117_P06_V1_ObsidianKestrelSink()).logObsidianKestrel(data);
    }
}

class CWE117_P06_V1_ObsidianKestrelSink {
    public void logObsidianKestrel(String data) {
        Logger obsidianKestrelLogger = Logger.getLogger("obsidianKestrel.audit");
        obsidianKestrelLogger.info("Login attempt for user " + data);
    }
}
