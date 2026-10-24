import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianLotusSafe {

    public void handleObsidianLotus() {
        String data;
        data = (new CWE117_P07_V1_ObsidianLotusSafeSource()).readObsidianLotus();
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_ObsidianLotusSafeSource {
    public String readObsidianLotus() {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_USER");
        return data;
    }
}
