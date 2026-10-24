import java.util.logging.Logger;

public class CWE117_P07_V1_ObsidianLotus {

    public void handleObsidianLotus() {
        String data;
        data = (new CWE117_P07_V1_ObsidianLotusSource()).readObsidianLotus();
        Logger obsidianLotusLogger = Logger.getLogger("obsidianLotus.audit");
        obsidianLotusLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_ObsidianLotusSource {
    public String readObsidianLotus() {
        String data;
        data = System.getenv("OBSIDIAN_LOTUS_USER");
        return data;
    }
}
