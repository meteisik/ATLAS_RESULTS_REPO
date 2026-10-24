import java.util.logging.Logger;

public class CWE117_P07_V2_SilentLotus {
    private static boolean privateReturnsTrue() { return true; }

    public void handleSilentLotus() {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE117_P07_V2_SilentLotusSource()).readSilentLotus();
        } else {
            data = null;
        }
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V2_SilentLotusSource {
    public String readSilentLotus() {
        String data;
        data = System.getenv("SILENT_LOTUS_USER");
        return data;
    }
}
