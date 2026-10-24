import java.util.logging.Logger;

public class CWE117_P07_V2_SilentLotusSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleSilentLotus() {
        String data;
        if (privateReturnsTrue()) {
            data = (new CWE117_P07_V2_SilentLotusSafeSource()).readSilentLotus();
        } else {
            data = null;
        }
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V2_SilentLotusSafeSource {
    public String readSilentLotus() {
        String data;
        data = System.getenv("SILENT_LOTUS_USER");
        return data;
    }
}
