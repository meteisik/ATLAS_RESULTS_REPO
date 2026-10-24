import java.util.logging.Logger;

public class CWE117_P06_V2_SilentLotusSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleSilentLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_LOTUS_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentLotusSafeSink()).logSilentLotus(data);
    }
}

class CWE117_P06_V2_SilentLotusSafeSink {
    public void logSilentLotus(String data) {
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
