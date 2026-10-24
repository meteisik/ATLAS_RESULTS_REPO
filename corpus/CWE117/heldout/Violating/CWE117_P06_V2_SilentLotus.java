import java.util.logging.Logger;

public class CWE117_P06_V2_SilentLotus {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleSilentLotus() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SILENT_LOTUS_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_SilentLotusSink()).logSilentLotus(data);
    }
}

class CWE117_P06_V2_SilentLotusSink {
    public void logSilentLotus(String data) {
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + data);
    }
}
