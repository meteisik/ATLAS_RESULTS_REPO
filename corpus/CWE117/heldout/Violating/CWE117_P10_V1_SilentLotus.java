import java.util.logging.Logger;

public class CWE117_P10_V1_SilentLotus {

    public static String data;

    public void handleSilentLotus() {
        data = System.getenv("SILENT_LOTUS_USER");
        (new CWE117_P10_V1_SilentLotusSink()).logSilentLotus();
    }
}

class CWE117_P10_V1_SilentLotusSink {
    public void logSilentLotus() {
        String data = CWE117_P10_V1_SilentLotus.data;
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + data);
    }
}
