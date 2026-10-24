import java.util.logging.Logger;

public class CWE117_P10_V1_SilentLotusSafe {

    public static String data;

    public void handleSilentLotus() {
        data = System.getenv("SILENT_LOTUS_USER");
        (new CWE117_P10_V1_SilentLotusSafeSink()).logSilentLotus();
    }
}

class CWE117_P10_V1_SilentLotusSafeSink {
    public void logSilentLotus() {
        String data = CWE117_P10_V1_SilentLotusSafe.data;
        Logger silentLotusLogger = Logger.getLogger("silentLotus.audit");
        silentLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
