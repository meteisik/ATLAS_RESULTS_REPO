import java.util.logging.Logger;

public class CWE117_P08_V2_SilentKestrelSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleSilentKestrel() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SILENT_KESTREL_USER");
        } else {
            data = null;
        }
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V2_SilentKestrelSafeSink()).logSilentKestrel(dataArray);
    }
}

class CWE117_P08_V2_SilentKestrelSafeSink {
    public void logSilentKestrel(String[] dataArray) {
        String data = dataArray[2];
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
