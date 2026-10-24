import java.util.logging.Logger;

public class CWE117_P08_V2_SilentKestrel {
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
        (new CWE117_P08_V2_SilentKestrelSink()).logSilentKestrel(dataArray);
    }
}

class CWE117_P08_V2_SilentKestrelSink {
    public void logSilentKestrel(String[] dataArray) {
        String data = dataArray[2];
        Logger silentKestrelLogger = Logger.getLogger("silentKestrel.audit");
        silentKestrelLogger.info("Login attempt for user " + data);
    }
}
