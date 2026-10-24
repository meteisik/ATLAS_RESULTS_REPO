import java.util.logging.Logger;

public class CWE117_P06_V2_OnyxKestrelSafe {
    private static int privateFive = 5;

    public void handleOnyxKestrel() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_KESTREL_USER");
        } else {
            data = null;
        }
        (new CWE117_P06_V2_OnyxKestrelSafeSink()).logOnyxKestrel(data);
    }
}

class CWE117_P06_V2_OnyxKestrelSafeSink {
    public void logOnyxKestrel(String data) {
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
