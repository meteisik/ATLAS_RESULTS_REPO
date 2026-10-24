import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxKestrelSafe {

    private String readOnyxKestrel() {
        String data;
        if (5 == 5) {
            data = System.getenv("ONYX_KESTREL_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleOnyxKestrel() {
        String data = readOnyxKestrel();
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
