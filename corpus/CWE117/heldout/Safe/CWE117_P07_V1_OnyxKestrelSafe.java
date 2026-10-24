import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxKestrelSafe {

    public void handleOnyxKestrel() {
        String data;
        data = (new CWE117_P07_V1_OnyxKestrelSafeSource()).readOnyxKestrel();
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxKestrelSafeSource {
    public String readOnyxKestrel() {
        String data;
        data = System.getenv("ONYX_KESTREL_USER");
        return data;
    }
}
