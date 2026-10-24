import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxLanternSafe {

    public void handleOnyxLantern() {
        String data;
        data = (new CWE117_P07_V1_OnyxLanternSafeSource()).readOnyxLantern();
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxLanternSafeSource {
    public String readOnyxLantern() {
        String data;
        data = System.getenv("ONYX_LANTERN_USER");
        return data;
    }
}
