import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxRavenSafe {

    public void handleOnyxRaven() {
        String data;
        data = (new CWE117_P07_V1_OnyxRavenSafeSource()).readOnyxRaven();
        Logger onyxRavenLogger = Logger.getLogger("onyxRaven.audit");
        onyxRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxRavenSafeSource {
    public String readOnyxRaven() {
        String data;
        data = System.getenv("ONYX_RAVEN_USER");
        return data;
    }
}
