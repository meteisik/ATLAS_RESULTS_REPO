import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxCometSafe {

    public void handleOnyxComet() {
        String data;
        data = (new CWE117_P07_V1_OnyxCometSafeSource()).readOnyxComet();
        Logger onyxCometLogger = Logger.getLogger("onyxComet.audit");
        onyxCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxCometSafeSource {
    public String readOnyxComet() {
        String data;
        data = System.getenv("ONYX_COMET_USER");
        return data;
    }
}
