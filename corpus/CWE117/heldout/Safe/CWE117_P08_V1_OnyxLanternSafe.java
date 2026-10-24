import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxLanternSafe {

    public void handleOnyxLantern() {
        String data;
        data = System.getenv("ONYX_LANTERN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxLanternSafeSink()).logOnyxLantern(dataArray);
    }
}

class CWE117_P08_V1_OnyxLanternSafeSink {
    public void logOnyxLantern(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxLanternLogger = Logger.getLogger("onyxLantern.audit");
        onyxLanternLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
