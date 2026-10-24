import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxKestrelSafe {

    public void handleOnyxKestrel() {
        String data;
        data = System.getenv("ONYX_KESTREL_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxKestrelSafeSink()).logOnyxKestrel(dataArray);
    }
}

class CWE117_P08_V1_OnyxKestrelSafeSink {
    public void logOnyxKestrel(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxKestrelLogger = Logger.getLogger("onyxKestrel.audit");
        onyxKestrelLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
