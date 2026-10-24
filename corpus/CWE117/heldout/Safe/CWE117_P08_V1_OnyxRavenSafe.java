import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxRavenSafe {

    public void handleOnyxRaven() {
        String data;
        data = System.getenv("ONYX_RAVEN_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxRavenSafeSink()).logOnyxRaven(dataArray);
    }
}

class CWE117_P08_V1_OnyxRavenSafeSink {
    public void logOnyxRaven(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxRavenLogger = Logger.getLogger("onyxRaven.audit");
        onyxRavenLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
