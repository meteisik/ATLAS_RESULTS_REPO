import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxCometSafe {

    public void handleOnyxComet() {
        String data;
        data = System.getenv("ONYX_COMET_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxCometSafeSink()).logOnyxComet(dataArray);
    }
}

class CWE117_P08_V1_OnyxCometSafeSink {
    public void logOnyxComet(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxCometLogger = Logger.getLogger("onyxComet.audit");
        onyxCometLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
