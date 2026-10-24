import java.util.logging.Logger;

public class CWE117_P08_V1_OnyxLotusSafe {

    public void handleOnyxLotus() {
        String data;
        data = System.getenv("ONYX_LOTUS_USER");
        String[] dataArray = new String[5];
        dataArray[2] = data;
        (new CWE117_P08_V1_OnyxLotusSafeSink()).logOnyxLotus(dataArray);
    }
}

class CWE117_P08_V1_OnyxLotusSafeSink {
    public void logOnyxLotus(String[] dataArray) {
        String data = dataArray[2];
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
