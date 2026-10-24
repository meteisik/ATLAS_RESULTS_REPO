import java.util.logging.Logger;

public class CWE117_P07_V1_OnyxLotusSafe {

    public void handleOnyxLotus() {
        String data;
        data = (new CWE117_P07_V1_OnyxLotusSafeSource()).readOnyxLotus();
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}

class CWE117_P07_V1_OnyxLotusSafeSource {
    public String readOnyxLotus() {
        String data;
        data = System.getenv("ONYX_LOTUS_USER");
        return data;
    }
}
