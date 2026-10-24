import java.util.logging.Logger;

public class CWE117_P04_V2_OnyxLotusSafe {
    private static boolean privateTrue = true;

    private String readOnyxLotus() {
        String data;
        if (privateTrue) {
            data = System.getenv("ONYX_LOTUS_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleOnyxLotus() {
        String data = readOnyxLotus();
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
