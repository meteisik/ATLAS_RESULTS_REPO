import java.util.logging.Logger;

public class CWE117_P05_V2_OnyxLotusSafe {
    private static int privateFive = 5;

    private String onyxLotusData;

    private void logOnyxLotus() {
        String data = onyxLotusData;
        Logger onyxLotusLogger = Logger.getLogger("onyxLotus.audit");
        onyxLotusLogger.info("Login attempt for user " + sanitize(data));
    }

    public void handleOnyxLotus() {
        String data;
        if (privateFive == 5) {
            data = System.getenv("ONYX_LOTUS_USER");
        } else {
            data = null;
        }
        onyxLotusData = data;
        logOnyxLotus();
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
