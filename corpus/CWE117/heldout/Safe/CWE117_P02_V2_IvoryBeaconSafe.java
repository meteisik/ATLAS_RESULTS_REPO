import java.util.logging.Logger;

public class CWE117_P02_V2_IvoryBeaconSafe {
    private static boolean privateTrue = true;

    public void handleIvoryBeacon() {
        String dataCopy;
        {
            String data;
            if (privateTrue) {
                data = System.getenv("IVORY_BEACON_USER");
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger ivoryBeaconLogger = Logger.getLogger("ivoryBeacon.audit");
            ivoryBeaconLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
