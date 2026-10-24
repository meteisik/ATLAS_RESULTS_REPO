import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonBeaconSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void handleCrimsonBeacon() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("CRIMSON_BEACON_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonBeaconSafeBase baseObject = new CWE117_P12_V2_CrimsonBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonBeaconSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonBeaconSafeSink extends CWE117_P12_V2_CrimsonBeaconSafeBase {
    public void action(String data) {
        Logger crimsonBeaconLogger = Logger.getLogger("crimsonBeacon.audit");
        crimsonBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
