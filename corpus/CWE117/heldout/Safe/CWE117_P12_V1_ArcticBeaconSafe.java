import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticBeaconSafe {

    public void handleArcticBeacon() {
        String data;
        data = System.getenv("ARCTIC_BEACON_USER");
        CWE117_P12_V1_ArcticBeaconSafeBase baseObject = new CWE117_P12_V1_ArcticBeaconSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticBeaconSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticBeaconSafeSink extends CWE117_P12_V1_ArcticBeaconSafeBase {
    public void action(String data) {
        Logger arcticBeaconLogger = Logger.getLogger("arcticBeacon.audit");
        arcticBeaconLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
