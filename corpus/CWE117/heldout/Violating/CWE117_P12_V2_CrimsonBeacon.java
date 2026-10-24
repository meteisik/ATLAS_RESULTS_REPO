import java.util.logging.Logger;

public class CWE117_P12_V2_CrimsonBeacon {
    private static boolean privateReturnsTrue() { return true; }

    public void handleCrimsonBeacon() {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("CRIMSON_BEACON_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_CrimsonBeaconBase baseObject = new CWE117_P12_V2_CrimsonBeaconSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_CrimsonBeaconBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_CrimsonBeaconSink extends CWE117_P12_V2_CrimsonBeaconBase {
    public void action(String data) {
        Logger crimsonBeaconLogger = Logger.getLogger("crimsonBeacon.audit");
        crimsonBeaconLogger.info("Login attempt for user " + data);
    }
}
