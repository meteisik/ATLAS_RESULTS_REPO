import java.util.logging.Logger;

public class CWE117_P12_V1_ArcticBeacon {

    public void handleArcticBeacon() {
        String data;
        data = System.getenv("ARCTIC_BEACON_USER");
        CWE117_P12_V1_ArcticBeaconBase baseObject = new CWE117_P12_V1_ArcticBeaconSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V1_ArcticBeaconBase {
    public abstract void action(String data);
}

class CWE117_P12_V1_ArcticBeaconSink extends CWE117_P12_V1_ArcticBeaconBase {
    public void action(String data) {
        Logger arcticBeaconLogger = Logger.getLogger("arcticBeacon.audit");
        arcticBeaconLogger.info("Login attempt for user " + data);
    }
}
