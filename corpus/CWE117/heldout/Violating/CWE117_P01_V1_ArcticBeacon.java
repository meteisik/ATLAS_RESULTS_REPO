import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticBeacon {

    public void handleArcticBeacon() {
        String data;
        data = System.getenv("ARCTIC_BEACON_USER");
        Logger arcticBeaconLogger = Logger.getLogger("arcticBeacon.audit");
        arcticBeaconLogger.info("Login attempt for user " + data);
    }
}
