import java.util.logging.Logger;

public class CWE117_P12_V2_ArcticOrbitSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void handleArcticOrbit() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_ORBIT_USER");
        } else {
            data = null;
        }
        CWE117_P12_V2_ArcticOrbitSafeBase baseObject = new CWE117_P12_V2_ArcticOrbitSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE117_P12_V2_ArcticOrbitSafeBase {
    public abstract void action(String data);
}

class CWE117_P12_V2_ArcticOrbitSafeSink extends CWE117_P12_V2_ArcticOrbitSafeBase {
    public void action(String data) {
        Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
        arcticOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
