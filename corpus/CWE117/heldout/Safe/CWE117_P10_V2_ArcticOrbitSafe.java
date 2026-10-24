import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticOrbitSafe {

    public static String data;

    public void handleArcticOrbit() {
        if (true) {
            data = System.getenv("ARCTIC_ORBIT_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticOrbitSafeSink()).logArcticOrbit();
    }
}

class CWE117_P10_V2_ArcticOrbitSafeSink {
    public void logArcticOrbit() {
        String data = CWE117_P10_V2_ArcticOrbitSafe.data;
        Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
        arcticOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
