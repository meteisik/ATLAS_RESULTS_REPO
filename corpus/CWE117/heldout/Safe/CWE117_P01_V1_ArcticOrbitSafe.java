import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticOrbitSafe {

    public void handleArcticOrbit() {
        String data;
        data = System.getenv("ARCTIC_ORBIT_USER");
        Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
        arcticOrbitLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
