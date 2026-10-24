import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticOrbitSafe {

    public void handleArcticOrbit() {
        String dataCopy;
        {
            String data;
            data = System.getenv("ARCTIC_ORBIT_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
            arcticOrbitLogger.info("Login attempt for user " + sanitize(data));
        }
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
