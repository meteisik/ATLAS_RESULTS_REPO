import java.util.logging.Logger;

public class CWE117_P01_V1_ArcticOrbit {

    public void handleArcticOrbit() {
        String data;
        data = System.getenv("ARCTIC_ORBIT_USER");
        Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
        arcticOrbitLogger.info("Login attempt for user " + data);
    }
}
