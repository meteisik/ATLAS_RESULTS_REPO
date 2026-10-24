import java.util.logging.Logger;

public class CWE117_P10_V2_ArcticOrbit {

    public static String data;

    public void handleArcticOrbit() {
        if (true) {
            data = System.getenv("ARCTIC_ORBIT_USER");
        } else {
            data = null;
        }
        (new CWE117_P10_V2_ArcticOrbitSink()).logArcticOrbit();
    }
}

class CWE117_P10_V2_ArcticOrbitSink {
    public void logArcticOrbit() {
        String data = CWE117_P10_V2_ArcticOrbit.data;
        Logger arcticOrbitLogger = Logger.getLogger("arcticOrbit.audit");
        arcticOrbitLogger.info("Login attempt for user " + data);
    }
}
