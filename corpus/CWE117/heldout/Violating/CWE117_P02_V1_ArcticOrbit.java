import java.util.logging.Logger;

public class CWE117_P02_V1_ArcticOrbit {

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
            arcticOrbitLogger.info("Login attempt for user " + data);
        }
    }
}
