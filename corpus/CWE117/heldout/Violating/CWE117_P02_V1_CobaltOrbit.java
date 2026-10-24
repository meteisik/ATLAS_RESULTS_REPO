import java.util.logging.Logger;

public class CWE117_P02_V1_CobaltOrbit {

    public void handleCobaltOrbit() {
        String dataCopy;
        {
            String data;
            data = System.getenv("COBALT_ORBIT_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger cobaltOrbitLogger = Logger.getLogger("cobaltOrbit.audit");
            cobaltOrbitLogger.info("Login attempt for user " + data);
        }
    }
}
