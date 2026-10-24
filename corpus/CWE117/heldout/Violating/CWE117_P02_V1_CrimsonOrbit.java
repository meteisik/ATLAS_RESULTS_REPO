import java.util.logging.Logger;

public class CWE117_P02_V1_CrimsonOrbit {

    public void handleCrimsonOrbit() {
        String dataCopy;
        {
            String data;
            data = System.getenv("CRIMSON_ORBIT_USER");
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger crimsonOrbitLogger = Logger.getLogger("crimsonOrbit.audit");
            crimsonOrbitLogger.info("Login attempt for user " + data);
        }
    }
}
