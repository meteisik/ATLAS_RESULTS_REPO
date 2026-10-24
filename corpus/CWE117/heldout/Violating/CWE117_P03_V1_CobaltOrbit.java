import java.util.logging.Logger;

public class CWE117_P03_V1_CobaltOrbit {

    private void logCobaltOrbit(String data) {
        Logger cobaltOrbitLogger = Logger.getLogger("cobaltOrbit.audit");
        cobaltOrbitLogger.info("Login attempt for user " + data);
    }

    public void handleCobaltOrbit() {
        String data;
        data = System.getenv("COBALT_ORBIT_USER");
        logCobaltOrbit(data);
    }
}
