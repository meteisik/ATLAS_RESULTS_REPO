import java.util.logging.Logger;

public class CWE117_P03_V1_IvoryOrbit {

    private void logIvoryOrbit(String data) {
        Logger ivoryOrbitLogger = Logger.getLogger("ivoryOrbit.audit");
        ivoryOrbitLogger.info("Login attempt for user " + data);
    }

    public void handleIvoryOrbit() {
        String data;
        data = System.getenv("IVORY_ORBIT_USER");
        logIvoryOrbit(data);
    }
}
