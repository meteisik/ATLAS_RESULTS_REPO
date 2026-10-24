import java.util.logging.Logger;

public class CWE117_P05_V1_JadeSundial {

    private String jadeSundialData;

    private void logJadeSundial() {
        String data = jadeSundialData;
        Logger jadeSundialLogger = Logger.getLogger("jadeSundial.audit");
        jadeSundialLogger.info("Login attempt for user " + data);
    }

    public void handleJadeSundial() {
        String data;
        data = System.getenv("JADE_SUNDIAL_USER");
        jadeSundialData = data;
        logJadeSundial();
    }
}
