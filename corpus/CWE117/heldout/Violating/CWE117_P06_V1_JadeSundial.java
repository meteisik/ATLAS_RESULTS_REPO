import java.util.logging.Logger;

public class CWE117_P06_V1_JadeSundial {

    public void handleJadeSundial() {
        String data;
        data = System.getenv("JADE_SUNDIAL_USER");
        (new CWE117_P06_V1_JadeSundialSink()).logJadeSundial(data);
    }
}

class CWE117_P06_V1_JadeSundialSink {
    public void logJadeSundial(String data) {
        Logger jadeSundialLogger = Logger.getLogger("jadeSundial.audit");
        jadeSundialLogger.info("Login attempt for user " + data);
    }
}
