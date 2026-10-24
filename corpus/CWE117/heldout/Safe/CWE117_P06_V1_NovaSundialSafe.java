import java.util.logging.Logger;

public class CWE117_P06_V1_NovaSundialSafe {

    public void handleNovaSundial() {
        String data;
        data = System.getenv("NOVA_SUNDIAL_USER");
        (new CWE117_P06_V1_NovaSundialSafeSink()).logNovaSundial(data);
    }
}

class CWE117_P06_V1_NovaSundialSafeSink {
    public void logNovaSundial(String data) {
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + sanitize(data));
    }

    private static String sanitize(String value) {
        return value.replace("\r", "").replace("\n", "");
    }
}
