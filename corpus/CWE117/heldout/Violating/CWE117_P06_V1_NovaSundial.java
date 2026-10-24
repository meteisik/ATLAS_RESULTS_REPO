import java.util.logging.Logger;

public class CWE117_P06_V1_NovaSundial {

    public void handleNovaSundial() {
        String data;
        data = System.getenv("NOVA_SUNDIAL_USER");
        (new CWE117_P06_V1_NovaSundialSink()).logNovaSundial(data);
    }
}

class CWE117_P06_V1_NovaSundialSink {
    public void logNovaSundial(String data) {
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + data);
    }
}
