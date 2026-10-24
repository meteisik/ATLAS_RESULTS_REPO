import java.util.logging.Logger;

public class CWE117_P03_V2_NovaSundial {

    private void logNovaSundial(String data) {
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + data);
    }

    public void handleNovaSundial() {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("NOVA_SUNDIAL_USER");
        }
        logNovaSundial(data);
    }
}
