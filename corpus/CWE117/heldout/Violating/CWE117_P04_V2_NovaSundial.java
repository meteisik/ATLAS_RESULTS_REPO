import java.util.logging.Logger;

public class CWE117_P04_V2_NovaSundial {

    private String readNovaSundial() {
        String data;
        if (5 == 5) {
            data = System.getenv("NOVA_SUNDIAL_USER");
        } else {
            data = null;
        }
        return data;
    }

    public void handleNovaSundial() {
        String data = readNovaSundial();
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + data);
    }
}
