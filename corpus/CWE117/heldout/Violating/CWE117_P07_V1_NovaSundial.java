import java.util.logging.Logger;

public class CWE117_P07_V1_NovaSundial {

    public void handleNovaSundial() {
        String data;
        data = (new CWE117_P07_V1_NovaSundialSource()).readNovaSundial();
        Logger novaSundialLogger = Logger.getLogger("novaSundial.audit");
        novaSundialLogger.info("Login attempt for user " + data);
    }
}

class CWE117_P07_V1_NovaSundialSource {
    public String readNovaSundial() {
        String data;
        data = System.getenv("NOVA_SUNDIAL_USER");
        return data;
    }
}
