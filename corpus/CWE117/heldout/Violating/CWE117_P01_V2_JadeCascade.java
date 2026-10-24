import java.util.logging.Logger;

public class CWE117_P01_V2_JadeCascade {

    public void handleJadeCascade() {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("JADE_CASCADE_USER");
            break;
        default:
            data = null;
            break;
        }
        Logger jadeCascadeLogger = Logger.getLogger("jadeCascade.audit");
        jadeCascadeLogger.info("Login attempt for user " + data);
    }
}
