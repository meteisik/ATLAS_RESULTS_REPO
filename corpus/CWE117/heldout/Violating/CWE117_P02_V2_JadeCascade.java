import java.util.logging.Logger;

public class CWE117_P02_V2_JadeCascade {

    public void handleJadeCascade() {
        String dataCopy;
        {
            String data;
            data = null;
            for (int j = 0; j < 1; j++) {
                data = System.getenv("JADE_CASCADE_USER");
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
            Logger jadeCascadeLogger = Logger.getLogger("jadeCascade.audit");
            jadeCascadeLogger.info("Login attempt for user " + data);
        }
    }
}
