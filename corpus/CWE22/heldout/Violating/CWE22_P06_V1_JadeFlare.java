import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P06_V1_JadeFlare {

    public void openJadeFlare() {
        String data;
        data = System.getenv("JADE_FLARE_PATH");
        (new CWE22_P06_V1_JadeFlareSink()).readJadeFlare(data);
    }
}

class CWE22_P06_V1_JadeFlareSink {
    public void readJadeFlare(String data) {
        String jadeFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File jadeFlareFile = new File(jadeFlareRoot + data);
            FileInputStream jadeFlareStream = null;
            InputStreamReader jadeFlareStreamReader = null;
            BufferedReader jadeFlareReader = null;
            if (jadeFlareFile.exists() && jadeFlareFile.isFile()) {
                try {
                    jadeFlareStream = new FileInputStream(jadeFlareFile);
                    jadeFlareStreamReader = new InputStreamReader(jadeFlareStream, "UTF-8");
                    jadeFlareReader = new BufferedReader(jadeFlareStreamReader);
                    System.out.println(jadeFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P06_V1_JadeFlareSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (jadeFlareReader != null) {
                            jadeFlareReader.close();
                        }
                        if (jadeFlareStreamReader != null) {
                            jadeFlareStreamReader.close();
                        }
                        if (jadeFlareStream != null) {
                            jadeFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P06_V1_JadeFlareSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
