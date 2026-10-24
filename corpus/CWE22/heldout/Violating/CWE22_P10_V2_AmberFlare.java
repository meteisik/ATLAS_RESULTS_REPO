import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P10_V2_AmberFlare {
    public static String data;

    public void openAmberFlare() {
        if (5 == 5) {
            data = System.getenv("AMBER_FLARE_PATH");
        } else {
            data = null;
        }
        (new CWE22_P10_V2_AmberFlareSink()).readAmberFlare();
    }
}

class CWE22_P10_V2_AmberFlareSink {
    public void readAmberFlare() {
        String data = CWE22_P10_V2_AmberFlare.data;
        String amberFlareRoot = "/home/user/uploads/";
        if (data != null) {
            File amberFlareFile = new File(amberFlareRoot + data);
            FileInputStream amberFlareStream = null;
            InputStreamReader amberFlareStreamReader = null;
            BufferedReader amberFlareReader = null;
            if (amberFlareFile.exists() && amberFlareFile.isFile()) {
                try {
                    amberFlareStream = new FileInputStream(amberFlareFile);
                    amberFlareStreamReader = new InputStreamReader(amberFlareStream, "UTF-8");
                    amberFlareReader = new BufferedReader(amberFlareStreamReader);
                    System.out.println(amberFlareReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P10_V2_AmberFlareSink").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (amberFlareReader != null) {
                            amberFlareReader.close();
                        }
                        if (amberFlareStreamReader != null) {
                            amberFlareStreamReader.close();
                        }
                        if (amberFlareStream != null) {
                            amberFlareStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P10_V2_AmberFlareSink").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
