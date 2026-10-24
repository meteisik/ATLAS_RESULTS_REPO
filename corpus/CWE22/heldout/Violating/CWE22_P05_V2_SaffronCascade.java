import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V2_SaffronCascade {
    private String saffronCascadeData;
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    private void readSaffronCascade() {
        String data = saffronCascadeData;
        String saffronCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File saffronCascadeFile = new File(saffronCascadeRoot + data);
            FileInputStream saffronCascadeStream = null;
            InputStreamReader saffronCascadeStreamReader = null;
            BufferedReader saffronCascadeReader = null;
            if (saffronCascadeFile.exists() && saffronCascadeFile.isFile()) {
                try {
                    saffronCascadeStream = new FileInputStream(saffronCascadeFile);
                    saffronCascadeStreamReader = new InputStreamReader(saffronCascadeStream, "UTF-8");
                    saffronCascadeReader = new BufferedReader(saffronCascadeStreamReader);
                    System.out.println(saffronCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V2_SaffronCascade").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (saffronCascadeReader != null) {
                            saffronCascadeReader.close();
                        }
                        if (saffronCascadeStreamReader != null) {
                            saffronCascadeStreamReader.close();
                        }
                        if (saffronCascadeStream != null) {
                            saffronCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V2_SaffronCascade").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openSaffronCascade() {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("SAFFRON_CASCADE_PATH");
        } else {
            data = null;
        }
        saffronCascadeData = data;
        readSaffronCascade();
    }
}
