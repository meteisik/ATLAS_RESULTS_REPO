import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V2_JadeFlareSafe {

    public void openJadeFlare() {
        String dataCopy;
        {
            String data;
            if (5 == 5) {
                data = "foo";
            } else {
                data = null;
            }
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V2_JadeFlareSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V2_JadeFlareSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
