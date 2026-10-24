import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_CrimsonRavenSafe {

    private void readCrimsonRaven(String data) {
        String crimsonRavenRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonRavenFile = new File(crimsonRavenRoot + data);
            FileInputStream crimsonRavenStream = null;
            InputStreamReader crimsonRavenStreamReader = null;
            BufferedReader crimsonRavenReader = null;
            if (crimsonRavenFile.exists() && crimsonRavenFile.isFile()) {
                try {
                    crimsonRavenStream = new FileInputStream(crimsonRavenFile);
                    crimsonRavenStreamReader = new InputStreamReader(crimsonRavenStream, "UTF-8");
                    crimsonRavenReader = new BufferedReader(crimsonRavenStreamReader);
                    System.out.println(crimsonRavenReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V1_CrimsonRavenSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonRavenReader != null) {
                            crimsonRavenReader.close();
                        }
                        if (crimsonRavenStreamReader != null) {
                            crimsonRavenStreamReader.close();
                        }
                        if (crimsonRavenStream != null) {
                            crimsonRavenStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V1_CrimsonRavenSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openCrimsonRaven() {
        String data;
        data = "foo";
        readCrimsonRaven(data);
    }
}
