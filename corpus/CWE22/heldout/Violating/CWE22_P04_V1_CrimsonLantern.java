import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P04_V1_CrimsonLantern {

    private String locateCrimsonLantern() {
        String data;
        data = System.getenv("CRIMSON_LANTERN_PATH");
        return data;
    }

    public void openCrimsonLantern() {
        String data = locateCrimsonLantern();
        String crimsonLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File crimsonLanternFile = new File(crimsonLanternRoot + data);
            FileInputStream crimsonLanternStream = null;
            InputStreamReader crimsonLanternStreamReader = null;
            BufferedReader crimsonLanternReader = null;
            if (crimsonLanternFile.exists() && crimsonLanternFile.isFile()) {
                try {
                    crimsonLanternStream = new FileInputStream(crimsonLanternFile);
                    crimsonLanternStreamReader = new InputStreamReader(crimsonLanternStream, "UTF-8");
                    crimsonLanternReader = new BufferedReader(crimsonLanternStreamReader);
                    System.out.println(crimsonLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P04_V1_CrimsonLantern").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (crimsonLanternReader != null) {
                            crimsonLanternReader.close();
                        }
                        if (crimsonLanternStreamReader != null) {
                            crimsonLanternStreamReader.close();
                        }
                        if (crimsonLanternStream != null) {
                            crimsonLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P04_V1_CrimsonLantern").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
