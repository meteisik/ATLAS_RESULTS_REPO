import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_CobaltLantern {

    public void openCobaltLantern() {
        String data;
        data = System.getenv("COBALT_LANTERN_PATH");
        String cobaltLanternRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltLanternFile = new File(cobaltLanternRoot + data);
            FileInputStream cobaltLanternStream = null;
            InputStreamReader cobaltLanternStreamReader = null;
            BufferedReader cobaltLanternReader = null;
            if (cobaltLanternFile.exists() && cobaltLanternFile.isFile()) {
                try {
                    cobaltLanternStream = new FileInputStream(cobaltLanternFile);
                    cobaltLanternStreamReader = new InputStreamReader(cobaltLanternStream, "UTF-8");
                    cobaltLanternReader = new BufferedReader(cobaltLanternStreamReader);
                    System.out.println(cobaltLanternReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_CobaltLantern").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltLanternReader != null) {
                            cobaltLanternReader.close();
                        }
                        if (cobaltLanternStreamReader != null) {
                            cobaltLanternStreamReader.close();
                        }
                        if (cobaltLanternStream != null) {
                            cobaltLanternStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_CobaltLantern").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
