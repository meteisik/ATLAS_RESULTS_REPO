import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_CobaltOrbitSafe {

    public void openCobaltOrbit() {
        String data;
        data = "foo";
        String cobaltOrbitRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltOrbitFile = new File(cobaltOrbitRoot + data);
            FileInputStream cobaltOrbitStream = null;
            InputStreamReader cobaltOrbitStreamReader = null;
            BufferedReader cobaltOrbitReader = null;
            if (cobaltOrbitFile.exists() && cobaltOrbitFile.isFile()) {
                try {
                    cobaltOrbitStream = new FileInputStream(cobaltOrbitFile);
                    cobaltOrbitStreamReader = new InputStreamReader(cobaltOrbitStream, "UTF-8");
                    cobaltOrbitReader = new BufferedReader(cobaltOrbitStreamReader);
                    System.out.println(cobaltOrbitReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_CobaltOrbitSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltOrbitReader != null) {
                            cobaltOrbitReader.close();
                        }
                        if (cobaltOrbitStreamReader != null) {
                            cobaltOrbitStreamReader.close();
                        }
                        if (cobaltOrbitStream != null) {
                            cobaltOrbitStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_CobaltOrbitSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
