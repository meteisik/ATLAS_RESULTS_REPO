import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P01_V1_CobaltLotus {

    public void openCobaltLotus() {
        String data;
        data = System.getenv("COBALT_LOTUS_PATH");
        String cobaltLotusRoot = "/home/user/uploads/";
        if (data != null) {
            File cobaltLotusFile = new File(cobaltLotusRoot + data);
            FileInputStream cobaltLotusStream = null;
            InputStreamReader cobaltLotusStreamReader = null;
            BufferedReader cobaltLotusReader = null;
            if (cobaltLotusFile.exists() && cobaltLotusFile.isFile()) {
                try {
                    cobaltLotusStream = new FileInputStream(cobaltLotusFile);
                    cobaltLotusStreamReader = new InputStreamReader(cobaltLotusStream, "UTF-8");
                    cobaltLotusReader = new BufferedReader(cobaltLotusStreamReader);
                    System.out.println(cobaltLotusReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P01_V1_CobaltLotus").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (cobaltLotusReader != null) {
                            cobaltLotusReader.close();
                        }
                        if (cobaltLotusStreamReader != null) {
                            cobaltLotusStreamReader.close();
                        }
                        if (cobaltLotusStream != null) {
                            cobaltLotusStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P01_V1_CobaltLotus").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }
}
