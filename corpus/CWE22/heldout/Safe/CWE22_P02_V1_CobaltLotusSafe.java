import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P02_V1_CobaltLotusSafe {

    public void openCobaltLotus() {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
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
                        Logger.getLogger("CWE22_P02_V1_CobaltLotusSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
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
                            Logger.getLogger("CWE22_P02_V1_CobaltLotusSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                        }
                    }
                }
            }
        }
    }
}
