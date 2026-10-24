import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P03_V1_IvoryCometSafe {

    private void readIvoryComet(String data) {
        String ivoryCometRoot = "/home/user/uploads/";
        if (data != null) {
            File ivoryCometFile = new File(ivoryCometRoot + data);
            FileInputStream ivoryCometStream = null;
            InputStreamReader ivoryCometStreamReader = null;
            BufferedReader ivoryCometReader = null;
            if (ivoryCometFile.exists() && ivoryCometFile.isFile()) {
                try {
                    ivoryCometStream = new FileInputStream(ivoryCometFile);
                    ivoryCometStreamReader = new InputStreamReader(ivoryCometStream, "UTF-8");
                    ivoryCometReader = new BufferedReader(ivoryCometStreamReader);
                    System.out.println(ivoryCometReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P03_V1_IvoryCometSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (ivoryCometReader != null) {
                            ivoryCometReader.close();
                        }
                        if (ivoryCometStreamReader != null) {
                            ivoryCometStreamReader.close();
                        }
                        if (ivoryCometStream != null) {
                            ivoryCometStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P03_V1_IvoryCometSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openIvoryComet() {
        String data;
        data = "foo";
        readIvoryComet(data);
    }
}
