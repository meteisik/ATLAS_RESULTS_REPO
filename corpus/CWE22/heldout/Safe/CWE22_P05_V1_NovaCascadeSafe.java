import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CWE22_P05_V1_NovaCascadeSafe {
    private String novaCascadeData;

    private void readNovaCascade() {
        String data = novaCascadeData;
        String novaCascadeRoot = "/home/user/uploads/";
        if (data != null) {
            File novaCascadeFile = new File(novaCascadeRoot + data);
            FileInputStream novaCascadeStream = null;
            InputStreamReader novaCascadeStreamReader = null;
            BufferedReader novaCascadeReader = null;
            if (novaCascadeFile.exists() && novaCascadeFile.isFile()) {
                try {
                    novaCascadeStream = new FileInputStream(novaCascadeFile);
                    novaCascadeStreamReader = new InputStreamReader(novaCascadeStream, "UTF-8");
                    novaCascadeReader = new BufferedReader(novaCascadeStreamReader);
                    System.out.println(novaCascadeReader.readLine());
                } catch (IOException exceptIO) {
                    Logger.getLogger("CWE22_P05_V1_NovaCascadeSafe").log(Level.WARNING, "Error with stream reading", exceptIO);
                } finally {
                    try {
                        if (novaCascadeReader != null) {
                            novaCascadeReader.close();
                        }
                        if (novaCascadeStreamReader != null) {
                            novaCascadeStreamReader.close();
                        }
                        if (novaCascadeStream != null) {
                            novaCascadeStream.close();
                        }
                    } catch (IOException exceptIO) {
                        Logger.getLogger("CWE22_P05_V1_NovaCascadeSafe").log(Level.WARNING, "Error closing stream reading objects", exceptIO);
                    }
                }
            }
        }
    }

    public void openNovaCascade() {
        String data;
        data = "foo";
        novaCascadeData = data;
        readNovaCascade();
    }
}
