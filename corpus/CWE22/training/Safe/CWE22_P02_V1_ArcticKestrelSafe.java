import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class CWE22_P02_V1_ArcticKestrelSafe {

    public void openArcticKestrel() throws IOException {
        String dataCopy;
        {
            String data;
            data = "foo";
            dataCopy = data;
        }
        {
            String data = dataCopy;
            String arcticKestrelRoot = "/home/user/uploads/";
            File arcticKestrelFile = new File(arcticKestrelRoot + data);
            FileInputStream arcticKestrelStream = new FileInputStream(arcticKestrelFile);
            arcticKestrelStream.close();
        }
    }
}
