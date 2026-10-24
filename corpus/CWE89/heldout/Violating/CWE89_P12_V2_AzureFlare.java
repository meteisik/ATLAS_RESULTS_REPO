import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureFlare {
    private static final class IO {
        static final boolean STATIC_FINAL_TRUE = true;
        static final int STATIC_FINAL_FIVE = 5;
        static boolean staticTrue = true;
        static int staticFive = 5;
        static boolean staticReturnsTrue() { return true; }
    }

    public void runAzureFlare() throws SQLException {
        String data;
        if (IO.staticReturnsTrue()) {
            data = System.getenv("AZURE_FLARE_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureFlareBase baseObject = new CWE89_P12_V2_AzureFlareSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureFlareBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureFlareSink extends CWE89_P12_V2_AzureFlareBase {
    public void action(String data) throws SQLException {
        Connection azureFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureFlare");
        Statement azureFlareStatement = null;
        ResultSet azureFlareRows = null;
        try {
            azureFlareStatement = azureFlareConnection.createStatement();
            azureFlareRows = azureFlareStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureFlareRows.getRow());
        } finally {
            if (azureFlareRows != null) {
                azureFlareRows.close();
            }
            if (azureFlareStatement != null) {
                azureFlareStatement.close();
            }
            azureFlareConnection.close();
        }
    }
}
