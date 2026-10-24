import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureAuroraSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void runAzureAurora() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = "foo";
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureAuroraSafeBase baseObject = new CWE89_P12_V2_AzureAuroraSafeSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureAuroraSafeBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureAuroraSafeSink extends CWE89_P12_V2_AzureAuroraSafeBase {
    public void action(String data) throws SQLException {
        Connection azureAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureAurora");
        Statement azureAuroraStatement = null;
        ResultSet azureAuroraRows = null;
        try {
            azureAuroraStatement = azureAuroraConnection.createStatement();
            azureAuroraRows = azureAuroraStatement.executeQuery("select * from users where name='" + data + "'");
            System.out.println(azureAuroraRows.getRow());
        } finally {
            if (azureAuroraRows != null) {
                azureAuroraRows.close();
            }
            if (azureAuroraStatement != null) {
                azureAuroraStatement.close();
            }
            azureAuroraConnection.close();
        }
    }
}
