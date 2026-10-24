import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P12_V2_AzureAurora {
    private static boolean privateReturnsTrue() { return true; }

    public void runAzureAurora() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("AZURE_AURORA_FILTER");
        } else {
            data = null;
        }
        CWE89_P12_V2_AzureAuroraBase baseObject = new CWE89_P12_V2_AzureAuroraSink();
        baseObject.action(data);
    }
}

abstract class CWE89_P12_V2_AzureAuroraBase {
    public abstract void action(String data) throws SQLException;
}

class CWE89_P12_V2_AzureAuroraSink extends CWE89_P12_V2_AzureAuroraBase {
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
