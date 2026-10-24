import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public class CWE89_P10_V2_AzureAurora {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public void runAzureAurora() throws SQLException {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AZURE_AURORA_FILTER");
        } else {
            data = null;
        }
        (new CWE89_P10_V2_AzureAuroraSink()).queryAzureAurora();
    }
}

class CWE89_P10_V2_AzureAuroraSink {
    public void queryAzureAurora() throws SQLException {
        String data = CWE89_P10_V2_AzureAurora.data;
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
