import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AzureAuroraSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public static String data;

    public static boolean authorized;

    public void deleteAzureAuroraAccount() throws SQLException {
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("AZURE_AURORA_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AzureAuroraSafeSink()).applyAzureAuroraDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AzureAuroraSafeSink {
    public void applyAzureAuroraDeletion() throws SQLException {
        String data = CWE284_P10_V2_AzureAuroraSafe.data;
        boolean authorized = CWE284_P10_V2_AzureAuroraSafe.authorized;
        Connection azureAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureAurora");
        try {
            PreparedStatement azureAuroraDelete = azureAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureAuroraDelete.setString(1, data);
            if (authorized) {
                azureAuroraDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            azureAuroraConnection.close();
        }
    }
}
