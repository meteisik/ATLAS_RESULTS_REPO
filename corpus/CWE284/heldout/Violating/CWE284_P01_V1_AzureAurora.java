import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AzureAurora {

    public void deleteAzureAuroraAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_AURORA_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection azureAuroraConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureAurora");
        try {
            PreparedStatement azureAuroraDelete = azureAuroraConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureAuroraDelete.setString(1, data);
            azureAuroraDelete.executeUpdate();
        } finally {
            azureAuroraConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
