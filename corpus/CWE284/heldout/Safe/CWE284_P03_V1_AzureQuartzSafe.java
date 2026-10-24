import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_AzureQuartzSafe {

    private void applyAzureQuartzDeletion(String data, boolean authorized) throws SQLException {
        Connection azureQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureQuartz");
        try {
            PreparedStatement azureQuartzDelete = azureQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureQuartzDelete.setString(1, data);
            if (authorized) {
                azureQuartzDelete.executeUpdate();
            }
        } finally {
            azureQuartzConnection.close();
        }
    }

    public void deleteAzureQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_QUARTZ_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyAzureQuartzDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
