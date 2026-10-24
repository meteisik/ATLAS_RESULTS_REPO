import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_AzureFlare {

    public void deleteAzureFlareAccount() throws SQLException {
        String data;
        data = System.getenv("AZURE_FLARE_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection azureFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:azureFlare");
        try {
            PreparedStatement azureFlareDelete = azureFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            azureFlareDelete.setString(1, data);
            azureFlareDelete.executeUpdate();
        } finally {
            azureFlareConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
